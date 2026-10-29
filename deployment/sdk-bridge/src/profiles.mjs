import { existsSync, renameSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PROVIDERS } from "./config.mjs";
import { BridgeError } from "./errors.mjs";
import { LoginSessions, bounded } from "./login.mjs";
import { createAuthStore } from "./oauth/store.mjs";
import { fetchUsage } from "./usage.mjs";

// OAuth access and refresh values for a provider, read locally from the store.
function oauthSecrets(auth, provider) {
	const grant = auth.get(provider);
	return [grant?.access, grant?.refresh].filter(value => typeof value === "string" && value.length > 0);
}

// Replaces every secret, raw and JSON-escaped, longest first so overlapping values are fully masked.
export function redactor(secrets) {
	const variants = new Set();
	for (const secret of secrets) {
		variants.add(secret);
		variants.add(JSON.stringify(secret).slice(1, -1));
	}
	const ordered = [...variants].filter(Boolean).sort((a, b) => b.length - a.length);
	return text => ordered.reduce((out, secret) => out.split(secret).join("[redacted]"), text);
}

// Canonical positive decimal integer: no sign, no leading zero, bounded length.
export const PROFILE_ID_PATTERN = /^[1-9][0-9]{0,18}$/;

const REASONING_EFFORTS = ["minimal", "low", "medium", "high", "xhigh", "max"];

// Allowlist of SimpleStreamOptions values a caller may set. Transport fields (apiKey, baseUrl, headers, fetch) are never accepted.
const INFER_OPTION_RULES = {
	temperature: v => Number.isFinite(v),
	topP: v => Number.isFinite(v),
	topK: v => Number.isFinite(v),
	minP: v => Number.isFinite(v),
	maxTokens: v => Number.isFinite(v) && v > 0,
	reasoning: v => REASONING_EFFORTS.includes(v),
	forceReasoningOff: v => typeof v === "boolean",
	sessionId: v => typeof v === "string" && v.length <= 256,
	stopSequences: v => Array.isArray(v) && v.length <= 4 && v.every(s => typeof s === "string"),
};

export function assertProvider(provider) {
	if (!PROVIDERS.includes(provider)) throw new BridgeError(400, "unsupported_provider");
	return provider;
}

export function pickInferOptions(raw) {
	if (raw === undefined) return {};
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new BridgeError(400, "invalid_options");
	const out = {};
	for (const [key, value] of Object.entries(raw)) {
		const rule = INFER_OPTION_RULES[key];
		if (!rule || !rule(value)) throw new BridgeError(400, "invalid_options");
		out[key] = value;
	}
	return out;
}

const SIDECAR_SUFFIXES = ["-journal", "-wal", "-shm"];

// Removes SQLite sidecar files of a store that is already closed. Never touches the main database file.
async function removeSidecars(file) {
	await Promise.all(SIDECAR_SUFFIXES.map(suffix => rm(file + suffix, { force: true })));
}

async function removeDb(file) {
	await rm(file, { force: true });
	await removeSidecars(file);
}

// Owns one isolated SDK store per profile at <dataDir>/profiles/<id>/auth.sqlite.
// Every profile is bound to one provider in binding.json; the SDK is never given a default or discovered store.
// Login attempts write to attempt-<sid>.sqlite and replace auth.sqlite only on success.
export function createProfiles({ dataDir, sdk, authProviders, fetchImpl = globalThis.fetch }) {
	const states = new Map();
	const locks = new Map();

	const dirOf = id => join(dataDir, "profiles", id);
	const dbOf = id => join(dirOf(id), "auth.sqlite");
	const attemptOf = (id, sid) => join(dirOf(id), `attempt-${sid}.sqlite`);
	const bindingOf = id => join(dirOf(id), "binding.json");

	// Serializes work on one key. Lifecycle uses the profile id; store file swaps use "store:<id>" as a leaf lock.
	async function withLock(key, fn) {
		const prev = locks.get(key) ?? Promise.resolve();
		const run = prev.then(fn, fn);
		const tail = run.catch(() => {});
		locks.set(key, tail);
		try {
			return await run;
		} finally {
			if (locks.get(key) === tail) locks.delete(key);
		}
	}

	async function readBinding(id) {
		try {
			const parsed = JSON.parse(await readFile(bindingOf(id), "utf8"));
			return typeof parsed?.provider === "string" ? parsed : null;
		} catch {
			return null;
		}
	}

	async function writeBinding(id, provider) {
		await mkdir(dirOf(id), { recursive: true, mode: 0o700 });
		await writeFile(bindingOf(id), JSON.stringify({ provider }), { mode: 0o600 });
	}

	function state(id) {
		let st = states.get(id);
		if (!st) {
			st = { id, auth: null, streams: new Set(), closing: false, sessions: null };
			st.sessions = new LoginSessions({
				store: {
					openAttempt: sid => openAttempt(id, sid),
					commit: (sid, auth, canCommit) => commitAttempt(id, sid, auth, canCommit),
					discard: (sid, auth) => discardAttempt(id, sid, auth),
				},
			});
			states.set(id, st);
		}
		return st;
	}

	// Maps an unsupported existing file to a fixed code; the file is left as is.
	async function openStore(file) {
		try {
			return await createAuthStore(file, { providers: authProviders });
		} catch (error) {
			if (error?.code === "unsupported_schema") throw new BridgeError(409, "unsupported_store");
			throw error;
		}
	}

	async function openAuth(st) {
		if (st.closing) throw new BridgeError(409, "profile_closing");
		if (!st.auth) {
			await withLock(`store:${st.id}`, async () => {
				if (st.closing) throw new BridgeError(409, "profile_closing");
				if (st.auth) return;
				await mkdir(dirOf(st.id), { recursive: true, mode: 0o700 });
				st.auth = await openStore(dbOf(st.id));
			});
		}
		return st.auth;
	}

	async function openAttempt(id, sid) {
		await mkdir(dirOf(id), { recursive: true, mode: 0o700 });
		return openStore(attemptOf(id, sid));
	}

	// Promotes a staged store over the profile store. The old grant stays intact until the rename succeeds.
	// canCommit() is checked before any file change and again with no await before renameSync, so a
	// cancel that lands during commit can never promote the staged grant.
	// Closing the old store drains any rotating refresh first; an existing unsupported file fails the commit untouched.
	async function commitAttempt(id, sid, auth, canCommit) {
		await withLock(`store:${id}`, async () => {
			if (!canCommit()) throw new Error("commit_cancelled");
			await auth.close();
			const st = states.get(id);
			let old = st?.auth ?? null;
			if (st) st.auth = null;
			if (!old && existsSync(dbOf(id))) old = await openStore(dbOf(id));
			if (old) await old.close();
			await removeSidecars(dbOf(id));
			if (!canCommit()) throw new Error("commit_cancelled");
			renameSync(attemptOf(id, sid), dbOf(id));
		});
	}

	// Discards only this attempt's staging store. The profile store is never touched.
	async function discardAttempt(id, sid, auth) {
		try {
			if (auth) await auth.close();
		} finally {
			await removeDb(attemptOf(id, sid));
		}
	}

	// Local metadata only: reads the SQLite row, never refreshes or calls the provider.
	async function connectedGrant(id, provider) {
		const binding = await readBinding(id);
		if (!binding || binding.provider !== provider || !existsSync(dbOf(id))) return null;
		const st = state(id);
		const auth = await openAuth(st);
		return auth.get(provider);
	}

	// Removes this profile's files. Callers must have cancelled attempts and drained streams first.
	// An existing store that is not open is probed first so an unsupported file is refused, never deleted.
	async function removeStoreFiles(id) {
		await withLock(`store:${id}`, async () => {
			const st = states.get(id);
			let old = st?.auth ?? null;
			if (st) st.auth = null;
			if (!old && existsSync(dbOf(id))) old = await openStore(dbOf(id));
			if (old) await old.close();
			await rm(dirOf(id), { recursive: true, force: true });
		});
	}

	async function prepareStart(id, provider) {
		const binding = await readBinding(id);
		if (binding && binding.provider !== provider) {
			if (await connectedGrant(id, binding.provider)) throw new BridgeError(409, "provider_mismatch");
			await removeStoreFiles(id);
		}
		await writeBinding(id, provider);
	}

	// Resolves the request credential (refreshing if expired). A store closed by a relogin swap is reopened once.
	async function resolveKey(st, provider, signal) {
		for (let attempt = 0; ; attempt++) {
			const auth = await openAuth(st);
			try {
				const before = oauthSecrets(auth, provider);
				const apiKey = await auth.getKey(provider, { signal });
				return { apiKey, secrets: [...before, ...oauthSecrets(auth, provider)] };
			} catch (error) {
				if (error?.code !== "store_closed" || attempt > 0 || st.closing) throw error;
			}
		}
	}

	function findModel(provider, modelId) {
		if (typeof modelId !== "string") throw new BridgeError(400, "unknown_model");
		const model = sdk.getBundledModels(provider).find(m => m.id === modelId);
		if (!model) throw new BridgeError(400, "unknown_model");
		return model;
	}

	return {
		async startLogin(id, provider) {
			return withLock(id, async () => {
				// Cancel any prior attempt before the store is touched, so its staging file is not removed underneath it.
				state(id).sessions.cancel(null);
				await state(id).sessions.drain();
				await prepareStart(id, provider);
				return state(id).sessions.start(provider);
			});
		},

		loginStatus(id, sessionId) {
			return state(id).sessions.get(sessionId);
		},

		submitLoginInput(id, sessionId, value) {
			return state(id).sessions.submit(sessionId, value);
		},

		async cancelLogin(id, sessionId) {
			return withLock(id, () => state(id).sessions.cancel(sessionId));
		},

		async status(id, provider) {
			assertProvider(provider);
			const grant = await connectedGrant(id, provider);
			if (!grant) return { connected: false };
			return { connected: true, email: grant.email, expires_at: new Date(grant.expires).toISOString() };
		},

		async models(id, provider) {
			assertProvider(provider);
			return sdk.getBundledModels(provider).map(m => ({
				id: m.id,
				name: m.name,
				context_window: m.contextWindow ?? null,
				supported_efforts: [...sdk.getSupportedEfforts(m)],
			}));
		},

		// Validates everything that can fail before streaming starts; those failures return a plain JSON error status.
		// Returns { lines, cancel }: lines is an async iterable of NDJSON text chunks, cancel aborts the SDK call.
		async infer(id, body, signal) {
			const provider = assertProvider(body.provider);
			const model = findModel(provider, body.model);
			const context = body.context;
			if (typeof context !== "object" || context === null || !Array.isArray(context.messages)) {
				throw new BridgeError(400, "invalid_context");
			}
			const options = pickInferOptions(body.options);
			if (options.reasoning && !options.forceReasoningOff && !sdk.getSupportedEfforts(model).includes(options.reasoning)) {
				throw new BridgeError(400, "unsupported_reasoning_effort");
			}
			if (!(await connectedGrant(id, provider))) throw new BridgeError(409, "not_connected");
			const st = state(id);

			const ctrl = new AbortController();
			signal?.addEventListener("abort", () => ctrl.abort(), { once: true });

			let finish;
			const done = new Promise(resolve => (finish = resolve));
			const entry = { ctrl, done };
			const end = () => {
				st.streams.delete(entry);
				finish();
			};
			// Registered before credential resolution so disconnect aborts it and waits for it; the store is not swapped under it.
			st.streams.add(entry);

			let apiKey;
			let redact;
			try {
				const resolved = await resolveKey(st, provider, ctrl.signal);
				apiKey = resolved.apiKey;
				// Refresh may rotate tokens inside the request, so secrets from both sides are redacted.
				redact = redactor([...resolved.secrets, apiKey]);
			} catch (error) {
				end();
				if (error instanceof BridgeError) throw error;
				// Provider error text can echo credentials, so only a fixed code leaves the bridge.
				throw new BridgeError(502, "sdk_error");
			}
			if (!apiKey) {
				end();
				throw new BridgeError(409, "not_connected");
			}

			// Wire capture: onPayload gives the request body (no URL), onSseEvent gives raw SSE frames as the SDK parsed them.
			// Upstream HTTP response bodies are not observable through SDK hooks, so no body-level wire_response is emitted.
			const pending = [];
			let stream;
			try {
				stream = sdk.streamSimple(model, context, {
					...options,
					apiKey,
					signal: ctrl.signal,
					onPayload: payload => {
						pending.push({ type: "wire_request", body: payload });
						return undefined;
					},
					onSseEvent: frame => {
						pending.push({ type: "wire_sse", event: frame });
					},
				});
			} catch (error) {
				end();
				throw error;
			}

			const line = obj => redact(JSON.stringify(obj)) + "\n";

			let started = false;
			async function* emit() {
				started = true;
				let terminal = false;
				// Protocol: nonterminal event lines omit the redundant `partial` snapshot (it grows with every delta, so
				// serializing it per event is quadratic). Deltas, tool calls and other fields are kept, and the final
				// `done.message` or `error.error` carries full state. The latest partial is attached once to bridge_error
				// if the SDK throws before a terminal event, so the interrupted state is preserved.
				let lastPartial;
				try {
					for await (const event of stream) {
						while (pending.length) yield line(pending.shift());
						const terminalEvent = event.type === "done" || event.type === "error";
						if (terminalEvent) {
							yield line(event);
						} else {
							if ("partial" in event) lastPartial = event.partial;
							const { partial: _omitted, ...rest } = event;
							yield line(rest);
						}
						if (event.type === "done" || event.type === "error") terminal = true;
					}
					while (pending.length) yield line(pending.shift());
					if (!terminal) yield line({ type: "bridge_error", code: "no_terminal", status: 502, partial: lastPartial });
				} catch {
					if (!terminal) {
						yield line({ type: "bridge_error", code: "stream_failed", status: 502, partial: lastPartial });
					}
				} finally {
					if (!terminal) ctrl.abort();
					end();
				}
			}

			return {
				lines: emit(),
				cancel: () => {
					ctrl.abort();
					if (!started) end();
				},
			};
		},

		// Disconnect cancels attempts and aborts inference, each bounded. If the SDK ignores abort, it fails with 504
		// and leaves every file in place, so the profile can be retried instead of losing its grant.
		async disconnect(id) {
			return withLock(id, async () => {
				const st = states.get(id);
				if (st) {
					st.closing = true;
					try {
						st.sessions.cancel(null);
						await st.sessions.drain();
						for (const entry of st.streams) entry.ctrl.abort();
						await bounded(Promise.all([...st.streams].map(e => e.done)));
					} catch (err) {
						st.closing = false;
						throw err;
					}
				}
				await removeStoreFiles(id);
				states.delete(id);
				return { connected: false };
			});
		},
		async usage(id, provider) {
			assertProvider(provider);
			if (!(await connectedGrant(id, provider))) throw new BridgeError(409, "not_connected");
			const st = state(id);
			let resolved;
			try {
				resolved = await resolveKey(st, provider);
			} catch (error) {
				if (error instanceof BridgeError) throw error;
				throw new BridgeError(502, "refresh_failed");
			}
			const auth = await openAuth(st);
			const grant = auth.get(provider);
			if (!grant || !grant.access) throw new BridgeError(409, "not_connected");

			const secrets = oauthSecrets(auth, provider);
			if (resolved?.apiKey && typeof resolved.apiKey === "string") {
				secrets.push(resolved.apiKey);
			}
			const redact = redactor(secrets);

			const result = await fetchUsage({
				provider,
				grant,
				fetchImpl,
			});
			return JSON.parse(redact(JSON.stringify(result)));
		},

		async getUsage(id, provider) {
			return this.usage(id, provider);
		},

		// Graceful shutdown: cancels login attempts, aborts inference, waits for drains (bounded), then closes the stores.
		// Stores are closed without deleting any file or grant. If a drain times out, nothing is closed and the error is returned
		// so the process exits with its files intact.
		async shutdown() {
			const all = [...states.values()];
			for (const st of all) st.closing = true;
			for (const st of all) {
				st.sessions.cancel(null);
				for (const entry of st.streams) entry.ctrl.abort();
			}
			await bounded(Promise.all(all.flatMap(st => [st.sessions.drain(), ...[...st.streams].map(e => e.done)])));
			for (const st of all) {
				if (st.auth) {
					const auth = st.auth;
					st.auth = null;
					await auth.close();
				}
			}
			states.clear();
		},
	};
}

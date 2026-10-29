import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import * as os from "node:os";

// Sanitized error: only a fixed code (and optional upstream HTTP status) is exposed, never provider prose or tokens.
export class OAuthError extends Error {
	constructor(code, status) {
		super(code);
		this.name = "OAuthError";
		this.code = code;
		this.status = status;
	}
}

const b64url = buf => Buffer.from(buf).toString("base64url");

export function createPkce() {
	const verifier = b64url(randomBytes(32));
	const challenge = b64url(createHash("sha256").update(verifier).digest());
	return { verifier, challenge, state: b64url(randomBytes(24)) };
}

export function decodeJwt(token) {
	try {
		const parts = String(token).split(".");
		if (parts.length !== 3) return null;
		const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
		return payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
	} catch {
		return null;
	}
}

export function abortableDelay(ms, signal) {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) return reject(new OAuthError("cancelled"));
		const onAbort = () => {
			clearTimeout(timer);
			reject(new OAuthError("cancelled"));
		};
		const timer = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

// Reads the body in chunks and stops at maxBytes so a hostile endpoint cannot exhaust memory.
async function readBounded(res, maxBytes, aborted, abortReason) {
	const declared = Number(res.headers?.get?.("content-length"));
	if (Number.isFinite(declared) && declared > maxBytes) {
		try {
			await res.body?.cancel();
		} catch {}
		throw new OAuthError("response_too_large");
	}
	if (!res.body) return "";
	let reader;
	try {
		reader = res.body.getReader();
	} catch (err) {
		try {
			await res.body?.cancel();
		} catch {}
		throw err instanceof OAuthError ? err : abortReason?.() ?? new OAuthError("network_error");
	}
	const chunks = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await Promise.race([reader.read(), aborted]);
			if (done) break;
			size += value.byteLength;
			if (size > maxBytes) throw new OAuthError("response_too_large");
			chunks.push(value);
		}
	} catch (err) {
		try {
			await reader?.cancel();
		} catch {}
		throw err instanceof OAuthError ? err : abortReason?.() ?? new OAuthError("network_error");
	} finally {
		try {
			reader?.releaseLock();
		} catch {}
	}
	return Buffer.concat(chunks).toString("utf8");
}

export async function requestJSON(fetchImpl, url, init = {}, { signal, timeoutMs = 15000, maxBytes = 1048576 } = {}) {
	const timeout = AbortSignal.timeout(timeoutMs);
	const parts = [timeout, signal, init.signal].filter(Boolean);
	const combined = AbortSignal.any(parts);
	const reason = () => new OAuthError(timeout.aborted && !signal?.aborted && !init.signal?.aborted ? "timeout" : "cancelled");
	if (combined.aborted) throw reason();
	let onAbort;
	const aborted = new Promise((_, reject) => {
		onAbort = () => reject(reason());
		combined.addEventListener("abort", onAbort, { once: true });
	});
	aborted.catch(() => {});
	try {
		let res;
		try {
			res = await Promise.race([fetchImpl(url, { ...init, signal: combined }), aborted]);
		} catch (err) {
			throw err instanceof OAuthError ? err : combined.aborted ? reason() : new OAuthError("network_error");
		}
		if (!res.ok) {
			res.body?.cancel().catch(() => {});
			throw new OAuthError("http_error", res.status);
		}
		const abortReason = () => (combined.aborted ? reason() : null);
		const text = await readBounded(res, maxBytes, aborted, abortReason);
		try {
			return JSON.parse(text);
		} catch {
			throw new OAuthError("invalid_response", res.status);
		}
	} finally {
		combined.removeEventListener("abort", onAbort);
	}
}

const safeEqual = (a, b) => {
	const x = Buffer.from(String(a));
	const y = Buffer.from(String(b));
	return x.length === y.length && timingSafeEqual(x, y);
};

const PAGE = message =>
	`<!doctype html><meta charset="utf-8"><title>Sign-in</title><body><p>${message}</p></body>`;

function originMatches(target, expected) {
	if (target.origin === expected.origin) return true;
	if (expected.hostname === "localhost" && target.protocol === expected.protocol && target.port === expected.port) {
		return target.hostname === "127.0.0.1" || target.hostname === "[::1]";
	}
	return false;
}

// Returns {code}, {error} (terminal provider denial) or {} (not acceptable; keep waiting).
function parseCallback(target, expected, state) {
	if (!originMatches(target, expected) || target.pathname !== expected.pathname) return {};
	const got = target.searchParams.get("state");
	if (got === null || !safeEqual(got, state)) return {};
	if (target.searchParams.get("error")) return { error: "authorization_denied" };
	const code = target.searchParams.get("code");
	return code ? { code } : {};
}

function parseManual(input, expected, state, manualFormat) {
	const text = String(input ?? "").trim();
	if (!text) return {};
	let target = null;
	try {
		target = new URL(text);
	} catch {}
	if (target) return parseCallback(target, expected, state);
	if (manualFormat !== "code-state") return {};
	const at = text.indexOf("#");
	if (at <= 0) return {};
	const gotState = text.slice(at + 1);
	return gotState && safeEqual(gotState, state) ? { code: text.slice(0, at) } : {};
}

function isAddressInUse(error) {
	const code = error?.code;
	if (typeof code === "string") return code === "EADDRINUSE";
	return error instanceof Error && /EADDRINUSE|address already in use/i.test(error.message);
}

function hasIpv6Loopback() {
	try {
		const interfaces = os.networkInterfaces();
		for (const name in interfaces) {
			const addresses = interfaces[name];
			if (!addresses) continue;
			for (const address of addresses) {
				if (address.internal && (address.family === "IPv6" || address.family === 6)) {
					return true;
				}
			}
		}
	} catch {}
	return false;
}

function listenServer(server, port, host) {
	return new Promise((resolve, reject) => {
		const onError = err => {
			server.removeListener("listening", onListen);
			reject(err);
		};
		const onListen = () => {
			server.removeListener("error", onError);
			resolve();
		};
		server.once("error", onError);
		server.once("listening", onListen);
		server.listen(port, host);
	});
}

function closeServer(server) {
	return new Promise(resolve => {
		server.close(() => resolve());
		server.closeAllConnections?.();
	});
}

export async function authorizationCode({
	url,
	buildUrl,
	redirectUri,
	state,
	ctrl = {},
	timeoutMs = 600000,
	manualFormat = "url",
	manualOnBindError = true,
	allowRandomPort = false,
}) {
	const signal = ctrl.signal;
	if (signal?.aborted) throw new OAuthError("cancelled");
	if (!state) throw new OAuthError("invalid_state");
	let expected;
	try {
		expected = new URL(redirectUri);
	} catch {
		throw new OAuthError("invalid_redirect_uri");
	}
	// Only loopback http callbacks may be bound; anything else would be an external redirect target.
	if (expected.protocol !== "http:" || !["localhost", "127.0.0.1", "[::1]"].includes(expected.hostname)) {
		throw new OAuthError("invalid_redirect_uri");
	}

	let settled = false;
	let resolveResult;
	let rejectResult;
	const result = new Promise((resolve, reject) => {
		resolveResult = resolve;
		rejectResult = reject;
	});
	result.catch(() => {});
	const finish = (err, val) => {
		if (settled) return;
		settled = true;
		if (err) rejectResult(err);
		else resolveResult(val);
	};

	let servers = [];
	let actualRedirectUri = redirectUri;
	let actualExpected = expected;

	const handleRequest = (req, res) => {
		const reply = (status, message) => {
			res.writeHead(status, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
				connection: "close",
			});
			res.end(PAGE(message));
		};
		let target;
		try {
			target = new URL(req.url ?? "", actualExpected.origin);
		} catch {
			return reply(400, "Invalid request.");
		}
		const validHost = h => {
			if (!h) return false;
			if (h === actualExpected.host) return true;
			if (actualExpected.hostname === "localhost") {
				const portSuffix = actualExpected.port ? `:${actualExpected.port}` : "";
				return h === `127.0.0.1${portSuffix}` || h === `[::1]${portSuffix}`;
			}
			return false;
		};
		if (target.pathname !== actualExpected.pathname || !validHost(req.headers.host)) {
			return reply(404, "Not found.");
		}
		if (req.method !== "GET") {
			res.setHeader("allow", "GET");
			return reply(405, "Method not allowed.");
		}
		const parsed = parseCallback(target, actualExpected, state);
		if (parsed.error) {
			reply(400, "Sign-in was not completed. You can close this window.");
			return finish(new OAuthError(parsed.error));
		}
		if (!parsed.code) return reply(400, "Invalid request.");
		reply(200, "Sign-in complete. You can close this window.");
		finish(null, { code: parsed.code, redirectUri: actualRedirectUri });
	};

	const timer = setTimeout(() => finish(new OAuthError("timeout")), timeoutMs);
	const onAbort = () => finish(new OAuthError("cancelled"));
	signal?.addEventListener("abort", onAbort, { once: true });
	const manualAbort = new AbortController();
	let listening = false;

	const isLocalhost = expected.hostname === "localhost";
	const preferredPort = Number(expected.port || 80);

	const tryBindPort = async port => {
		if (signal?.aborted) return null;
		const dualStack = isLocalhost && hasIpv6Loopback();
		const primary = createServer(handleRequest);
		const primaryHost = isLocalhost ? "127.0.0.1" : expected.hostname.replace(/^\[|\]$/g, "");
		try {
			await listenServer(primary, port, primaryHost);
		} catch {
			return null;
		}
		if (signal?.aborted) {
			await closeServer(primary);
			return null;
		}
		const boundPort = primary.address().port;
		if (!dualStack) {
			return { servers: [primary], port: boundPort };
		}
		const companion = createServer(handleRequest);
		try {
			await listenServer(companion, boundPort, "::1");
			if (signal?.aborted) {
				await Promise.all([closeServer(primary), closeServer(companion)]);
				return null;
			}
			return { servers: [primary, companion], port: boundPort };
		} catch (err) {
			if (!isAddressInUse(err)) {
				return { servers: [primary], port: boundPort };
			}
			await closeServer(primary);
			return null;
		}
	};

	try {
		let bound = await tryBindPort(preferredPort);
		if (!bound && allowRandomPort) {
			for (let attempt = 0; attempt < 4; attempt++) {
				bound = await tryBindPort(0);
				if (bound) break;
			}
		}

		if (bound) {
			listening = true;
			servers = bound.servers;
			const actualPort = bound.port;
			const u = new URL(redirectUri);
			u.port = String(actualPort);
			actualRedirectUri = u.toString();
			actualExpected = new URL(actualRedirectUri);
			if (actualPort !== preferredPort) {
				ctrl.onProgress?.(`Preferred port ${preferredPort} unavailable, using port ${actualPort}`);
			}
		}

		if (signal?.aborted) onAbort();
		if (!listening && !manualOnBindError) finish(new OAuthError("callback_unavailable"));

		const urlBuilder = typeof buildUrl === "function" ? buildUrl : (typeof url === "function" ? url : () => url);
		const authUrl = urlBuilder(actualRedirectUri);

		if (!settled) ctrl.onAuth?.({ url: authUrl });
		if (!settled && ctrl.onManualCodeInput) {
			void (async () => {
				while (!settled) {
					let input;
					try {
						input = await ctrl.onManualCodeInput(manualAbort.signal);
					} catch {
						if (!listening) finish(new OAuthError("manual_input_failed"));
						return;
					}
					if (settled) return;
					const parsed = parseManual(input, actualExpected, state, manualFormat);
					if (parsed.code) return finish(null, { code: parsed.code, redirectUri: actualRedirectUri });
					if (parsed.error) return finish(new OAuthError(parsed.error));
				}
			})();
		} else if (!settled && !listening) {
			finish(new OAuthError("callback_unavailable"));
		}
		return await result;
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
		manualAbort.abort();
		if (servers.length > 0) {
			await Promise.all(servers.map(closeServer));
		}
	}
}

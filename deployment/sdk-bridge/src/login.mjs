import { randomBytes } from "node:crypto";
import { BridgeError } from "./errors.mjs";

const TEXT_LIMIT = 300;
const INPUT_LIMIT = 4096;
// Upper bound on waiting for an SDK login or stream to honor abort; beyond it the caller gets 504 and nothing is deleted.
export const DRAIN_TIMEOUT_MS = 5000;

function clip(value, limit = TEXT_LIMIT) {
	return String(value).slice(0, limit);
}

export function bounded(promise, ms = DRAIN_TIMEOUT_MS) {
	let timer;
	const timeout = new Promise((_, reject) => {
		timer = setTimeout(() => reject(new BridgeError(504, "drain_timeout")), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// store: { openAttempt(sid) -> auth store, commit(sid, auth, canCommit), discard(sid, auth|null) }
// Each attempt writes to its own staging store; only a successful, non-cancelled attempt is committed
// over the profile store, so a cancelled relogin never touches an existing connected grant.
// One login attempt per profile: the latest session is the only one that can be polled, answered, or cancelled.
export class LoginSessions {
	constructor({ store }) {
		this.store = store;
		this.current = null;
	}

	async start(provider) {
		if (this.current) await bounded(this.cancelSession(this.current));

		const s = {
			id: randomBytes(16).toString("hex"),
			provider,
			status: "pending",
			authorization_url: undefined,
			instructions: undefined,
			progress: undefined,
			prompt: undefined,
			email: undefined,
			expires_at: undefined,
			error: undefined,
			aborted: false,
			abort: new AbortController(),
			pending: null,
			done: null,
		};
		this.current = s;
		s.done = this.run(s);
		return { session_id: s.id, status: "pending" };
	}

	get(sessionId) {
		return this.view(this.match(sessionId));
	}

	submit(sessionId, value) {
		const s = this.match(sessionId);
		if (!s.pending) throw new BridgeError(409, "no_pending_prompt");
		if (typeof value !== "string" || value.length > INPUT_LIMIT) throw new BridgeError(400, "invalid_value");
		if (value === "" && !s.pending.allowEmpty) throw new BridgeError(400, "invalid_value");
		const { resolve } = s.pending;
		s.pending = null;
		s.prompt = undefined;
		// The value goes straight to the SDK; it is never stored or logged here.
		resolve(value);
		return { status: s.status };
	}

	// sessionId null cancels whatever attempt is current (used by disconnect).
	async cancel(sessionId) {
		if (sessionId !== null && this.match(sessionId) !== this.current) {
			throw new BridgeError(404, "not_found");
		}
		if (!this.current) return { status: "cancelled" };
		this.cancelSession(this.current);
		return this.view(this.current);
	}

	match(sessionId) {
		if (!this.current || this.current.id !== sessionId) throw new BridgeError(404, "not_found");
		return this.current;
	}

	// Non-blocking: aborts the attempt and returns its run promise. Status stays pending until the run ends, and an aborted run never commits.
	cancelSession(s) {
		if (s.status === "pending") {
			s.aborted = true;
			s.abort.abort();
			if (s.pending) {
				s.pending.reject(new Error("cancelled"));
				s.pending = null;
				s.prompt = undefined;
			}
		}
		return s.done;
	}

	// Bounded wait for the current attempt to finish; used by disconnect, shutdown, and before a new start.
	async drain() {
		if (this.current) await bounded(this.current.done);
	}

	ask(s, prompt, allowEmpty) {
		if (s.aborted) return Promise.reject(new Error("cancelled"));
		s.pending?.reject(new Error("superseded"));
		return new Promise((resolve, reject) => {
			s.pending = { resolve, reject, allowEmpty };
			s.prompt = {
				message: clip(prompt.message),
				placeholder: prompt.placeholder ? clip(prompt.placeholder) : undefined,
				secret: prompt.secret === true,
				allow_empty: allowEmpty,
			};
		});
	}

	async run(s) {
		const ctrl = {
			signal: s.abort.signal,
			onAuth: info => {
				s.authorization_url = info.url;
				s.instructions = info.instructions ? clip(info.instructions) : undefined;
			},
			onProgress: message => {
				s.progress = clip(message, 200);
			},
			onPrompt: prompt => this.ask(s, prompt, prompt.allowEmpty === true),
			onManualCodeInput: () => this.ask(s, { message: "Paste the full callback URL" }, false),
		};
		let auth = null;
		let committed = false;
		try {
			auth = await this.store.openAttempt(s.id);
			const grant = await auth.login(s.provider, ctrl);
			if (s.aborted) {
				s.status = "cancelled";
				return;
			}
			s.email = grant.email;
			s.expires_at = new Date(grant.expires).toISOString();
			await this.store.commit(s.id, auth, () => !s.aborted);
			committed = true;
			s.status = "complete";
		} catch {
			if (s.aborted) {
				s.status = "cancelled";
			} else {
				// Provider error text is deliberately dropped; only a fixed code is exposed.
				s.status = "error";
				s.error = "login_failed";
			}
		} finally {
			if (!committed) {
				try {
					await this.store.discard(s.id, auth);
				} catch {
					// Cleanup failure is surfaced as a fixed code, never as provider or file text.
					s.error = "cleanup_failed";
					if (!s.aborted) s.status = "error";
				}
			}
			s.pending = null;
			s.prompt = undefined;
		}
	}

	view(s) {
		const out = { session_id: s.id, status: s.status };
		for (const key of ["authorization_url", "instructions", "progress", "prompt", "email", "expires_at", "error"]) {
			if (s[key] !== undefined) out[key] = s[key];
		}
		return out;
	}
}

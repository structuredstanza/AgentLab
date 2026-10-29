import { Database } from "bun:sqlite";

// application_id marks a file as this store's private schema; any other populated database is refused untouched.
const APPLICATION_ID = 0x4f415554;
const SCHEMA_VERSION = 1;
// Upper bound on a provider refresh once it has started; the rotated token must be persisted before the caller's abort is honored.
export const REFRESH_TIMEOUT_MS = 30_000;
const GRANT_LIMIT = 64 * 1024;
const OPTIONAL_STRINGS = ["accountId", "email", "orgId", "orgName", "projectId"];

// Codes only (never provider or file text): unsupported_schema, invalid_grant, not_connected, refresh_failed, store_closed, unknown_provider.
export class StoreError extends Error {
	constructor(code) {
		super(code);
		this.name = "StoreError";
		this.code = code;
	}
}

// Strict grant shape. Unknown extra fields are allowed only as scalars so a provider can carry metadata without code here.
export function validateGrant(grant) {
	if (typeof grant !== "object" || grant === null || Array.isArray(grant)) throw new StoreError("invalid_grant");
	if (grant.type !== "oauth") throw new StoreError("invalid_grant");
	for (const key of ["access", "refresh"]) {
		if (typeof grant[key] !== "string" || grant[key].length === 0) throw new StoreError("invalid_grant");
	}
	if (typeof grant.expires !== "number" || !Number.isFinite(grant.expires)) throw new StoreError("invalid_grant");
	for (const key of OPTIONAL_STRINGS) {
		if (grant[key] !== undefined && typeof grant[key] !== "string") throw new StoreError("invalid_grant");
	}
	for (const value of Object.values(grant)) {
		if (value !== undefined && !["string", "number", "boolean"].includes(typeof value)) throw new StoreError("invalid_grant");
	}
	const text = JSON.stringify(grant);
	if (text.length > GRANT_LIMIT) throw new StoreError("invalid_grant");
	return JSON.parse(text);
}

function openDatabase(file) {
	const db = new Database(file);
	try {
		const count = db.query("SELECT count(*) AS n FROM sqlite_master").get().n;
		const appId = db.query("PRAGMA application_id").get().application_id;
		const version = db.query("PRAGMA user_version").get().user_version;
		const fresh = count === 0 && appId === 0 && version === 0;
		if (!fresh && (appId !== APPLICATION_ID || version > SCHEMA_VERSION)) throw new StoreError("unsupported_schema");
		// Order makes a crash mid-init recoverable: the marker is written first, the version last.
		db.run(`PRAGMA application_id = ${APPLICATION_ID}`);
		db.run("CREATE TABLE IF NOT EXISTS grants (provider TEXT PRIMARY KEY, grant TEXT NOT NULL) STRICT");
		db.run(`PRAGMA user_version = ${SCHEMA_VERSION}`);
		return db;
	} catch (error) {
		db.close();
		// A file that is not SQLite at all is also foreign data.
		throw error instanceof StoreError ? error : new StoreError("unsupported_schema");
	}
}

// providers: { <canonical id>: { login(ctrl), refresh(grant, {signal}), apiKey(grant) } }
export async function createAuthStore(file, { providers }) {
	const db = openDatabase(file);
	const select = db.query("SELECT grant FROM grants WHERE provider = ?");
	const upsert = db.query("INSERT INTO grants (provider, grant) VALUES (?, ?) ON CONFLICT(provider) DO UPDATE SET grant = excluded.grant");
	const refreshing = new Map();
	const operations = new Set();
	let closing = null;

	const driverOf = provider => {
		const driver = Object.hasOwn(providers, provider) ? providers[provider] : undefined;
		if (!driver) throw new StoreError("unknown_provider");
		return driver;
	};
	const assertOpen = () => {
		if (closing) throw new StoreError("store_closed");
	};
	const read = provider => {
		const row = select.get(provider);
		return row ? validateGrant(JSON.parse(row.grant)) : null;
	};
	const track = promise => {
		operations.add(promise);
		promise.then(
			() => operations.delete(promise),
			() => operations.delete(promise),
		);
		return promise;
	};

	// Compare-and-swap on the refresh token: a grant replaced meanwhile wins over a stale refresh result.
	const persist = db.transaction((provider, previous, next) => {
		const current = read(provider);
		if (!current) throw new StoreError("not_connected");
		if (current.refresh !== previous.refresh) return current;
		upsert.run(provider, JSON.stringify(next));
		return next;
	});

	// Single flight per provider. The driver gets an internal timeout only: caller cancellation never aborts a rotating refresh,
	// otherwise the provider could rotate the refresh token while the response is dropped.
	function refresh(provider, grant) {
		let flight = refreshing.get(provider);
		if (flight) return flight;
		flight = (async () => {
			let rotated;
			try {
				rotated = await driverOf(provider).refresh(grant, { signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS) });
			} catch {
				throw new StoreError("refresh_failed");
			}
			const next = validateGrant({ ...grant, ...rotated, refresh: rotated?.refresh || grant.refresh });
			return persist(provider, grant, next);
		})().finally(() => refreshing.delete(provider));
		refreshing.set(provider, flight);
		return flight;
	}

	function untilAborted(promise, signal) {
		if (!signal) return promise;
		return new Promise((resolve, reject) => {
			const onAbort = () => reject(signal.reason ?? new StoreError("aborted"));
			promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
			if (signal.aborted) onAbort();
			else signal.addEventListener("abort", onAbort, { once: true });
		});
	}

	return {
		get(provider) {
			assertOpen();
			return read(provider);
		},

		// Writes the grant into this store only; the caller decides whether the staged store is promoted.
		login(provider, ctrl) {
			assertOpen();
			const driver = driverOf(provider);
			return track(
				(async () => {
					const grant = validateGrant(await driver.login(ctrl));
					assertOpen();
					upsert.run(provider, JSON.stringify(grant));
					return grant;
				})(),
			);
		},

		getKey(provider, { signal } = {}) {
			assertOpen();
			const driver = driverOf(provider);
			signal?.throwIfAborted();
			return track(
				(async () => {
					const grant = read(provider);
					if (!grant) throw new StoreError("not_connected");
					if (Date.now() < grant.expires) return driver.apiKey(grant);
					return driver.apiKey(await untilAborted(refresh(provider, grant), signal));
				})(),
			);
		},

		// Rejects new work, waits for in-flight logins and refreshes (bounded by their own timeouts), then closes the database.
		close() {
			closing ??= (async () => {
				await Promise.allSettled([...operations, ...refreshing.values()]);
				db.close();
			})();
			return closing;
		},
	};
}

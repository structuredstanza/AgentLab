import { createHash, timingSafeEqual } from "node:crypto";
import { BridgeError } from "./errors.mjs";
import { PROFILE_ID_PATTERN, assertProvider } from "./profiles.mjs";

export const BRIDGE_VERSION = "0.1.0";
const BODY_LIMIT = 4096;
// Inference requests carry a full pi-ai Context, so they get a larger cap than control-plane bodies.
const INFER_BODY_LIMIT = 8 * 1024 * 1024;
const SESSION_ID = /^[0-9a-f]{32}$/;

function json(status, body) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", "cache-control": "no-store" },
	});
}

function ndjson(result) {
	const enc = new TextEncoder();
	const iterator = result.lines[Symbol.asyncIterator]();
	const stream = new ReadableStream({
		async pull(controller) {
			const { value, done } = await iterator.next();
			if (done) controller.close();
			else controller.enqueue(enc.encode(value));
		},
		cancel() {
			result.cancel();
		},
	});
	return new Response(stream, {
		status: 200,
		headers: { "content-type": "application/x-ndjson", "cache-control": "no-store" },
	});
}

function fail(err) {
	if (err instanceof BridgeError) return json(err.status, { error: err.code });
	// Internal details stay out of the response and out of logs.
	return json(500, { error: "internal" });
}

// Compare digests so the check runs in constant time and does not depend on token length.
function bearerOk(req, expectedDigest) {
	const header = req.headers.get("authorization") ?? "";
	if (!header.startsWith("Bearer ")) return false;
	const got = createHash("sha256").update(header.slice(7)).digest();
	return timingSafeEqual(got, expectedDigest);
}

async function readJson(req, limit = BODY_LIMIT) {
	const reader = req.body?.getReader();
	if (!reader) return {};
	const chunks = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > limit) {
			await reader.cancel();
			throw new BridgeError(413, "body_too_large");
		}
		chunks.push(value);
	}
	const text = Buffer.concat(chunks).toString("utf8");
	if (text === "") return {};
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new BridgeError(400, "invalid_json");
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new BridgeError(400, "invalid_json");
	}
	return parsed;
}

function profileId(raw) {
	if (!PROFILE_ID_PATTERN.test(raw)) throw new BridgeError(400, "invalid_profile_id");
	return raw;
}

function queryProvider(url) {
	const provider = url.searchParams.get("provider");
	if (provider === null) throw new BridgeError(400, "provider_required");
	return assertProvider(provider);
}

export function createHandler({ token, profiles }) {
	const expectedDigest = createHash("sha256").update(token).digest();

	async function route(req, url) {
		const method = req.method;
		const path = url.pathname;

		if (path === "/healthz") {
			if (method !== "GET") throw new BridgeError(405, "method_not_allowed");
			return json(200, { status: "ok", version: BRIDGE_VERSION });
		}
		if (!path.startsWith("/v1/")) throw new BridgeError(404, "not_found");

		// Authentication happens before any body parsing or profile lookup.
		if (!bearerOk(req, expectedDigest)) throw new BridgeError(401, "unauthorized");

		const parts = path.slice("/v1/profiles/".length).split("/");
		if (!path.startsWith("/v1/profiles/") || parts.length < 2) throw new BridgeError(404, "not_found");
		const id = profileId(parts[0]);
		const rest = parts.slice(1);

		if (rest[0] === "login" && rest.length === 2 && rest[1] === "start") {
			if (method !== "POST") throw new BridgeError(405, "method_not_allowed");
			const body = await readJson(req);
			const provider = assertProvider(body.provider);
			return json(200, await profiles.startLogin(id, provider));
		}

		if (rest[0] === "login" && rest.length >= 2) {
			const sessionId = rest[1];
			if (!SESSION_ID.test(sessionId)) throw new BridgeError(404, "not_found");
			if (rest.length === 2) {
				if (method === "GET") return json(200, profiles.loginStatus(id, sessionId));
				if (method === "DELETE") return json(200, await profiles.cancelLogin(id, sessionId));
				throw new BridgeError(405, "method_not_allowed");
			}
			if (rest.length === 3 && rest[2] === "input") {
				if (method !== "POST") throw new BridgeError(405, "method_not_allowed");
				const body = await readJson(req);
				return json(200, profiles.submitLoginInput(id, sessionId, body.value));
			}
			throw new BridgeError(404, "not_found");
		}

		if (rest.length === 1 && rest[0] === "status") {
			if (method !== "GET") throw new BridgeError(405, "method_not_allowed");
			return json(200, await profiles.status(id, queryProvider(url)));
		}

		if (rest.length === 1 && rest[0] === "grant") {
			if (method !== "DELETE") throw new BridgeError(405, "method_not_allowed");
			return json(200, await profiles.disconnect(id));
		}

		if (rest.length === 1 && rest[0] === "models") {
			if (method !== "GET") throw new BridgeError(405, "method_not_allowed");
			return json(200, { models: await profiles.models(id, queryProvider(url)) });
		}
		if (rest.length === 1 && rest[0] === "usage") {
			if (method !== "GET") throw new BridgeError(405, "method_not_allowed");
			return json(200, await profiles.usage(id, queryProvider(url)));
		}


		if (rest.length === 1 && rest[0] === "infer") {
			if (method !== "POST") throw new BridgeError(405, "method_not_allowed");
			const body = await readJson(req, INFER_BODY_LIMIT);
			return ndjson(await profiles.infer(id, body, req.signal));
		}

		throw new BridgeError(404, "not_found");
	}

	return async function fetch(req) {
		try {
			return await route(req, new URL(req.url));
		} catch (err) {
			return fail(err);
		}
	};
}

export function startServer({ host, port, token, profiles }) {
	return Bun.serve({ hostname: host, port, fetch: createHandler({ token, profiles }) });
}

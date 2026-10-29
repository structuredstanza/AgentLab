import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthStore } from "../src/oauth/store.mjs";
import { createProfiles } from "../src/profiles.mjs";
import { createHandler } from "../src/server.mjs";

// Drives the real /infer path with an injected SDK whose streamSimple yields scripted native events.
const TOKEN = "t".repeat(40);
const auth = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
const API_KEY = "sk-secret-value";
const context = { messages: [{ role: "user", content: "hi" }] };
const model = { id: "m1", name: "Model One", provider: "anthropic", supportedEfforts: ["low", "high"] };
let dataDir;
let streamCalls;

const authProviders = {
	anthropic: {
		login: async () => ({ type: "oauth", access: "at-1", refresh: "rt-1", expires: 4102444800000, email: "a@b.c" }),
		refresh: async () => {
			throw new Error("not used");
		},
		apiKey: () => API_KEY,
	},
};

function makeSdk(script) {
	return {
		getBundledModels: () => [model],
		getSupportedEfforts: m => m.supportedEfforts,
		streamSimple(_m, _ctx, opts) {
			streamCalls++;
			return (async function* () {
				opts.onPayload({ model: "m1", stream: true });
				yield* script(opts);
			})();
		},
	};
}

function handlerFor(sdk) {
	return createHandler({ token: TOKEN, profiles: createProfiles({ dataDir, sdk, authProviders }) });
}

async function bindAndConnect() {
	const dir = join(dataDir, "profiles", "1");
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "binding.json"), JSON.stringify({ provider: "anthropic" }));
	const store = await createAuthStore(join(dir, "auth.sqlite"), { providers: authProviders });
	await store.login("anthropic", {});
	await store.close();
}

async function infer(handle) {
	const res = await handle(
		new Request("http://127.0.0.1:8788/v1/profiles/1/infer", {
			method: "POST",
			headers: auth,
			body: JSON.stringify({ provider: "anthropic", model: "m1", context }),
		}),
	);
	expect(res.status).toBe(200);
	expect(res.headers.get("content-type")).toBe("application/x-ndjson");
	const text = await res.text();
	return text.split("\n").filter(Boolean).map(l => JSON.parse(l));
}

beforeEach(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "bridge-stream-"));
	streamCalls = 0;
	await bindAndConnect();
});

afterEach(() => rmSync(dataDir, { recursive: true, force: true }));

describe("native NDJSON stream", () => {
	test("unsupported configured reasoning effort is rejected before streaming", async () => {
		const handle = handlerFor(makeSdk(async function* () {}));
		const res = await handle(
			new Request("http://127.0.0.1:8788/v1/profiles/1/infer", {
				method: "POST",
				headers: auth,
				body: JSON.stringify({ provider: "anthropic", model: "m1", context, options: { reasoning: "medium" } }),
			}),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("unsupported_reasoning_effort");
		expect(streamCalls).toBe(0);
	});
	test("nonterminal lines drop partial; deltas and terminal message stay intact", async () => {
		const partialA = { role: "assistant", content: [] };
		const message = {
			role: "assistant",
			content: [{ type: "text", text: "hi", textSignature: "opaque-sig" }],
			stopReason: "stop",
		};
		const handle = handlerFor(
			makeSdk(async function* () {
				yield { type: "start", partial: partialA };
				yield { type: "text_delta", contentIndex: 0, delta: "hi", partial: message };
				yield { type: "done", reason: "stop", message };
			}),
		);
		const lines = await infer(handle);
		expect(lines.map(l => l.type)).toEqual(["wire_request", "start", "text_delta", "done"]);
		expect(lines[1]).toEqual({ type: "start" });
		expect(lines[2]).toEqual({ type: "text_delta", contentIndex: 0, delta: "hi" });
		expect(lines[3].message).toEqual(message);
	});

	test("SDK throw before terminal attaches last partial once as bridge_error", async () => {
		const partial = { role: "assistant", content: [{ type: "text", text: "par", textSignature: "s1" }] };
		const handle = handlerFor(
			makeSdk(async function* () {
				yield { type: "text_delta", contentIndex: 0, delta: "par", partial };
				throw new Error("upstream failed");
			}),
		);
		const lines = await infer(handle);
		const last = lines.at(-1);
		expect(last.type).toBe("bridge_error");
		expect(last.code).toBe("stream_failed");
		expect(last.status).toBe(502);
		expect(last.partial).toEqual(partial);
		expect(lines.filter(l => "partial" in l)).toEqual([last]);
	});

	test("terminal error event keeps full native error message", async () => {
		const error = { role: "assistant", stopReason: "error", errorMessage: "rate limited", content: [] };
		const handle = handlerFor(
			makeSdk(async function* () {
				yield { type: "error", reason: "error", error };
			}),
		);
		const lines = await infer(handle);
		expect(lines.at(-1)).toEqual({ type: "error", reason: "error", error });
	});

	test("missing terminal event is reported, not success", async () => {
		const handle = handlerFor(
			makeSdk(async function* () {
				yield { type: "text_delta", contentIndex: 0, delta: "x" };
			}),
		);
		const lines = await infer(handle);
		expect(lines.at(-1)).toEqual({ type: "bridge_error", code: "no_terminal", status: 502, partial: undefined });
	});

	test("credential is redacted from every line", async () => {
		const handle = handlerFor(
			makeSdk(async function* (opts) {
				yield { type: "text_delta", contentIndex: 0, delta: `echo ${API_KEY}` };
				yield { type: "done", reason: "stop", message: { role: "assistant", content: [{ type: "text", text: API_KEY }] } };
			}),
		);
		const handleRes = await handle(
			new Request("http://127.0.0.1:8788/v1/profiles/1/infer", {
				method: "POST",
				headers: auth,
				body: JSON.stringify({ provider: "anthropic", model: "m1", context }),
			}),
		);
		const text = await handleRes.text();
		expect(text).not.toContain(API_KEY);
		expect(text).toContain("[redacted]");
	});
});

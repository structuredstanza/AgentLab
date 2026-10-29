import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createProfiles } from "../src/profiles.mjs";
import { createHandler } from "../src/server.mjs";

// Covers only validation that happens before streaming starts. The NDJSON stream itself needs the real SDK offline fixture.
const fakeSdk = {
	streamSimple() { throw new Error("not used"); },
	getBundledModels: () => [{ id: "m1", name: "Model One", provider: "anthropic" }],
	getSupportedEfforts: () => [],
};

const TOKEN = "t".repeat(40);
const auth = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
const context = { messages: [{ role: "user", content: "hi" }] };
let dataDir;
let handle;

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "bridge-infer-"));
	handle = createHandler({ token: TOKEN, profiles: createProfiles({ dataDir, sdk: fakeSdk, authProviders: {} }) });
});

afterEach(() => rmSync(dataDir, { recursive: true, force: true }));

const post = body =>
	handle(new Request("http://127.0.0.1:8788/v1/profiles/1/infer", {
		method: "POST",
		headers: auth,
		body: JSON.stringify(body),
	}));

describe("infer validation before streaming", () => {
	test("unknown provider", async () => {
		const res = await post({ provider: "openai", model: "m1", context });
		expect((await res.json()).error).toBe("unsupported_provider");
	});

	test("model outside the catalog", async () => {
		const res = await post({ provider: "anthropic", model: "invented", context });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("unknown_model");
	});

	test("malformed context", async () => {
		const res = await post({ provider: "anthropic", model: "m1", context: { messages: "x" } });
		expect((await res.json()).error).toBe("invalid_context");
	});

	test("transport fields in options are refused", async () => {
		for (const options of [{ apiKey: "x" }, { baseUrl: "https://a.invalid" }, { headers: {} }, { fetch: 1 }]) {
			const res = await post({ provider: "anthropic", model: "m1", context, options });
			expect((await res.json()).error).toBe("invalid_options");
		}
	});

	test("bad option values are refused", async () => {
		const res = await post({ provider: "anthropic", model: "m1", context, options: { reasoning: "extreme" } });
		expect((await res.json()).error).toBe("invalid_options");
	});

	test("no grant means not connected, with no stream started", async () => {
		const res = await post({ provider: "anthropic", model: "m1", context });
		expect(res.status).toBe(409);
		expect((await res.json()).error).toBe("not_connected");
	});
});

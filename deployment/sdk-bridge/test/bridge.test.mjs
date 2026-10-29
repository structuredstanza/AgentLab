import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createProfiles } from "../src/profiles.mjs";
import { createHandler } from "../src/server.mjs";

// Seams for bridge-logic boundaries only: provider drivers are fake, while the grant store (SQLite, staging, rename promotion) is the real owned store.
let loginMode = "complete";
let loginGate = null;
let loginEmail = "u@example.invalid";
const fakeDriver = {
	async login(ctrl) {
		ctrl.onAuth({ url: "https://auth.example.invalid/start" });
		if (loginMode === "prompt") {
			const value = await ctrl.onPrompt({ message: "Enter code", secret: true });
			if (value !== "123") throw new Error("bad");
		}
		if (loginMode === "gate") await loginGate;
		return { type: "oauth", access: "fake-access", refresh: "fake-refresh", expires: 4102444800000, email: loginEmail };
	},
	async refresh() {
		throw new Error("not used");
	},
	apiKey: grant => grant.access,
};
const authProviders = { anthropic: fakeDriver, "openai-codex": fakeDriver, "google-antigravity": fakeDriver };
const fakeSdk = {
	streamSimple() {
		throw new Error("not used");
	},
	getBundledModels: () => [{ id: "m1", name: "Model One", contextWindow: 1000 }],
	getSupportedEfforts: () => [],
};

const TOKEN = "t".repeat(40);
let dataDir;
let handle;

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "bridge-test-"));
	loginMode = "complete";
	loginGate = null;
	loginEmail = "u@example.invalid";
	const profiles = createProfiles({ dataDir, sdk: fakeSdk, authProviders });
	handle = createHandler({ token: TOKEN, profiles });
});

afterEach(() => {
	rmSync(dataDir, { recursive: true, force: true });
});

const auth = { authorization: `Bearer ${TOKEN}` };
const req = (method, path, body, headers = auth) =>
	handle(new Request(`http://127.0.0.1:8788${path}`, {
		method,
		headers: body === undefined ? headers : { ...headers, "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	}));

const settle = () => Bun.sleep(5);

async function connect(id, provider = "anthropic") {
	const start = await (await req("POST", `/v1/profiles/${id}/login/start`, { provider })).json();
	await settle();
	return start;
}

describe("auth and routing", () => {
	test("healthz is public and minimal", async () => {
		const res = await req("GET", "/healthz", undefined, {});
		expect(res.status).toBe(200);
		expect(Object.keys(await res.json()).sort()).toEqual(["status", "version"]);
	});

	test("v1 without bearer is refused", async () => {
		expect((await req("GET", "/v1/profiles/1/status?provider=anthropic", undefined, {})).status).toBe(401);
		expect((await req("GET", "/v1/profiles/1/status?provider=anthropic", undefined, { authorization: "Bearer nope" })).status).toBe(401);
	});

	test("non-canonical profile ids are rejected", async () => {
		for (const id of ["0", "01", "-1", "1.5", "abc"]) {
			expect((await req("GET", `/v1/profiles/${id}/status?provider=anthropic`)).status).toBe(400);
		}
	});

	test("unknown provider is rejected", async () => {
		const res = await req("POST", "/v1/profiles/1/login/start", { provider: "openai" });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("unsupported_provider");
	});
});

describe("login flow", () => {
	test("prompt is published and resolved, then grant reports connected", async () => {
		loginMode = "prompt";
		const start = await (await req("POST", "/v1/profiles/1/login/start", { provider: "anthropic" })).json();
		expect(start.status).toBe("pending");
		await settle();

		const pending = await (await req("GET", `/v1/profiles/1/login/${start.session_id}`)).json();
		expect(pending.authorization_url).toBe("https://auth.example.invalid/start");
		expect(pending.prompt.secret).toBe(true);

		const submitted = await req("POST", `/v1/profiles/1/login/${start.session_id}/input`, { value: "123" });
		expect(submitted.status).toBe(200);
		await settle();

		const done = await (await req("GET", `/v1/profiles/1/login/${start.session_id}`)).json();
		expect(done.status).toBe("complete");
		expect(done.email).toBe("u@example.invalid");

		const status = await (await req("GET", "/v1/profiles/1/status?provider=anthropic")).json();
		expect(status.connected).toBe(true);
		expect(status.expires_at).toBe(new Date(4102444800000).toISOString());
		expect(done.expires_at).toBe(new Date(4102444800000).toISOString());
	});

	test("cancelled login that still resolves leaves no grant", async () => {
		loginMode = "gate";
		let release;
		loginGate = new Promise(r => (release = r));
		const start = await (await req("POST", "/v1/profiles/2/login/start", { provider: "anthropic" })).json();
		await settle();
		const cancelled = await (await req("DELETE", `/v1/profiles/2/login/${start.session_id}`)).json();
		expect(["pending", "cancelled"]).toContain(cancelled.status);
		release();
		await settle();
		const view = await (await req("GET", `/v1/profiles/2/login/${start.session_id}`)).json();
		expect(view.status).toBe("cancelled");
		const status = await (await req("GET", "/v1/profiles/2/status?provider=anthropic")).json();
		expect(status.connected).toBe(false);
	});

	test("cancelled relogin keeps the existing connected grant", async () => {
		await connect(7);
		loginMode = "gate";
		let release;
		loginGate = new Promise(r => (release = r));
		const again = await (await req("POST", "/v1/profiles/7/login/start", { provider: "anthropic" })).json();
		await settle();
		await req("DELETE", `/v1/profiles/7/login/${again.session_id}`);
		release();
		await settle();
		const status = await (await req("GET", "/v1/profiles/7/status?provider=anthropic")).json();
		expect(status.connected).toBe(true);
		expect(status.email).toBe("u@example.invalid");
	});

	test("successful relogin replaces the grant", async () => {
		await connect(8);
		loginEmail = "new@example.invalid";
		await connect(8);
		const status = await (await req("GET", "/v1/profiles/8/status?provider=anthropic")).json();
		expect(status.email).toBe("new@example.invalid");
	});

	test("unknown session id is not found", async () => {
		const res = await req("GET", `/v1/profiles/1/login/${"a".repeat(32)}`);
		expect(res.status).toBe(404);
	});
});

describe("binding and disconnect", () => {
	test("provider change under a connected profile is refused", async () => {
		await connect(3, "anthropic");
		const res = await req("POST", "/v1/profiles/3/login/start", { provider: "google-antigravity" });
		expect(res.status).toBe(409);
		expect((await res.json()).error).toBe("provider_mismatch");
	});

	test("models are available without a connected grant and carry catalog metadata", async () => {
		const body = await (await req("GET", "/v1/profiles/4/models?provider=anthropic")).json();
		expect(body.models).toEqual([{ id: "m1", name: "Model One", context_window: 1000, supported_efforts: [] }]);
		await connect(4);
		const connectedBody = await (await req("GET", "/v1/profiles/4/models?provider=anthropic")).json();
		expect(connectedBody).toEqual(body);
	});

	test("disconnect removes the grant", async () => {
		await connect(5);
		await req("DELETE", "/v1/profiles/5/grant");
		const status = await (await req("GET", "/v1/profiles/5/status?provider=anthropic")).json();
		expect(status.connected).toBe(false);
	});
});

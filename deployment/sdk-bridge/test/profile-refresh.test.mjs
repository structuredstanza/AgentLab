import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthStore } from "../src/oauth/store.mjs";
import { createProfiles } from "../src/profiles.mjs";

// Profile-level races around a rotating refresh that is already in flight when the request path resolves its credential.
let dataDir;
let release;
let refreshGate;
let refreshCalls;
let profiles;

const expired = { type: "oauth", access: "at-old", refresh: "rt-old", expires: 1, email: "old@example.invalid" };
const driver = {
	login: async () => ({ type: "oauth", access: "at-login", refresh: "rt-login", expires: 4102444800000, email: "new@example.invalid" }),
	async refresh() {
		refreshCalls++;
		await refreshGate;
		return { type: "oauth", access: "at-rot", refresh: "rt-rot", expires: 4102444800000 };
	},
	apiKey: grant => grant.access,
};
const authProviders = { anthropic: driver };
const sdk = {
	getBundledModels: () => [{ id: "m1", name: "M", provider: "anthropic" }],
	getSupportedEfforts: () => [],
	streamSimple: () => (async function* () {})(),
};
const body = { provider: "anthropic", model: "m1", context: { messages: [{ role: "user", content: "hi" }] } };
const dbFile = () => join(dataDir, "profiles", "1", "auth.sqlite");

async function grantOnDisk() {
	const store = await createAuthStore(dbFile(), { providers: authProviders });
	const grant = store.get("anthropic");
	await store.close();
	return grant;
}

async function waitFor(fn) {
	for (let i = 0; i < 400; i++) {
		if (await fn()) return;
		await Bun.sleep(10);
	}
	throw new Error("waitFor timeout");
}

beforeEach(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "profile-refresh-"));
	refreshCalls = 0;
	refreshGate = new Promise(r => (release = r));
	mkdirSync(join(dataDir, "profiles", "1"), { recursive: true });
	writeFileSync(join(dataDir, "profiles", "1", "binding.json"), JSON.stringify({ provider: "anthropic" }));
	const seed = await createAuthStore(dbFile(), { providers: { anthropic: { ...driver, login: async () => expired } } });
	await seed.login("anthropic", {});
	await seed.close();
	profiles = createProfiles({ dataDir, sdk, authProviders });
});

afterEach(async () => {
	try {
		release?.();
		if (profiles) await profiles.shutdown().catch(() => {});
	} finally {
		if (dataDir) rmSync(dataDir, { recursive: true, force: true });
	}
});

describe("rotating refresh in flight during infer", () => {
	test("disconnect keeps the files until the rotation is saved, then removes them", async () => {
		const request = profiles.infer("1", body).catch(e => e);
		await waitFor(() => refreshCalls === 1);
		let disconnected = false;
		const disconnect = profiles.disconnect("1").then(r => ((disconnected = true), r));
		await Bun.sleep(100);
		expect(disconnected).toBe(false);
		expect(existsSync(dbFile())).toBe(true);
		release();
		expect(await disconnect).toEqual({ connected: false });
		await request;
		expect(existsSync(dbFile())).toBe(false);
		expect(refreshCalls).toBe(1);
	});
	test("relogin commit waits for the rotation and then replaces the grant", async () => {
		const request = profiles.infer("1", body).catch(e => e);
		await waitFor(() => refreshCalls === 1);
		const { session_id } = await profiles.startLogin("1", "anthropic");
		await Bun.sleep(100);
		expect(profiles.loginStatus("1", session_id).status).toBe("pending");
		release();
		await waitFor(() => profiles.loginStatus("1", session_id).status !== "pending");
		expect(profiles.loginStatus("1", session_id).status).toBe("complete");
		await request;
		expect(await grantOnDisk()).toMatchObject({ access: "at-login", refresh: "rt-login" });
		expect(refreshCalls).toBe(1);
	});

	test("cancelling the request does not lose the rotated refresh token", async () => {
		const abort = new AbortController();
		const request = profiles.infer("1", body, abort.signal).catch(e => e);
		await waitFor(() => refreshCalls === 1);
		abort.abort();
		const error = await request;
		expect(error.status).toBe(502);
		release();
		await profiles.shutdown();
		expect(await grantOnDisk()).toMatchObject({ access: "at-rot", refresh: "rt-rot" });
	});
});

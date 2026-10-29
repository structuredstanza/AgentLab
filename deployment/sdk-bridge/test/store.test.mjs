import { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthStore } from "../src/oauth/store.mjs";

let dir;
let file;
let refreshCalls;
let refreshGate;
let refreshResult;

const expired = { type: "oauth", access: "at-old", refresh: "rt-old", expires: 1, email: "u@example.invalid" };
const driver = {
	login: async () => expired,
	async refresh(grant) {
		refreshCalls++;
		await refreshGate;
		return refreshResult(grant);
	},
	apiKey: grant => `key:${grant.access}`,
};
const providers = { anthropic: driver };
const open = () => createAuthStore(file, { providers });

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "store-test-"));
	file = join(dir, "auth.sqlite");
	refreshCalls = 0;
	refreshGate = null;
	refreshResult = () => ({ type: "oauth", access: "at-new", refresh: "rt-new", expires: 4102444800000 });
});

afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("grant storage", () => {
	test("login persists across reopen", async () => {
		const a = await open();
		await a.login("anthropic", {});
		await a.close();
		const b = await open();
		expect(b.get("anthropic")).toEqual(expired);
		expect(b.get("openai-codex")).toBeNull();
		await b.close();
	});

	test("an invalid grant is rejected and nothing is stored", async () => {
		const bad = { ...driver, login: async () => ({ type: "oauth", access: "", refresh: "r", expires: 1 }) };
		const store = await createAuthStore(file, { providers: { anthropic: bad } });
		await expect(store.login("anthropic", {})).rejects.toMatchObject({ code: "invalid_grant" });
		expect(store.get("anthropic")).toBeNull();
		await store.close();
	});

	test("a database with a foreign schema is refused and left byte-identical", async () => {
		const foreign = new Database(file);
		foreign.run("CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, data TEXT)");
		foreign.run("INSERT INTO auth_credentials (data) VALUES ('x')");
		foreign.close();
		const before = readFileSync(file);
		await expect(open()).rejects.toMatchObject({ code: "unsupported_schema" });
		expect(readFileSync(file).equals(before)).toBe(true);
	});
});

describe("refresh", () => {
	test("concurrent requests share one refresh and the rotated grant is durable", async () => {
		const store = await open();
		await store.login("anthropic", {});
		const keys = await Promise.all([store.getKey("anthropic"), store.getKey("anthropic")]);
		expect(keys).toEqual(["key:at-new", "key:at-new"]);
		expect(refreshCalls).toBe(1);
		await store.close();
		const again = await open();
		expect(again.get("anthropic")).toMatchObject({ access: "at-new", refresh: "rt-new", email: "u@example.invalid" });
		await again.close();
	});

	test("near-expiry single flight: requests within skew share one refresh", async () => {
		const nearExpiry = { type: "oauth", access: "at-old", refresh: "rt-old", expires: Date.now() - 1000, email: "u@example.invalid" };
		refreshResult = () => ({ type: "oauth", access: "at-new", refresh: "rt-new", expires: 4102444800000 });
		const store = await createAuthStore(file, { providers: { anthropic: { ...driver, login: async () => nearExpiry } } });
		await store.login("anthropic", {});
		const keys = await Promise.all([store.getKey("anthropic"), store.getKey("anthropic")]);
		expect(keys).toEqual(["key:at-new", "key:at-new"]);
		expect(refreshCalls).toBe(1);
		await store.close();
	});

	test("the old refresh token is kept when the provider omits a new one", async () => {
		refreshResult = () => ({ type: "oauth", access: "at-new", expires: 4102444800000 });
		const store = await open();
		await store.login("anthropic", {});
		await store.getKey("anthropic");
		expect(store.get("anthropic").refresh).toBe("rt-old");
		await store.close();
	});

	test("caller abort does not lose a rotation that already started", async () => {
		let release;
		refreshGate = new Promise(r => (release = r));
		const store = await open();
		await store.login("anthropic", {});
		const abort = new AbortController();
		const key = store.getKey("anthropic", { signal: abort.signal });
		await Bun.sleep(5);
		abort.abort();
		await expect(key).rejects.toBeDefined();
		const closing = store.close();
		release();
		await closing;
		const again = await open();
		expect(again.get("anthropic").refresh).toBe("rt-new");
		await again.close();
	});

	test("a failed refresh surfaces only a fixed code and keeps the grant", async () => {
		refreshResult = () => {
			throw new Error("provider said at-old rt-old");
		};
		const store = await open();
		await store.login("anthropic", {});
		const error = await store.getKey("anthropic").catch(e => e);
		expect(error.code).toBe("refresh_failed");
		expect(error.message).not.toContain("rt-old");
		expect(store.get("anthropic")).toEqual(expired);
		await store.close();
	});
});

describe("close", () => {
	test("rejects new operations once closing", async () => {
		const store = await open();
		await store.login("anthropic", {});
		const closing = store.close();
		expect(() => store.getKey("anthropic")).toThrow(expect.objectContaining({ code: "store_closed" }));
		expect(() => store.get("anthropic")).toThrow(expect.objectContaining({ code: "store_closed" }));
		await closing;
	});
});

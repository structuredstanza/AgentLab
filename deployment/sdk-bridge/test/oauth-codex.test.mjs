import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createCodexOAuth } from "../src/oauth/codex.mjs";

// Offline fixtures: a fail-closed fake fetch stands in for auth.openai.com. The only real socket is the
// loopback callback listener on localhost:1455 that the owned login flow binds itself.

const b64u = o => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = payload => `${b64u({ alg: "none" })}.${b64u(payload)}.sig`;
const profile = ({ account = "acct-1", email = "User@Fixture.Test", plan = "Pro" } = {}) => ({
	"https://api.openai.com/auth": { chatgpt_account_id: account, chatgpt_plan_type: plan },
	"https://api.openai.com/profile": { email },
});
const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function fakeFetch(routes) {
	const calls = [];
	const fetchImpl = async (url, init = {}) => {
		const u = new URL(url);
		const handler = routes[u.origin + u.pathname];
		const body = init.body instanceof URLSearchParams ? Object.fromEntries(init.body) : init.body ? JSON.parse(init.body) : {};
		calls.push({ url: String(url), method: init.method, headers: init.headers, body });
		if (!handler) throw new Error(`unrouted ${url}`);
		return handler(body, calls.length);
	};
	return { fetchImpl, calls };
}

const TOKEN = "https://auth.openai.com/oauth/token";
const sha256 = s => createHash("sha256").update(s).digest("base64url");

function browserCtrl({ callback = "manual", signal } = {}) {
	const seen = {};
	let publish;
	const published = new Promise(r => (publish = r));
	return {
		seen,
		signal,
		onAuth: info => {
			seen.url = new URL(info.url);
			publish();
		},
		onProgress: m => (seen.progress = m),
		onManualCodeInput: async () => {
			await published;
			if (callback !== "manual") return new Promise(() => {});
			const redirect = new URL(seen.url.searchParams.get("redirect_uri"));
			redirect.searchParams.set("code", "code-1");
			redirect.searchParams.set("state", seen.url.searchParams.get("state"));
			return redirect.href;
		},
	};
}

describe("codex oauth login", () => {
	test("sends native PKCE authorize parameters and exchanges the code", async () => {
		const access = jwt(profile());
		const { fetchImpl, calls } = fakeFetch({
			[TOKEN]: () => reply({ access_token: access, refresh_token: "r1", id_token: jwt(profile()), expires_in: 3600 }),
		});
		const ctrl = browserCtrl();
		const before = Date.now();
		const grant = await createCodexOAuth({ fetchImpl }).login(ctrl);
		const q = ctrl.seen.url.searchParams;
		expect(ctrl.seen.url.origin + ctrl.seen.url.pathname).toBe("https://auth.openai.com/oauth/authorize");
		expect(Object.fromEntries(q)).toMatchObject({
			response_type: "code",
			client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
			redirect_uri: "http://localhost:1455/auth/callback",
			scope: "openid profile email offline_access api.connectors.read api.connectors.invoke",
			code_challenge_method: "S256",
			id_token_add_organizations: "true",
			codex_cli_simplified_flow: "true",
			originator: "omp",
		});
		expect(calls).toHaveLength(1);
		expect(calls[0].body).toMatchObject({ grant_type: "authorization_code", code: "code-1", redirect_uri: q.get("redirect_uri") });
		expect(sha256(calls[0].body.code_verifier)).toBe(q.get("code_challenge"));
		expect(grant).toMatchObject({ type: "oauth", access, refresh: "r1", accountId: "acct-1", orgId: "acct-1", orgName: "pro", email: "user@fixture.test" });
		expect(grant.expires).toBeGreaterThanOrEqual(before + 3_600_000);
	});

	test("accepts the browser callback on the localhost listener", async () => {
		const { fetchImpl } = fakeFetch({
			[TOKEN]: () => reply({ access_token: jwt(profile()), refresh_token: "r1", expires_in: 60 }),
		});
		const seen = {};
		const login = createCodexOAuth({ fetchImpl }).login({
			onAuth: info => (seen.url = new URL(info.url)),
		});
		while (!seen.url) await new Promise(r => setTimeout(r, 5));
		const cb = new URL(seen.url.searchParams.get("redirect_uri"));
		const wrong = new URL(cb);
		wrong.searchParams.set("code", "evil");
		wrong.searchParams.set("state", "wrong");
		expect((await fetch(wrong)).status).toBe(400);
		cb.searchParams.set("code", "code-2");
		cb.searchParams.set("state", seen.url.searchParams.get("state"));
		expect((await fetch(cb)).status).toBe(200);
		expect((await login).accountId).toBe("acct-1");
	});

	test("rejects a callback with a mismatched state from manual input", async () => {
		const { fetchImpl, calls } = fakeFetch({});
		const ctrl = browserCtrl();
		let first = true;
		ctrl.onManualCodeInput = async () => (first ? ((first = false), "http://localhost:1455/auth/callback?code=x&state=nope") : new Promise(() => {}));
		const ac = new AbortController();
		ctrl.signal = ac.signal;
		const login = createCodexOAuth({ fetchImpl }).login(ctrl);
		setTimeout(() => ac.abort(), 100);
		await expect(login).rejects.toMatchObject({ code: "cancelled" });
		expect(calls).toHaveLength(0);
	});

	test("invalid_grant on exchange surfaces only a fixed code and status", async () => {
		const { fetchImpl } = fakeFetch({
			[TOKEN]: () => reply({ error: "invalid_grant", error_description: "secret-code-leak", refresh_token: "leaky" }, 400),
		});
		const err = await createCodexOAuth({ fetchImpl }).login(browserCtrl()).catch(e => e);
		expect(err).toMatchObject({ code: "http_error", status: 400 });
		expect(JSON.stringify(err) + err.message).not.toMatch(/secret-code-leak|leaky/);
	});

	test("rejects token responses without identity or required fields", async () => {
		const noIdentity = fakeFetch({ [TOKEN]: () => reply({ access_token: jwt({}), refresh_token: "r", expires_in: 60 }) });
		await expect(createCodexOAuth({ fetchImpl: noIdentity.fetchImpl }).login(browserCtrl())).rejects.toMatchObject({ code: "codex_identity_missing" });
		const noRefresh = fakeFetch({ [TOKEN]: () => reply({ access_token: jwt(profile()), expires_in: 60 }) });
		await expect(createCodexOAuth({ fetchImpl: noRefresh.fetchImpl }).login(browserCtrl())).rejects.toMatchObject({ code: "codex_token_response_invalid" });
	});

	test("takes plan and account from the id_token when the access token lacks them", async () => {
		const { fetchImpl } = fakeFetch({
			[TOKEN]: () =>
				reply({ access_token: jwt({}), id_token: jwt(profile({ account: "acct-id", plan: "TEAM" })), refresh_token: "r", expires_in: 60 }),
		});
		const grant = await createCodexOAuth({ fetchImpl }).login(browserCtrl());
		expect(grant).toMatchObject({ accountId: "acct-id", orgId: "acct-id", orgName: "team", email: "user@fixture.test" });
	});
});

describe("codex oauth refresh", () => {
	const stored = { type: "oauth", access: "old", refresh: "r-old", expires: 1, accountId: "acct-1", email: "kept@fixture.test", orgId: "acct-1", orgName: "pro" };

	test("posts the refresh grant and keeps stored identity when the token carries none", async () => {
		const { fetchImpl, calls } = fakeFetch({ [TOKEN]: () => reply({ access_token: "opaque-access", refresh_token: "r-new", expires_in: 120 }) });
		const grant = await createCodexOAuth({ fetchImpl }).refresh(stored);
		expect(calls[0].body).toEqual({ grant_type: "refresh_token", refresh_token: "r-old", client_id: "app_EMoamEEZ73f0CkXaXp7hrann" });
		expect(grant).toMatchObject({ access: "opaque-access", refresh: "r-new", accountId: "acct-1", email: "kept@fixture.test", orgId: "acct-1", orgName: "pro" });
		expect(grant.expires).toBeGreaterThan(Date.now());
	});

	test("preserves the old refresh token when the response omits it", async () => {
		const { fetchImpl } = fakeFetch({ [TOKEN]: () => reply({ access_token: jwt(profile({ account: "acct-2" })), expires_in: 120 }) });
		const grant = await createCodexOAuth({ fetchImpl }).refresh(stored);
		expect(grant).toMatchObject({ refresh: "r-old", accountId: "acct-2", orgId: "acct-1", orgName: "pro" });
	});

	test("invalid_grant is a fixed error and cancellation is honored", async () => {
		const bad = fakeFetch({ [TOKEN]: () => reply({ error: "invalid_grant", error_description: "leak-me" }, 400) });
		const err = await createCodexOAuth({ fetchImpl: bad.fetchImpl }).refresh(stored).catch(e => e);
		expect(err).toMatchObject({ code: "http_error", status: 400 });
		expect(err.message).not.toContain("leak-me");
		const ac = new AbortController();
		ac.abort();
		await expect(createCodexOAuth({ fetchImpl: bad.fetchImpl }).refresh(stored, { signal: ac.signal })).rejects.toMatchObject({ code: "cancelled" });
		await expect(createCodexOAuth({ fetchImpl: bad.fetchImpl }).refresh({ ...stored, refresh: "" })).rejects.toMatchObject({ code: "codex_refresh_missing" });
	});
});

describe("codex device login", () => {
	const USERCODE = "https://auth.openai.com/api/accounts/deviceauth/usercode";
	const DEVICE_TOKEN = "https://auth.openai.com/api/accounts/deviceauth/token";

	test("polls then exchanges against the device redirect", async () => {
		let polls = 0;
		const { fetchImpl, calls } = fakeFetch({
			[USERCODE]: () => reply({ device_auth_id: "dev-1", user_code: "ABCD-1234", interval: 0 }),
			[DEVICE_TOKEN]: () => (++polls === 1 ? reply({}, 403) : reply({ authorization_code: "dc", code_verifier: "dv" })),
			[TOKEN]: () => reply({ access_token: jwt(profile()), refresh_token: "r", expires_in: 60 }),
		});
		const seen = {};
		const grant = await createCodexOAuth({ fetchImpl }).loginDevice({ onAuth: info => (seen.auth = info) });
		expect(seen.auth).toEqual({ url: "https://auth.openai.com/codex/device", instructions: "Enter code: ABCD-1234" });
		expect(polls).toBe(2);
		expect(calls.at(-1).body).toMatchObject({ code: "dc", code_verifier: "dv", redirect_uri: "https://auth.openai.com/deviceauth/callback" });
		expect(grant.accountId).toBe("acct-1");
	}, 20_000);

	test("cancel during polling stops before any token request", async () => {
		const { fetchImpl, calls } = fakeFetch({ [USERCODE]: () => reply({ device_auth_id: "d", user_code: "U", interval: 0 }) });
		const ac = new AbortController();
		const login = createCodexOAuth({ fetchImpl }).loginDevice({ signal: ac.signal, onAuth: () => ac.abort() });
		await expect(login).rejects.toMatchObject({ code: "cancelled" });
		expect(calls).toHaveLength(1);
	});

	test("polling errors other than pending are terminal and fixed", async () => {
		const { fetchImpl } = fakeFetch({
			[USERCODE]: () => reply({ device_auth_id: "d", user_code: "U", interval: 0 }),
			[DEVICE_TOKEN]: () => reply({ error: "boom-text" }, 500),
		});
		const err = await createCodexOAuth({ fetchImpl }).loginDevice({}).catch(e => e);
		expect(err).toMatchObject({ code: "http_error", status: 500 });
	}, 20_000);
});

import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { createAnthropicOAuth } from "../src/oauth/anthropic.mjs";

// Offline: provider calls go to a fake fetch; the login callback uses the real localhost listener.
const TOKEN_URL = "https://api.anthropic.com/v1/oauth/token";
const BOOTSTRAP_PREFIX = "https://api.anthropic.com/api/claude_cli/bootstrap";
const SECRET = "fixture-secret-body-value";
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });

function fakeFetch(handlers) {
	const calls = [];
	const fn = async (url, init = {}) => {
		const u = String(url);
		const body = init.body ? JSON.parse(init.body) : undefined;
		calls.push({ url: u, init, body });
		const key = u.startsWith(BOOTSTRAP_PREFIX) ? "bootstrap" : u === TOKEN_URL ? "token" : null;
		if (!key || !handlers[key]) throw new Error(`unexpected fetch ${u}`);
		return handlers[key]({ init, body });
	};
	fn.calls = calls;
	fn.of = k => calls.filter(c => (k === "token" ? c.url === TOKEN_URL : c.url.startsWith(BOOTSTRAP_PREFIX)));
	return fn;
}

const tokenBody = (extra = {}) => ({
	access_token: "access-1",
	refresh_token: "refresh-1",
	expires_in: 3600,
	account: { uuid: "acct-1", email_address: "a@example.test" },
	organization: { uuid: "org-1", name: "Org One" },
	...extra,
});

// Drives login: records the authorize URL, then answers via the real callback or a manual paste.
async function runLogin(oauth, mode, { codeSuffix = "" } = {}) {
	const controller = new AbortController();
	let authUrl;
	let info;
	const ctrl = {
		signal: controller.signal,
		onAuth: i => {
			info = i;
			authUrl = new URL(i.url);
		},
		onProgress() {},
		onPrompt: async () => "",
		onManualCodeInput:
			mode === "manual"
				? () =>
						new Promise(resolve => {
							const t = setInterval(() => {
								if (!authUrl) return;
								clearInterval(t);
								const p = authUrl.searchParams;
								resolve(`${p.get("redirect_uri")}?code=MANUAL${codeSuffix}&state=${p.get("state")}`);
							}, 5);
						})
				: undefined,
	};
	const done = oauth.login(ctrl);
	if (mode === "callback") {
		while (!authUrl) await Bun.sleep(5);
		const p = authUrl.searchParams;
		const res = await fetch(`${p.get("redirect_uri")}?code=CB&state=${p.get("state")}`);
		await res.arrayBuffer();
	}
	const grant = await done;
	return { grant, authUrl, info, controller };
}

describe("anthropic native OAuth", () => {
	test("callback login sends native PKCE/client/scopes and keeps full identity without bootstrap", async () => {
		const f = fakeFetch({ token: () => json(tokenBody()) });
		const before = Date.now();
		const { grant, authUrl, info } = await runLogin(createAnthropicOAuth({ fetchImpl: f }), "callback");
		const p = authUrl.searchParams;
		expect(authUrl.origin + authUrl.pathname).toBe("https://claude.ai/oauth/authorize");
		expect(p.get("client_id")).toBe("9d1c250a-e61b-44d9-88ed-5944d1962f5e");
		expect(p.get("redirect_uri")).toBe("http://localhost:54545/callback");
		expect(p.get("response_type")).toBe("code");
		expect(p.get("code")).toBe("true");
		expect(p.get("code_challenge_method")).toBe("S256");
		expect(p.get("scope").split(" ")).toEqual([
			"org:create_api_key",
			"user:profile",
			"user:inference",
			"user:sessions:claude_code",
			"user:mcp_servers",
			"user:file_upload",
		]);
		expect(info.instructions).toContain("browser");
		const [t] = f.of("token");
		expect(t.body).toMatchObject({ grant_type: "authorization_code", code: "CB", state: p.get("state"), redirect_uri: p.get("redirect_uri") });
		expect(createHash("sha256").update(t.body.code_verifier).digest("base64url")).toBe(p.get("code_challenge"));
		expect(grant).toMatchObject({ type: "oauth", access: "access-1", refresh: "refresh-1", accountId: "acct-1", email: "a@example.test", orgId: "org-1", orgName: "Org One" });
		expect(grant.expires).toBeGreaterThanOrEqual(before + 3600_000 - 300_000);
		expect(grant.expires).toBeLessThanOrEqual(Date.now() + 3600_000 - 300_000);
		expect(f.of("bootstrap")).toHaveLength(0);
	});

	test("manual full-callback paste works and bootstrap fills missing identity including org", async () => {
		const f = fakeFetch({
			token: () => json({ access_token: "a2", refresh_token: "r2", expires_in: 100 }),
			bootstrap: () =>
				json({ oauth_account: { account_uuid: "acct-2", account_email: "b@example.test", organization_uuid: "org-2", organization_name: "Org Two" } }),
		});
		const { grant } = await runLogin(createAnthropicOAuth({ fetchImpl: f }), "manual");
		expect(f.of("token")[0].body.code).toBe("MANUAL");
		expect(grant).toMatchObject({ access: "a2", accountId: "acct-2", email: "b@example.test", orgId: "org-2", orgName: "Org Two" });
		const b = f.of("bootstrap")[0];
		expect(b.init.headers.Authorization).toBe("Bearer a2");
		expect(b.init.headers["anthropic-beta"]).toBe("oauth-2025-04-20");
		expect(b.url).toContain("entrypoint=cli");
	});

	test("failed login bootstrap still yields the grant without identity", async () => {
		const f = fakeFetch({
			token: () => json({ access_token: "a3", refresh_token: "r3", expires_in: 100 }),
			bootstrap: () => json({ error: SECRET }, 500),
		});
		const { grant } = await runLogin(createAnthropicOAuth({ fetchImpl: f }), "manual");
		expect(grant.access).toBe("a3");
		expect(grant.accountId).toBeUndefined();
		expect(JSON.stringify(grant)).not.toContain(SECRET);
	});

	test("token exchange failure is a safe fixed error", async () => {
		const f = fakeFetch({ token: () => json({ error: "invalid_grant", error_description: SECRET }, 400) });
		const err = await runLogin(createAnthropicOAuth({ fetchImpl: f }), "callback").catch(e => e);
		expect(err).toBeInstanceOf(Error);
		expect(String(err.message)).not.toContain(SECRET);
	});

	test("malformed token response and missing refresh token are rejected", async () => {
		for (const body of [{ access_token: "x" }, { access_token: "x", expires_in: 10 }]) {
			const f = fakeFetch({ token: () => json(body) });
			await expect(runLogin(createAnthropicOAuth({ fetchImpl: f }), "callback")).rejects.toThrow();
		}
	});

	test("cancelling before the callback rejects and never calls the token endpoint", async () => {
		const f = fakeFetch({ token: () => json(tokenBody()) });
		const controller = new AbortController();
		const oauth = createAnthropicOAuth({ fetchImpl: f });
		let seen = false;
		const done = oauth.login({ signal: controller.signal, onAuth: () => (seen = true), onProgress() {}, onPrompt: async () => "" });
		while (!seen) await Bun.sleep(5);
		controller.abort();
		await expect(done).rejects.toThrow();
		expect(f.calls).toHaveLength(0);
	});

	const stored = {
		type: "oauth",
		access: "old-access",
		refresh: "old-refresh",
		expires: 1,
		accountId: "acct-s",
		email: "s@example.test",
		orgId: "org-s",
		orgName: "Org S",
	};

	test("refresh rotates tokens, uses native headers, and keeps org identity fixed", async () => {
		const f = fakeFetch({
			token: () => json({ access_token: "new-access", refresh_token: "new-refresh", expires_in: 28800, organization: { uuid: "other", name: "Other" } }),
		});
		const input = structuredClone(stored);
		const out = await createAnthropicOAuth({ fetchImpl: f }).refresh(input);
		expect(out).toMatchObject({ access: "new-access", refresh: "new-refresh", accountId: "acct-s", email: "s@example.test", orgId: "org-s", orgName: "Org S" });
		expect(input).toEqual(stored);
		const [t] = f.of("token");
		expect(t.body).toEqual({ grant_type: "refresh_token", client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e", refresh_token: "old-refresh" });
		expect(t.init.headers["anthropic-beta"]).toBe("oauth-2025-04-20");
		expect(t.init.headers["User-Agent"]).toBe("anthropic-sdk-typescript/0.112.1 userOAuthProvider");
		expect(f.of("bootstrap")).toHaveLength(0);
	});

	test("refresh keeps the old refresh token when the response omits it and takes new account identity", async () => {
		const f = fakeFetch({ token: () => json({ access_token: "n", expires_in: 60, account: { uuid: "acct-new", email_address: "n@example.test" } }) });
		const out = await createAnthropicOAuth({ fetchImpl: f }).refresh(structuredClone(stored));
		expect(out).toMatchObject({ refresh: "old-refresh", accountId: "acct-new", email: "n@example.test", orgId: "org-s" });
	});

	test("optional refresh bootstrap failure or cancellation keeps the rotated grant", async () => {
		const partial = { ...stored, email: undefined };
		delete partial.email;
		for (const mode of ["http", "abort"]) {
			const controller = new AbortController();
			const f = fakeFetch({
				token: () => json({ access_token: "rot-a", refresh_token: "rot-r", expires_in: 60 }),
				bootstrap: () => {
					if (mode === "abort") {
						controller.abort();
						throw new DOMException("aborted", "AbortError");
					}
					return json({ error: SECRET }, 503);
				},
			});
			const out = await createAnthropicOAuth({ fetchImpl: f }).refresh(structuredClone(partial), { signal: controller.signal });
			expect(f.of("bootstrap")).toHaveLength(1);
			expect(out).toMatchObject({ access: "rot-a", refresh: "rot-r", accountId: "acct-s", orgId: "org-s" });
			expect(out.email).toBeUndefined();
		}
	});

	test("refresh bootstrap adds account/email but never changes org", async () => {
		const partial = { ...stored };
		delete partial.email;
		const f = fakeFetch({
			token: () => json({ access_token: "b", refresh_token: "br", expires_in: 60 }),
			bootstrap: () => json({ oauth_account: { account_email: "boot@example.test", organization_uuid: "evil", organization_name: "Evil" } }),
		});
		const out = await createAnthropicOAuth({ fetchImpl: f }).refresh(partial);
		expect(out.email).toBe("boot@example.test");
		expect(out.orgId).toBe("org-s");
		expect(out.orgName).toBe("Org S");
	});

	test("refresh errors are safe and a grant without a refresh token is rejected before any request", async () => {
		const f = fakeFetch({ token: () => json({ error: "invalid_grant", error_description: SECRET }, 400) });
		const err = await createAnthropicOAuth({ fetchImpl: f }).refresh(structuredClone(stored)).catch(e => e);
		expect(err).toBeInstanceOf(Error);
		expect(String(err.message)).not.toContain(SECRET);
		const g = fakeFetch({});
		await expect(createAnthropicOAuth({ fetchImpl: g }).refresh({ ...stored, refresh: "" })).rejects.toThrow();
		expect(g.calls).toHaveLength(0);
	});

	test("cancelled refresh before the token response rejects", async () => {
		const controller = new AbortController();
		controller.abort();
		const f = fakeFetch({ token: ({ init }) => (init.signal?.aborted ? Promise.reject(new DOMException("aborted", "AbortError")) : json(tokenBody())) });
		await expect(createAnthropicOAuth({ fetchImpl: f }).refresh(structuredClone(stored), { signal: controller.signal })).rejects.toThrow();
	});
});

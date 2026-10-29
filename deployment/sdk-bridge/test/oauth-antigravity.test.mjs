import { describe, expect, test } from "bun:test";
import { REDIRECT_URI, createAntigravityOAuth } from "../src/oauth/antigravity.mjs";

// Offline fixtures only: every request is answered by a scripted fetch keyed by "METHOD url"; unknown requests fail.
const json = (o, status = 200) => {
	const body = JSON.stringify(o);
	const headers = { "content-type": "application/json" };
	const fn = () => new Response(body, { status, headers: { ...headers } });
	fn.status = status;
	fn.body = body;
	fn.headers = headers;
	return fn;
};
const LOAD = "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
const ONBOARD = "https://daily-cloudcode-pa.googleapis.com/v1internal:onboardUser";
const OP = "https://daily-cloudcode-pa.googleapis.com/v1internal/operations/op1";
const TOKEN = "https://oauth2.googleapis.com/token";
const USERINFO = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";

function toResponse(item, init) {
	if (typeof item === "function") return item(init);
	if (item instanceof Response) return item.clone();
	if (item && typeof item === "object" && "body" in item && "status" in item) {
		return new Response(item.body, { status: item.status, headers: item.headers });
	}
	return item;
}

function script(routes) {
	const calls = [];
	const activeRoutes = {};
	for (const [key, val] of Object.entries(routes)) {
		activeRoutes[key] = Array.isArray(val) ? [...val] : [val];
	}
	const fetchImpl = async (url, init = {}) => {
		const key = `${init.method ?? "GET"} ${url}`;
		calls.push({ key, init });
		const queue = activeRoutes[key];
		if (!queue?.length) throw new Error(`unrouted ${key}`);
		const next = queue.length > 1 ? queue.shift() : queue[0];
		return toResponse(next, init);
	};
	return { fetchImpl, calls };
}

function loginCtrl(extra = {}) {
	const ctrl = {
		signal: new AbortController().signal,
		progress: [],
		onAuth: ({ url }) => {
			ctrl.url = url;
		},
		onProgress: m => ctrl.progress.push(m),
		// Manual fallback: answer with the callback URL carrying the state from the published authorize URL.
		onManualCodeInput: async () => `${REDIRECT_URI}?code=auth-code&state=${new URL(ctrl.url).searchParams.get("state")}`,
		...extra,
	};
	return ctrl;
}

const tokenRoutes = { [`POST ${TOKEN}`]: [json({ access_token: "acc1", refresh_token: "ref1", expires_in: 3600 })], [`GET ${USERINFO}`]: [json({ email: "u@example.test" })] };

describe("antigravity login", () => {
	test("existing project: native authorize params, no onboarding", async () => {
		const { fetchImpl, calls } = script({
			...tokenRoutes,
			[`POST ${LOAD}`]: [json({ currentTier: { id: "standard-tier" }, paidTier: { id: "p" }, cloudaicompanionProject: "proj-1" })],
		});
		const ctrl = loginCtrl();
		const grant = await createAntigravityOAuth({ fetchImpl }).login(ctrl);
		expect(grant).toMatchObject({ type: "oauth", access: "acc1", refresh: "ref1", email: "u@example.test", projectId: "proj-1" });
		const u = new URL(ctrl.url);
		expect(u.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
		expect(u.searchParams.get("code_challenge_method")).toBe("S256");
		expect(u.searchParams.get("access_type")).toBe("offline");
		expect(u.searchParams.get("prompt")).toBe("consent");
		expect(u.searchParams.get("scope")).toContain("auth/aicode");
		const exchange = new URLSearchParams(calls.find(c => c.key === `POST ${TOKEN}`).init.body);
		expect(exchange.get("grant_type")).toBe("authorization_code");
		expect(exchange.get("code")).toBe("auth-code");
		expect(calls.some(c => c.key === `POST ${ONBOARD}`)).toBe(false);
		expect(JSON.parse(calls.find(c => c.key === `POST ${LOAD}`).init.body)).toEqual({ metadata: { ideType: "ANTIGRAVITY" } });
	});

	test("unpaid-tier project triggers the second loadCodeAssist with the project", async () => {
		const { fetchImpl, calls } = script({
			...tokenRoutes,
			[`POST ${LOAD}`]: [json({ currentTier: { id: "t" }, cloudaicompanionProject: "proj-2" })],
		});
		await createAntigravityOAuth({ fetchImpl }).login(loginCtrl());
		const loads = calls.filter(c => c.key === `POST ${LOAD}`).map(c => JSON.parse(c.init.body));
		expect(loads[1]).toEqual({ cloudaicompanionProject: "proj-2", metadata: { ideType: "ANTIGRAVITY" } });
	});

	test("provisioning: onboard free tier, poll operation, then read project", async () => {
		const { fetchImpl, calls } = script({
			...tokenRoutes,
			[`POST ${LOAD}`]: [
				json({ allowedTiers: [{ id: "free-tier" }] }),
				json({ currentTier: { id: "free-tier" }, cloudaicompanionProject: "proj-3" }),
				json({ currentTier: { id: "free-tier" }, paidTier: { id: "f" }, cloudaicompanionProject: "proj-3" }),
			],
			[`POST ${ONBOARD}`]: [json({ name: "operations/op1", done: false })],
			[`GET ${OP}`]: [json({ name: "operations/op1", done: false }), json({ done: true, response: { "@type": "x" } })],
		});
		const sleeps = [];
		const grant = await createAntigravityOAuth({ fetchImpl, sleep: async ms => void sleeps.push(ms) }).login(loginCtrl());
		expect(grant.projectId).toBe("proj-3");
		expect(JSON.parse(calls.find(c => c.key === `POST ${ONBOARD}`).init.body)).toEqual({ tierId: "free-tier", metadata: { ideType: "ANTIGRAVITY" } });
		expect(sleeps).toEqual([1000, 1000]);
		expect(calls.find(c => c.key === `POST ${LOAD}`).init.headers["User-Agent"]).toMatch(/^antigravity\/hub\//);
	});

	test("operation error and malformed operation name fail safely without provider prose", async () => {
		const base = { ...tokenRoutes, [`POST ${LOAD}`]: [json({ allowedTiers: [{ id: "free-tier" }] })] };
		const failing = script({ ...base, [`POST ${ONBOARD}`]: [json({ done: true, error: { code: 7, message: "SECRET-PROSE" } })] });
		const err = await createAntigravityOAuth({ fetchImpl: failing.fetchImpl }).login(loginCtrl()).catch(e => e);
		expect(err.code).toBe("onboard_failed");
		expect(String(err.message)).not.toContain("SECRET-PROSE");
		const traversal = script({ ...base, [`POST ${ONBOARD}`]: [json({ name: "../../evil", done: false })] });
		const err2 = await createAntigravityOAuth({ fetchImpl: traversal.fetchImpl, sleep: async () => {} }).login(loginCtrl()).catch(e => e);
		expect(err2.code).toBe("invalid_response");
	});

	test("onboarding poll timeout", async () => {
		let t = 0;
		const { fetchImpl } = script({
			...tokenRoutes,
			[`POST ${LOAD}`]: [json({ allowedTiers: [{ id: "free-tier" }] })],
			[`POST ${ONBOARD}`]: [json({ name: "operations/op1", done: false })],
			[`GET ${OP}`]: [json({ name: "operations/op1", done: false })],
		});
		const driver = createAntigravityOAuth({ fetchImpl, now: () => t, sleep: async ms => void (t += ms + 30_000) });
		const err = await driver.login(loginCtrl()).catch(e => e);
		expect(err.code).toBe("onboard_timeout");
	});

	test("ineligible free tier and missing project are distinct failures", async () => {
		const inel = script({ ...tokenRoutes, [`POST ${LOAD}`]: [json({ ineligibleTiers: [{ tierId: "free-tier", reasonMessage: "PROSE", validationUrl: "https://accounts.google.com/verify?x=1" }] })] });
		const e1 = await createAntigravityOAuth({ fetchImpl: inel.fetchImpl }).login(loginCtrl()).catch(e => e);
		expect(e1.code).toBe("free_tier_ineligible");
		expect(e1.validationUrl).toBe("https://accounts.google.com/verify?x=1");
		const none = script({ ...tokenRoutes, [`POST ${LOAD}`]: [json({ currentTier: { id: "t" }, paidTier: { id: "p" } })] });
		expect((await createAntigravityOAuth({ fetchImpl: none.fetchImpl }).login(loginCtrl()).catch(e => e)).code).toBe("project_missing");
	});
});

describe("antigravity refresh", () => {
	const stored = { type: "oauth", access: "old", refresh: "old-ref", expires: 1, email: "keep@example.test", projectId: "proj-9", accountId: "a1" };

	test("rotated tokens survive userinfo failure; project/email/metadata retained; no discovery calls", async () => {
		const { fetchImpl, calls } = script({
			[`POST ${TOKEN}`]: [json({ access_token: "new", refresh_token: "new-ref", expires_in: 100 })],
			[`GET ${USERINFO}`]: [json({}, 500)],
		});
		const g = await createAntigravityOAuth({ fetchImpl, now: () => 1_000_000 }).refresh(stored);
		expect(g).toEqual({ ...stored, access: "new", refresh: "new-ref", expires: 1_000_000 + 100_000 - 300_000 });
		expect(calls.map(c => c.key)).toEqual([`POST ${TOKEN}`, `GET ${USERINFO}`]);
		const body = new URLSearchParams(calls[0].init.body);
		expect(body.get("grant_type")).toBe("refresh_token");
		expect(body.get("refresh_token")).toBe("old-ref");
	});

	test("keeps the old refresh token when omitted and adopts a fresh email", async () => {
		const { fetchImpl } = script({
			[`POST ${TOKEN}`]: [json({ access_token: "new", expires_in: 100 })],
			[`GET ${USERINFO}`]: [json({ email: "fresh@example.test" })],
		});
		const g = await createAntigravityOAuth({ fetchImpl }).refresh(stored);
		expect(g.refresh).toBe("old-ref");
		expect(g.email).toBe("fresh@example.test");
		expect(g.projectId).toBe("proj-9");
	});

	test("requires projectId and rejects provider errors without leaking bodies", async () => {
		const driver = createAntigravityOAuth({ fetchImpl: script({ [`POST ${TOKEN}`]: [json({ error: "SECRET-BODY" }, 400)] }).fetchImpl });
		expect((await driver.refresh({ ...stored, projectId: undefined }).catch(e => e)).code).toBe("missing_project");
		const err = await driver.refresh(stored).catch(e => e);
		expect(String(err.message)).not.toContain("SECRET-BODY");
	});

	test("a cancelled signal rejects before any rotation is applied", async () => {
		const ac = new AbortController();
		ac.abort();
		const { fetchImpl, calls } = script({ [`POST ${TOKEN}`]: [json({ access_token: "x", expires_in: 1 })] });
		await expect(createAntigravityOAuth({ fetchImpl }).refresh(stored, { signal: ac.signal })).rejects.toBeDefined();
		expect(calls.length).toBeLessThanOrEqual(1);
	});
});


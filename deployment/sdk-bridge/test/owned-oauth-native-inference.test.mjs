import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAntigravityOAuth } from "../src/oauth/antigravity.mjs";
import { createAuthProviders } from "../src/oauth/index.mjs";
import { createProfiles } from "../src/profiles.mjs";
import { createHandler } from "../src/server.mjs";

// Drives the owned OAuth/auth store (src/oauth) plus the real pinned SDK inference (@oh-my-pi/pi-ai 18.13.3) through the bridge against a local fixture.
// Isolation: owned OAuth and SDK inference both use a fail-closed fetch router that rewrites known provider hosts to the
// loopback fixture and throws on any other URL. The parent must additionally run this file inside a network namespace
// (bwrap --unshare-net), which is the independent boundary.

const TOKEN = "t".repeat(40);
const AUTH = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
const realFetch = globalThis.fetch;
const ROUTED_HOSTS = new Set([
	"api.anthropic.com",
	"auth.openai.com",
	"api.openai.com",
	"chatgpt.com",
	"oauth2.googleapis.com",
	"www.googleapis.com",
	"daily-cloudcode-pa.googleapis.com",
	"antigravity-hub-auto-updater-974169037036.us-central1.run.app",
]);
let origin;
let server;
let handle;
let dataDir;
let sdk;

// Fixture state: codes issued from registered PKCE challenges, current grants, refresh counters, secrets to scan for.
const fx = { n: 0, codes: new Map(), current: new Map(), refreshes: new Map(), secrets: new Set(), auth: new Map(), nativeErrors: new Map(), unrouted: [], calls: [] };

const sha256b64u = s => createHash("sha256").update(s).digest("base64url");

// Sanitized diagnostics only: the native error field with fixture secrets redacted and length bounded.
const safeError = v => {
	let s = typeof v === "string" ? v : JSON.stringify(v ?? null);
	for (const sec of fx.secrets) s = s.split(sec).join("[redacted]");
	return s.slice(0, 300);
};

const b64u = o => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = payload => `${b64u({ alg: "none", typ: "JWT" })}.${b64u(payload)}.sig`;
const json = (o, status = 200) =>
	new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
const sse = (frames, named = false) =>
	new Response(
		frames.map(f => (named ? `event: ${f.type}\n` : "") + `data: ${JSON.stringify(f)}\n\n`).join(""),
		{ headers: { "content-type": "text/event-stream" } },
	);
const parse = text =>
	text.trimStart().startsWith("{") ? JSON.parse(text) : Object.fromEntries(new URLSearchParams(text));

function issue(provider, extra = {}) {
	const n = ++fx.n;
	const access =
		provider === "openai-codex"
			? jwt({ exp: Math.floor(Date.now() / 1000) + 3600, "https://api.openai.com/auth": { chatgpt_account_id: "acct-fixture-1" }, "https://api.openai.com/profile": { email: "codex@fixture.test" } })
			: `${provider === "anthropic" ? "sk-ant-oat01-" : ""}AT-${provider}-${n}`;
	const refresh = `RT-${provider}-${n}`;
	fx.current.set(provider, { access, refresh });
	fx.secrets.add(access).add(refresh);
	return { access_token: access, refresh_token: refresh, expires_in: 3600, token_type: "Bearer", ...extra };
}

function tokenGrant(provider, p, extra = {}) {
	if (p.grant_type === "authorization_code") {
		const g = fx.codes.get(p.code);
		fx.codes.delete(p.code);
		if (!g || g.provider !== provider) return json({ error: "invalid_grant" }, 400);
		if (p.state !== undefined && p.state !== g.state) return json({ error: "state_mismatch" }, 400);
		if (p.redirect_uri !== undefined && p.redirect_uri !== g.redirect) return json({ error: "redirect_mismatch" }, 400);
		if (!p.code_verifier || sha256b64u(p.code_verifier) !== g.challenge) return json({ error: "pkce_mismatch" }, 400);
	} else if (p.grant_type === "refresh_token") {
		if (p.refresh_token !== fx.current.get(provider)?.refresh) return json({ error: "invalid_grant" }, 400);
		fx.refreshes.set(provider, (fx.refreshes.get(provider) ?? 0) + 1);
	} else {
		return json({ error: "unsupported_grant_type" }, 400);
	}
	return json(issue(provider, extra));
}

const ANTHROPIC_SSE = [
	{ type: "message_start", message: { id: "msg_a1", type: "message", role: "assistant", model: "claude-opus-5-5", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 11, output_tokens: 1 } } },
	{ type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "", signature: "" } },
	{ type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "Fixture reasoning" } },
	{ type: "content_block_delta", index: 0, delta: { type: "signature_delta", signature: "SIG-ANTH-1" } },
	{ type: "content_block_stop", index: 0 },
	{ type: "content_block_start", index: 1, content_block: { type: "text", text: "" } },
	{ type: "content_block_delta", index: 1, delta: { type: "text_delta", text: "Anthropic fixture answer" } },
	{ type: "content_block_stop", index: 1 },
	{ type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 7 } },
	{ type: "message_stop" },
];

const CODEX_SSE = [
	{ type: "response.created", response: { id: "resp_c1" } },
	{ type: "response.output_item.added", output_index: 0, item: { type: "reasoning", id: "rs_c1", summary: [] } },
	{ type: "response.reasoning_summary_text.delta", item_id: "rs_c1", output_index: 0, summary_index: 0, delta: "Fixture summary" },
	{ type: "response.output_item.done", output_index: 0, item: { type: "reasoning", id: "rs_c1", summary: [{ type: "summary_text", text: "Fixture summary" }], encrypted_content: "ENC-CODEX-1" } },
	{ type: "response.output_item.added", output_index: 1, item: { type: "message", id: "msg_c1", role: "assistant", status: "in_progress", content: [] } },
	{ type: "response.output_text.delta", item_id: "msg_c1", output_index: 1, content_index: 0, delta: "Codex fixture answer" },
	{ type: "response.output_item.done", output_index: 1, item: { type: "message", id: "msg_c1", role: "assistant", status: "completed", content: [{ type: "output_text", text: "Codex fixture answer" }] } },
	{ type: "response.completed", response: { id: "resp_c1", status: "completed", usage: { input_tokens: 5, output_tokens: 4, total_tokens: 9 } } },
];

// Antigravity thought/tool signatures must be base64 for the SDK to replay them (google-shared.ts L141-156).
const SIG_AG_1 = Buffer.from("fixture-ag-thought-sig-1").toString("base64");
const SIG_AG_2 = Buffer.from("fixture-ag-toolcall-sig-2").toString("base64");
const AG_SSE = [
	{ response: { candidates: [{ content: { role: "model", parts: [{ thought: true, text: "Fixture thought", thoughtSignature: SIG_AG_1 }] } }], responseId: "resp_ag1" } },
	{ response: { candidates: [{ content: { role: "model", parts: [{ text: "Antigravity fixture answer" }] } }] } },
	{ response: { candidates: [{ content: { role: "model", parts: [{ functionCall: { name: "lookup", args: { city: "Oslo" } }, thoughtSignature: SIG_AG_2 }] }, finishReason: "STOP" }], usageMetadata: { promptTokenCount: 8, candidatesTokenCount: 6, totalTokenCount: 14 } } },
];

// Answers each native tool call so the next turn carries a real toolResult, not a synthetic "No result provided".
function toolResultsFor(message) {
	return message.content
		.filter(b => b.type === "toolCall")
		.map(call => ({
			role: "toolResult",
			toolCallId: call.id,
			toolName: call.name,
			content: [{ type: "text", text: "Oslo: 12C fixture result" }],
			isError: false,
			timestamp: Date.now(),
		}));
}

// Keys are hostname + pathname of the ORIGINAL provider URL (carried in x-original-url).
const handlers = {
	"api.anthropic.com/v1/oauth/token": ({ text }) =>
		tokenGrant("anthropic", parse(text), {
			account: { uuid: "acct-anth-uuid", email_address: "anth@fixture.test" },
			organization: { uuid: "org-anth-uuid", name: "Fixture Org" },
		}),
	"api.anthropic.com/api/claude_cli/bootstrap": () => json({}),
	"api.anthropic.com/v1/messages": () => sse(ANTHROPIC_SSE, true),
	"auth.openai.com/oauth/token": ({ text }) => tokenGrant("openai-codex", parse(text)),
	"api.openai.com/profile": () => json({ email: "codex@fixture.test" }),
	"chatgpt.com/backend-api/codex/responses": () => sse(CODEX_SSE, true),
	"oauth2.googleapis.com/token": ({ text }) => tokenGrant("google-antigravity", parse(text)),
	"www.googleapis.com/oauth2/v1/userinfo": () => json({ email: "ag@fixture.test" }),
	"daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist": () => json({ cloudaicompanionProject: "proj-fixture-1" }),
	"daily-cloudcode-pa.googleapis.com/v1internal:onboardUser": () =>
		json({ name: "operations/onboard-1", done: true, response: { "@type": "type.googleapis.com/google.cloud.cloudcode.v1internal.OnboardUserResponse", cloudaicompanionProject: "proj-fixture-1" } }),
	"daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent": () => sse(AG_SSE),
	"antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-arm64-mac.yml": () =>
		new Response("version: 2.26.0\n", { headers: { "content-type": "text/yaml" } }),
};
async function dispatch(req) {
	const orig = new URL(req.headers.get("x-original-url") ?? "http://unknown.invalid/");
	const key = orig.hostname + orig.pathname;
	const text = req.method === "GET" ? "" : await req.text();
	fx.calls.push(`${req.method} ${key}`);
	fx.auth.set(key, req.headers.get("authorization") ?? "");
	const h = handlers[key];
	if (!h) return new Response(`unexpected fixture route ${key}`, { status: 599 });
	return h({ text });
}

// Fail-closed router: known provider hosts go to the fixture; the fixture origin passes; everything else throws.
async function routedFetch(input, init = {}) {
	const req = input instanceof Request ? input : undefined;
	const url = new URL(req ? req.url : String(input));
	const method = init.method ?? req?.method ?? "GET";
	const headers = new Headers(init.headers ?? req?.headers);
	const body =
		init.body !== undefined ? init.body : req && method !== "GET" && method !== "HEAD" ? await req.arrayBuffer() : undefined;
	const opts = { method, headers, body, signal: init.signal ?? req?.signal, redirect: init.redirect ?? "follow" };
	if (url.origin === origin) return realFetch(url, opts);
	if (!ROUTED_HOSTS.has(url.hostname)) {
		fx.unrouted.push(`${url.origin}${url.pathname}`); // no query or fragment: those may carry secrets
		throw new Error(`offline fixture: blocked ${url.origin}${url.pathname}`);
	}
	headers.set("x-original-url", url.toString());
	return realFetch(new URL(url.pathname + url.search, origin), opts);
}

function bridge(method, path, body) {
	return handle(
		new Request(`http://127.0.0.1:8788${path}`, {
			method,
			headers: AUTH,
			body: body === undefined ? undefined : JSON.stringify(body),
		}),
	);
}

async function bridgeJson(method, path, body) {
	const res = await bridge(method, path, body);
	if (res.status !== 200) throw new Error(`bridge ${method} ${path} -> ${res.status}: ${await res.text()}`);
	return res.json();
}

async function waitFor(fn, ms = 20000) {
	const end = Date.now() + ms;
	for (;;) {
		const v = await fn();
		if (v) return v;
		if (Date.now() > end) throw new Error("waitFor timeout");
		await Bun.sleep(50);
	}
}

// Captures the PKCE/state from the actual authorize URL the SDK produced.
function register(provider, authorizationUrl) {
	const u = new URL(authorizationUrl);
	const state = u.searchParams.get("state");
	const challenge = u.searchParams.get("code_challenge");
	const redirect = u.searchParams.get("redirect_uri");
	if (!state || !challenge || !redirect || u.searchParams.get("code_challenge_method") !== "S256") {
		throw new Error(`authorize URL lacks S256 PKCE/state/redirect for ${provider}`);
	}
	return { provider, state, challenge, redirect };
}

// Simulates the human's browser consent: the local callback receives a code bound to the registered challenge.
async function completeBrowserCallback(reg) {
	const code = `code-${reg.provider}-${++fx.n}`;
	fx.codes.set(code, reg);
	const cb = new URL(reg.redirect);
	cb.searchParams.set("code", code);
	cb.searchParams.set("state", reg.state);
	return realFetch(cb, { redirect: "manual" }).then(r => r.arrayBuffer());
}

async function login(id, provider) {
	const { session_id: sid } = await bridgeJson("POST", `/v1/profiles/${id}/login/start`, { provider });
	const pendingView = await waitFor(async () => {
		const v = await bridgeJson("GET", `/v1/profiles/${id}/login/${sid}`);
		return v.authorization_url ? v : null;
	});
	const reg = register(provider, pendingView.authorization_url);
	const cb = completeBrowserCallback(reg);
	const done = await waitFor(async () => {
		const v = await bridgeJson("GET", `/v1/profiles/${id}/login/${sid}`);
		return v.status === "pending" ? null : v;
	});
	await cb;
	return done;
}

async function infer(id, provider, model, messages) {
	const res = await bridge("POST", `/v1/profiles/${id}/infer`, {
		provider,
		model,
		context: { messages },
		// google-antigravity/gemini-3.1-pro supports only low|high (SDK catalog); other providers keep medium.
		options: { reasoning: provider === "google-antigravity" ? "high" : "medium" },
	});
	if (res.status !== 200)
		throw new Error(
			`infer ${provider} -> ${res.status}: ${await res.text()} native=${fx.nativeErrors.get(provider) ?? "none"} unrouted=${fx.unrouted.slice(-3).join(",") || "none"} calls=${fx.calls.slice(-3).join(",") || "none"}`,
		);
	expect(res.headers.get("content-type")).toBe("application/x-ndjson");
	const text = await res.text();
	return { text, lines: text.split("\n").filter(Boolean).map(l => JSON.parse(l)) };
}

function terminalDiag(provider, res) {
	const last = res.lines.at(-1) ?? {};
	const errMsg = last.error?.errorMessage ?? last.message?.errorMessage ?? last.errorMessage;
	const detail = safeError(errMsg ? { errorMessage: errMsg, detail: last.error ?? last } : (last.error ?? last.message ?? last));
	return `infer ${provider} terminal=${last.type} stopReason=${last.message?.stopReason ?? last.stopReason ?? "none"} detail=${detail} calls=${fx.calls.slice(-3).join(",") || "none"} unrouted=${fx.unrouted.slice(-3).join(",") || "none"}`;
}

const textOf = m => m.content.filter(b => b.type === "text").map(b => b.text).join("");

const CASES = [
	{
		name: "anthropic",
		id: 1,
		route: "api.anthropic.com/v1/messages",
		provider: "anthropic",
		model: "claude-opus-5-5",
		email: "anth@fixture.test",
		check(message) {
			expect(textOf(message)).toContain("Anthropic fixture answer");
			expect(JSON.stringify(message)).toContain("SIG-ANTH-1");
		},
		replay: ["SIG-ANTH-1"],
	},
	{
		name: "openai-codex",
		id: 2,
		route: "chatgpt.com/backend-api/codex/responses",
		provider: "openai-codex",
		model: "gpt-5.6-luna",
		email: "codex@fixture.test",
		check(message) {
			expect(textOf(message)).toContain("Codex fixture answer");
			expect(JSON.stringify(message)).toContain("ENC-CODEX-1");
			expect(JSON.stringify(message)).toContain("rs_c1");
		},
		replay: ["ENC-CODEX-1"],
		// filterInput (openai-codex/request-transformer.ts) strips top-level input ids under store:false.
		wireCheck(body) {
			const item = body.input.find(i => i.type === "reasoning");
			expect(item).toBeDefined();
			expect(item.encrypted_content).toBe("ENC-CODEX-1");
			expect(item).not.toHaveProperty("id");
			expect(item.summary).toEqual([{ type: "summary_text", text: "Fixture summary" }]);
		},
	},
	{
		name: "google-antigravity",
		id: 3,
		route: "daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent",
		provider: "google-antigravity",
		model: "gemini-3.1-pro",
		email: "ag@fixture.test",
		check(message) {
			expect(textOf(message)).toContain("Antigravity fixture answer");
			const call = message.content.find(b => b.type === "toolCall");
			expect(call?.name).toBe("lookup");
			expect(call?.arguments).toEqual({ city: "Oslo" });
			expect(JSON.stringify(message)).toContain(SIG_AG_1);
			expect(JSON.stringify(message)).toContain(SIG_AG_2);
		},
		replay: [SIG_AG_1, SIG_AG_2],
	},
];

beforeAll(async () => {
	// Force Codex onto SSE (its WebSocket transport is otherwise preferred for gpt-5.6-luna).
	process.env.PI_CODEX_WEBSOCKET = "0";
	dataDir = mkdtempSync(join(tmpdir(), "offline-sdk-"));
	server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: dispatch });
	origin = `http://127.0.0.1:${server.port}`;
	globalThis.fetch = routedFetch;
	const real = await import("../src/sdk.mjs");
	const streamSimple = (model, context, options) => {
		try {
			return real.streamSimple(model, context, { ...options, fetch: routedFetch });
		} catch (err) {
			fx.nativeErrors.set(model.provider, safeError(err?.message ?? err));
			throw err;
		}
	};
	handle = createHandler({
		token: TOKEN,
		profiles: createProfiles({
			dataDir,
			sdk: { ...real, streamSimple },
			authProviders: {
				...createAuthProviders({ fetchImpl: routedFetch }),
				"google-antigravity": createAntigravityOAuth({ fetchImpl: routedFetch, now: () => Date.now() }),
			},
		}),
	});
});

afterAll(() => {
	globalThis.fetch = realFetch;
	server?.stop(true);
	rmSync(dataDir, { recursive: true, force: true });
});

describe("offline ownedOAuth+nativeSDKinference, and native history", () => {
	for (const c of CASES) {
		test(`${c.name}: real OAuth/PKCE login, native stream, opaque replay`, async () => {
			const done = await login(c.id, c.provider);
			if (done.status !== "complete")
				throw new Error(
					`login ${c.provider} status=${done.status} keys=${Object.keys(done).join(",")} error=${safeError(done.error)} native=${fx.nativeErrors.get(c.provider) ?? "none"} unrouted=${fx.unrouted.slice(-3).join(",") || "none"} calls=${fx.calls.slice(-3).join(",") || "none"}`,
				);
			expect(done.email).toBe(c.email);
			const st = await bridgeJson("GET", `/v1/profiles/${c.id}/status?provider=${c.provider}`);
			if (st.connected !== true)
				throw new Error(`status ${c.provider} connected=${st.connected} expires_in_ms=${st.expires_at === undefined ? "none" : Date.parse(st.expires_at) - Date.now()}`);

			const t1 = await infer(c.id, c.provider, c.model, [{ role: "user", content: "hi" }]);
			if (t1.lines.at(-1).type !== "done") throw new Error(terminalDiag(c.provider, t1));
			expect(t1.lines.some(l => l.type === "bridge_error" || l.type === "error")).toBe(false);
			for (const s of fx.secrets) expect(t1.text).not.toContain(s);
			c.check(t1.lines.at(-1).message);
			const first = t1.lines.at(-1).message;

			const t2 = await infer(c.id, c.provider, c.model, [
				{ role: "user", content: "hi" },
				first,
				...toolResultsFor(first),
				{ role: "user", content: "again" },
			]);
			const wire = t2.lines.find(l => l.type === "wire_request");
			expect(wire).toBeDefined();
			const body = JSON.stringify(wire.body);
			for (const token of c.replay) expect(body).toContain(token);
			if (c.wireCheck) c.wireCheck(wire.body);
			expect(t2.lines.at(-1).type).toBe("done");

			// Deterministic expired grant: advance the clock past expires_in so the SDK must refresh against the fixture.
			const before = fx.current.get(c.provider);
			const refreshesBefore = fx.refreshes.get(c.provider) ?? 0;
			const realNow = Date.now;
			let t3;
			Date.now = () => realNow() + 3601_000;
			try {
				t3 = await infer(c.id, c.provider, c.model, [
					{ role: "user", content: "hi" },
					first,
					...toolResultsFor(first),
					{ role: "user", content: "after refresh" },
				]);
			} finally {
				Date.now = realNow;
			}
			const after = fx.current.get(c.provider);
			expect(fx.refreshes.get(c.provider) ?? 0).toBeGreaterThan(refreshesBefore);
			expect(after.refresh).not.toBe(before.refresh);
			expect(after.access).not.toBe(before.access);
			if (t3.lines.at(-1).type !== "done") throw new Error(terminalDiag(c.provider, t3));
			expect(t3.lines.some(l => l.type === "bridge_error" || l.type === "error")).toBe(false);
			for (const s of fx.secrets) expect(t3.text).not.toContain(s);
			c.check(t3.lines.at(-1).message);
			expect(fx.auth.get(c.route)).toContain(after.access);
			expect(fx.auth.get(c.route)).not.toContain(before.access);
		}, 120000);
	}
});

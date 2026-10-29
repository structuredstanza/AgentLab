import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { OAuthError, abortableDelay, authorizationCode, createPkce, decodeJwt, requestJSON } from "../src/oauth/common.mjs";

const STATE = "state-123";
const AUTH_URL = "https://auth.example.invalid/authorize";

async function freePort() {
	const s = createServer();
	await new Promise(r => s.listen(0, "127.0.0.1", r));
	const { port } = s.address();
	await new Promise(r => s.close(r));
	return port;
}

const never = signal => new Promise((_, reject) => signal?.addEventListener("abort", () => reject(new Error("aborted"))));
const portFree = async (port, host = "127.0.0.1") => {
	const s = createServer();
	const ok = await new Promise(r => {
		s.once("error", () => r(false));
		s.listen(port, host, () => r(true));
	});
	if (ok) await new Promise(r => s.close(r));
	return ok;
};
const fail = p => p.then(() => null, e => e);

async function setup() {
	const port = await freePort();
	return { port, redirectUri: `http://127.0.0.1:${port}/callback`, cb: (q, init) => fetch(`http://127.0.0.1:${port}/callback${q}`, init) };
}

describe("authorizationCode callback", () => {
	test("browser callback wins the race and stops manual input", async () => {
		const { redirectUri, cb } = await setup();
		let manualSignal;
		let callbackTask;
		const { code, redirectUri: actualUri } = await authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			ctrl: {
				onAuth: () => {
					callbackTask = cb(`?code=abc&state=${STATE}`);
				},
				onManualCodeInput: s => ((manualSignal = s), never(s)),
			},
		});
		await callbackTask;
		expect(code).toBe("abc");
		expect(actualUri).toBe(redirectUri);
		expect(manualSignal.aborted).toBe(true);
	});

	test("invalid attempts do not consume the pending login", async () => {
		const { port, redirectUri, cb } = await setup();
		const statuses = [];
		let callbackTask;
		const { code } = await authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			ctrl: {
				onAuth: () => {
					callbackTask = (async () => {
						statuses.push((await cb(`?code=x&state=wrong`)).status);
						statuses.push((await cb(`?state=${STATE}`)).status);
						statuses.push((await cb(`?code=x&state=${STATE}`, { method: "POST" })).status);
						statuses.push((await fetch(`http://127.0.0.1:${port}/other?code=x&state=${STATE}`)).status);
						statuses.push((await cb(`?code=good&state=${STATE}`)).status);
					})();
				},
			},
		});
		await callbackTask;
		expect(code).toBe("good");
		expect(statuses.slice(0, 4).every(s => s >= 400)).toBe(true);
		expect(statuses[4]).toBe(200);
		expect(await portFree(port)).toBe(true);
	});

	test("provider denial with matching state rejects", async () => {
		const { redirectUri, cb } = await setup();
		let callbackTask;
		const err = await fail(
			authorizationCode({
				url: AUTH_URL,
				redirectUri,
				state: STATE,
				ctrl: {
					onAuth: () => {
						callbackTask = cb(`?error=access_denied&state=${STATE}`);
					},
				},
			}),
		);
		await callbackTask;
		expect(err).toBeInstanceOf(OAuthError);
	});

	test("binds before publishing the auth URL", async () => {
		const { port, redirectUri } = await setup();
		let boundAtAuth;
		const p = authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			ctrl: {
				onAuth: async () => {
					boundAtAuth = !(await portFree(port));
				},
				onManualCodeInput: () => Promise.resolve(`${redirectUri}?code=m&state=${STATE}`),
			},
		});
		expect((await p).code).toBe("m");
		expect(boundAtAuth).toBe(true);
	});
});

describe("authorizationCode manual input", () => {
	test("rejected pastes are retried until a valid callback URL arrives", async () => {
		const { redirectUri } = await setup();
		const inputs = [
			"",
			"not a url",
			`${redirectUri}?code=a&state=wrong`,
			`${redirectUri}/other?code=a&state=${STATE}`,
			`http://evil.example.invalid/callback?code=a&state=${STATE}`,
			`${redirectUri}?state=${STATE}`,
			`${redirectUri}?code=ok&state=${STATE}`,
		];
		let asked = 0;
		const { code } = await authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			ctrl: { onManualCodeInput: () => Promise.resolve(inputs[asked++]) },
		});
		expect(code).toBe("ok");
		expect(asked).toBe(inputs.length);
	});

	test("code#state needs code-state format and matching state", async () => {
		const { redirectUri } = await setup();
		let asked = 0;
		const urlMode = authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			timeoutMs: 100,
			ctrl: { onManualCodeInput: () => (asked++ ? never() : Promise.resolve(`raw#${STATE}`)) },
		});
		expect((await fail(urlMode)).code).toBe("timeout");

		const inputs = ["raw", "raw#wrong", `raw#${STATE}`];
		let i = 0;
		const { code } = await authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			manualFormat: "code-state",
			ctrl: { onManualCodeInput: () => Promise.resolve(inputs[i++]) },
		});
		expect(code).toBe("raw");
		expect(i).toBe(3);
	});

	test("manualOnBindError=false fails fast without publishing the auth URL", async () => {
		const blocker = createServer();
		await new Promise(r => blocker.listen(0, "127.0.0.1", r));
		const redirectUri = `http://127.0.0.1:${blocker.address().port}/callback`;
		let published = false;
		try {
			const err = await fail(
				authorizationCode({
					url: AUTH_URL,
					redirectUri,
					state: STATE,
					manualOnBindError: false,
					ctrl: { onAuth: () => (published = true), onManualCodeInput: () => Promise.resolve(`${redirectUri}?code=m&state=${STATE}`) },
				}),
			);
			expect(err.code).toBe("callback_unavailable");
			expect(published).toBe(false);
		} finally {
			blocker.close();
		}
	});


	test("bind failure falls back to manual input; without it the login fails", async () => {
		const blocker = createServer();
		await new Promise(r => blocker.listen(0, "127.0.0.1", r));
		const redirectUri = `http://127.0.0.1:${blocker.address().port}/callback`;
		try {
			const { code } = await authorizationCode({
				url: AUTH_URL,
				redirectUri,
				state: STATE,
				ctrl: { onManualCodeInput: () => Promise.resolve(`${redirectUri}?code=m&state=${STATE}`) },
			});
			expect(code).toBe("m");
			const err = await fail(authorizationCode({ url: AUTH_URL, redirectUri, state: STATE, ctrl: {} }));
			expect(err.code).toBe("callback_unavailable");
		} finally {
			blocker.close();
		}
	});
});

describe("authorizationCode validation and lifecycle", () => {
	test("rejects non-loopback or non-http redirect URIs and missing state", async () => {
		for (const redirectUri of ["https://127.0.0.1:1234/cb", "http://evil.example.invalid:1234/cb", "nonsense"]) {
			expect(await fail(authorizationCode({ url: AUTH_URL, redirectUri, state: STATE, ctrl: {} }))).toBeInstanceOf(OAuthError);
		}
		const { redirectUri } = await setup();
		expect(await fail(authorizationCode({ url: AUTH_URL, redirectUri, state: "", ctrl: {} }))).toBeInstanceOf(OAuthError);
	});

	test("abort and timeout reject and release the listener", async () => {
		const a = await setup();
		const ac = new AbortController();
		const aborted = fail(
			authorizationCode({ url: AUTH_URL, redirectUri: a.redirectUri, state: STATE, ctrl: { signal: ac.signal, onAuth: () => queueMicrotask(() => ac.abort()) } }),
		);
		expect((await aborted).code).toBe("cancelled");
		expect(await portFree(a.port)).toBe(true);

		const t = await setup();
		const err = await fail(authorizationCode({ url: AUTH_URL, redirectUri: t.redirectUri, state: STATE, timeoutMs: 50, ctrl: {} }));
		expect(err.code).toBe("timeout");
		expect(await portFree(t.port)).toBe(true);

		const pre = new AbortController();
		pre.abort();
		expect((await fail(authorizationCode({ url: AUTH_URL, redirectUri: t.redirectUri, state: STATE, ctrl: { signal: pre.signal } }))).code).toBe("cancelled");
	});

	test("a failing manual prompt does not kill a live callback listener", async () => {
		const { redirectUri, cb } = await setup();
		let callbackTask;
		const { code } = await authorizationCode({
			url: AUTH_URL,
			redirectUri,
			state: STATE,
			ctrl: {
				onManualCodeInput: () => Promise.reject(new Error("superseded")),
				onAuth: () => {
					setTimeout(() => {
						callbackTask = cb(`?code=late&state=${STATE}`);
					}, 20);
				},
			},
		});
		await callbackTask;
		expect(code).toBe("late");
	});
});
describe("authorizationCode dual-stack and random port fallback", () => {
	test("occupied IPv6 localhost port fails and tears down IPv4 listener", async () => {
		const blocker = createServer();
		await new Promise(r => blocker.listen(0, "::1", r));
		const port = blocker.address().port;
		const redirectUri = `http://localhost:${port}/callback`;
		try {
			const err = await fail(
				authorizationCode({
					url: AUTH_URL,
					redirectUri,
					state: STATE,
					manualOnBindError: false,
					allowRandomPort: false,
					ctrl: {},
				}),
			);
			expect(err.code).toBe("callback_unavailable");
			expect(await portFree(port, "127.0.0.1")).toBe(true);
		} finally {
			blocker.close();
		}
	});

	test("occupied preferred port with allowRandomPort binds port 0 with consistent redirect URIs", async () => {
		const blocker = createServer();
		await new Promise(r => blocker.listen(0, "127.0.0.1", r));
		const port = blocker.address().port;
		const preferredUri = `http://localhost:${port}/callback`;
		let publishedUrl;
		let callbackTask;
		try {
			const res = await authorizationCode({
				buildUrl: uri => `https://auth.example.invalid/authorize?redirect_uri=${encodeURIComponent(uri)}&state=${STATE}`,
				redirectUri: preferredUri,
				state: STATE,
				allowRandomPort: true,
				ctrl: {
					onAuth: ({ url }) => {
						publishedUrl = url;
						const actualUri = new URL(url).searchParams.get("redirect_uri");
						callbackTask = fetch(`${actualUri}?code=ephemeral&state=${STATE}`);
					},
				},
			});
			await callbackTask;
			expect(res.code).toBe("ephemeral");
			const publishedRedirect = new URL(publishedUrl).searchParams.get("redirect_uri");
			expect(res.redirectUri).toBe(publishedRedirect);
			expect(res.redirectUri).not.toBe(preferredUri);
			const boundPort = Number(new URL(res.redirectUri).port);
			expect(await portFree(boundPort, "127.0.0.1")).toBe(true);
		} finally {
			blocker.close();
		}
	});

	test("cancellation cleans up all dual-stack localhost listeners", async () => {
		const port = await freePort();
		const redirectUri = `http://localhost:${port}/callback`;
		const ac = new AbortController();
		let published = false;
		const aborted = fail(
			authorizationCode({
				url: AUTH_URL,
				redirectUri,
				state: STATE,
				ctrl: {
					signal: ac.signal,
					onAuth: () => {
						published = true;
						ac.abort();
					},
				},
			}),
		);
		expect((await aborted).code).toBe("cancelled");
		expect(published).toBe(true);
		expect(await portFree(port, "127.0.0.1")).toBe(true);
		expect(await portFree(port, "::1")).toBe(true);
	});
});

describe("requestJSON", () => {
	const json = (body, init) => () => Promise.resolve(new Response(body, init));

	test("parses JSON responses", async () => {
		expect(await requestJSON(json('{"a":1}'), "https://x.invalid", {})).toEqual({ a: 1 });
	});

	test("http errors expose status only, not the body", async () => {
		const err = await fail(requestJSON(json("secret-token-body", { status: 401 }), "https://x.invalid", {}));
		expect(err).toMatchObject({ code: "http_error", status: 401 });
		expect(JSON.stringify(err)).not.toContain("secret");
		expect(err.message).not.toContain("secret");
	});

	test("oversized and malformed bodies are rejected", async () => {
		const big = await fail(requestJSON(json(JSON.stringify({ a: "x".repeat(200) })), "https://x.invalid", {}, { maxBytes: 100 }));
		expect(big.code).toBe("response_too_large");
		const streamed = () =>
			Promise.resolve(new Response(new ReadableStream({ pull: c => c.enqueue(new Uint8Array(64)) })));
		expect((await fail(requestJSON(streamed, "https://x.invalid", {}, { maxBytes: 100 }))).code).toBe("response_too_large");
		expect((await fail(requestJSON(json("<html>"), "https://x.invalid", {}))).code).toBe("invalid_response");
	});

	test("timeout and caller cancel are distinct, even if fetch ignores the signal", async () => {
		const hang = () => new Promise(() => {});
		expect((await fail(requestJSON(hang, "https://x.invalid", {}, { timeoutMs: 20 }))).code).toBe("timeout");
		const ac = new AbortController();
		const p = fail(requestJSON(hang, "https://x.invalid", {}, { signal: ac.signal }));
		ac.abort();
		expect((await p).code).toBe("cancelled");
	});

	test("network failures are generic", async () => {
		const err = await fail(requestJSON(() => Promise.reject(new Error("tok_secret")), "https://x.invalid", {}));
		expect(err.code).toBe("network_error");
		expect(err.message).not.toContain("secret");
	});
	test("declared oversized body cancels stream before throwing", async () => {
		let cancelled = false;
		const stream = new ReadableStream({
			cancel() {
				cancelled = true;
			},
		});
		const res = () => Promise.resolve(new Response(stream, { headers: { "content-length": "200" } }));
		const err = await fail(requestJSON(res, "https://x.invalid", {}, { maxBytes: 100 }));
		expect(err.code).toBe("response_too_large");
		expect(cancelled).toBe(true);
	});

	test("stream read failure is sanitized to network_error", async () => {
		const broken = () =>
			Promise.resolve(
				new Response(
					new ReadableStream({
						start(controller) {
							controller.error(new Error("secret_stream_failure"));
						},
					}),
				),
			);
		const err = await fail(requestJSON(broken, "https://x.invalid", {}));
		expect(err.code).toBe("network_error");
		expect(err.message).not.toContain("secret_stream_failure");
	});
});

describe("helpers", () => {
	test("PKCE challenge is the S256 of the verifier", () => {
		const { verifier, challenge, state } = createPkce();
		expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
		expect(state).not.toBe(createPkce().state);
	});

	test("decodeJwt returns payload or null", () => {
		const payload = Buffer.from(JSON.stringify({ sub: "u" })).toString("base64url");
		expect(decodeJwt(`h.${payload}.s`)).toEqual({ sub: "u" });
		expect(decodeJwt("garbage")).toBeNull();
		expect(decodeJwt("a.!!.c")).toBeNull();
	});

	test("abortableDelay resolves or cancels", async () => {
		await abortableDelay(5);
		const ac = new AbortController();
		const p = fail(abortableDelay(10_000, ac.signal));
		ac.abort();
		expect((await p).code).toBe("cancelled");
	});
});

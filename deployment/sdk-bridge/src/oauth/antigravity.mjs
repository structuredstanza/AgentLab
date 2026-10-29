// Owned port of the pinned SDK 18.13.3 google-antigravity login/refresh (catalog auth/google-antigravity.kdl,
// registry/oauth/google-antigravity.ts, engine/oauth-code.ts, engine/refresh.ts, engine/common.ts,
// registry/oauth/index.ts getOAuthApiKey, cat wire/gemini-headers.ts). Native public client; no ARTEX branding.
import { OAuthError, abortableDelay, authorizationCode, createPkce, requestJSON } from "./common.mjs";

const CLIENT_ID = Buffer.from(
	"MTA3MTAwNjA2MDU5MS10bWhzc2luMmgyMWxjcmUyMzV2dG9sb2poNGc0MDNlcC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbQ==",
	"base64",
).toString();
const CLIENT_SECRET = Buffer.from("R09DU1BYLUs1OEZXUjQ4NkxkTEoxbUxCOHNYQzR6NnFEQWY=", "base64").toString();
const AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
export const REDIRECT_URI = "http://127.0.0.1:51121/oauth-callback";
const SCOPES = [
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/cclog",
	"https://www.googleapis.com/auth/experimentsandconfigs",
	"https://www.googleapis.com/auth/aicode",
];
const ENDPOINT = "https://daily-cloudcode-pa.googleapis.com";
const LOAD_URL = `${ENDPOINT}/v1internal:loadCodeAssist`;
const ONBOARD_URL = `${ENDPOINT}/v1internal:onboardUser`;
const OPERATIONS_URL = `${ENDPOINT}/v1internal`;
const FREE_TIER_ID = "free-tier";
const METADATA = Object.freeze({ ideType: "ANTIGRAVITY" });
const EXPIRY_SKEW_MS = 300_000;
const ONBOARD_TIMEOUT_MS = 30_000;
const ONBOARD_POLL_MS = 1_000;
const REQUEST_TIMEOUT_MS = 30_000;
// Pinned native client identity (SDK DEFAULT_ANTIGRAVITY_VERSION); the live manifest lookup is deliberately not ported.
const BUILDS = { darwin: ["darwin", "arm64"], linux: ["linux", "amd64"], win32: ["windows", "amd64"] };

function userAgent() {
	const [os, arch] = BUILDS[process.platform] ?? BUILDS.linux;
	return `antigravity/hub/2.26.0 (aidev_client; os_type=${os}; arch=${arch}; cl=1005016104)`;
}

const isObj = v => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = v => typeof v === "string";
const present = v => v !== undefined && v !== null;
const bad = () => new OAuthError("invalid_response");

function parseLoad(p) {
	if (!isObj(p)) throw bad();
	for (const k of ["currentTier", "paidTier"]) if (present(p[k]) && !isObj(p[k])) throw bad();
	if (present(p.allowedTiers) && !Array.isArray(p.allowedTiers)) throw bad();
	if (present(p.ineligibleTiers) && !Array.isArray(p.ineligibleTiers)) throw bad();
	if (present(p.cloudaicompanionProject) && !isStr(p.cloudaicompanionProject)) throw bad();
	return p;
}

function parseOperation(p) {
	if (!isObj(p)) throw bad();
	if (present(p.name) && !isStr(p.name)) throw bad();
	if (present(p.done) && typeof p.done !== "boolean") throw bad();
	if (present(p.error) && !isObj(p.error)) throw bad();
	if (present(p.response) && !(isObj(p.response) && isStr(p.response["@type"]))) throw bad();
	return p;
}

const projectOf = p => (p.cloudaicompanionProject ? p.cloudaicompanionProject : undefined);

function assertFreeTierEligible(p) {
	if (p.allowedTiers?.some(t => t?.id === FREE_TIER_ID)) return;
	const tier = p.ineligibleTiers?.find(t => t?.tierId === FREE_TIER_ID && t.reasonMessage);
	if (!tier) return;
	// Provider prose is not forwarded; only a Google https validation URL is exposed for the UI.
	const error = new OAuthError("free_tier_ineligible");
	try {
		const u = new URL(tier.validationUrl);
		if (u.protocol === "https:" && /(^|\.)google\.com$/.test(u.hostname)) error.validationUrl = u.href;
	} catch {}
	throw error;
}

/** Raised cancellation must stay distinguishable from provider failures. */
function rethrowCancel(error, signal) {
	if (signal?.aborted) throw error;
}

export function createAntigravityOAuth({ fetchImpl = globalThis.fetch, now = Date.now, sleep = abortableDelay } = {}) {
	const cloud = (url, method, headers, body, signal, timeoutMs = REQUEST_TIMEOUT_MS) =>
		requestJSON(fetchImpl, url, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, { signal, timeoutMs });

	async function loadCodeAssist(headers, signal) {
		let payload = parseLoad(await cloud(LOAD_URL, "POST", headers, { metadata: METADATA }, signal));
		const project = projectOf(payload);
		if (!present(payload.paidTier) && project) {
			payload = parseLoad(
				await cloud(LOAD_URL, "POST", headers, { cloudaicompanionProject: project, metadata: METADATA }, signal),
			);
		}
		return payload;
	}

	async function onboardUser(headers, signal) {
		const deadline = now() + ONBOARD_TIMEOUT_MS;
		const remaining = () => {
			const left = deadline - now();
			if (left > 0) return left;
			throw new OAuthError("onboard_timeout");
		};
		let op = parseOperation(
			await cloud(ONBOARD_URL, "POST", headers, { tierId: FREE_TIER_ID, metadata: METADATA }, signal, remaining()),
		);
		for (;;) {
			if (op.done === true) {
				if (present(op.error)) throw new OAuthError("onboard_failed");
				if (!present(op.response)) throw bad();
				return;
			}
			await sleep(Math.min(ONBOARD_POLL_MS, remaining()), signal);
			if (signal?.aborted) throw new OAuthError("cancelled");
			// The operation name is provider-supplied and becomes a URL path: accept only a plain resource path.
			if (!op.name || !/^[A-Za-z0-9_\-./]+$/.test(op.name) || op.name.split("/").includes("..")) throw bad();
			op = parseOperation(await cloud(`${OPERATIONS_URL}/${op.name}`, "GET", headers, undefined, signal, remaining()));
		}
	}

	async function discoverProject(access, ctrl) {
		const signal = ctrl.signal;
		const headers = {
			Authorization: `Bearer ${access}`,
			"Content-Type": "application/json",
			"User-Agent": userAgent(),
			"Accept-Encoding": "gzip",
		};
		try {
			ctrl.onProgress?.("Checking Cloud Code Assist account status...");
			const initial = await loadCodeAssist(headers, signal);
			assertFreeTierEligible(initial);
			if (!present(initial.currentTier)) {
				ctrl.onProgress?.("Provisioning the Antigravity free tier...");
				await onboardUser(headers, signal);
			}
			ctrl.onProgress?.("Refreshing Cloud Code Assist project...");
			const project = projectOf(await loadCodeAssist(headers, signal));
			if (project) return project;
			throw new OAuthError("project_missing");
		} catch (error) {
			rethrowCancel(error, signal);
			throw error instanceof OAuthError ? error : new OAuthError("discovery_failed");
		}
	}

	async function token(params, signal) {
		const body = await requestJSON(
			fetchImpl,
			TOKEN_URL,
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams(params).toString(),
			},
			{ signal, timeoutMs: REQUEST_TIMEOUT_MS },
		);
		if (!isObj(body) || !isStr(body.access_token) || !body.access_token) throw new OAuthError("invalid_token_response");
		if (typeof body.expires_in !== "number" || !Number.isFinite(body.expires_in)) throw new OAuthError("invalid_token_response");
		return {
			access: body.access_token,
			refresh: isStr(body.refresh_token) ? body.refresh_token : "",
			expires: now() + body.expires_in * 1000 - EXPIRY_SKEW_MS,
		};
	}

	// Userinfo failures (including cancellation after the token response) must never discard a rotated grant.
	async function userEmail(access, signal) {
		try {
			const body = await requestJSON(
				fetchImpl,
				USERINFO_URL,
				{ headers: { Authorization: `Bearer ${access}` } },
				{ signal, timeoutMs: REQUEST_TIMEOUT_MS },
			);
			return isObj(body) && isStr(body.email) && body.email ? body.email : undefined;
		} catch {
			return undefined;
		}
	}

	return {
		async login(ctrl) {
			const signal = ctrl.signal;
			const pkce = createPkce();
			const buildAuthUrl = redirectUri => {
				const params = new URLSearchParams({
					client_id: CLIENT_ID,
					response_type: "code",
					redirect_uri: redirectUri,
					scope: SCOPES.join(" "),
					code_challenge: pkce.challenge,
					code_challenge_method: "S256",
					state: pkce.state,
					access_type: "offline",
					prompt: "consent",
				});
				return `${AUTHORIZE_URL}?${params}`;
			};
			const { code, redirectUri: actualRedirectUri } = await authorizationCode({
				buildUrl: buildAuthUrl,
				redirectUri: REDIRECT_URI,
				state: pkce.state,
				ctrl,
				manualFormat: "code-state",
				allowRandomPort: true,
			});
			const t = await token(
				{
					grant_type: "authorization_code",
					client_id: CLIENT_ID,
					client_secret: CLIENT_SECRET,
					code,
					redirect_uri: actualRedirectUri,
					code_verifier: pkce.verifier,
				},
				signal,
			);
			if (!t.refresh) throw new OAuthError("missing_refresh_token");
			if (signal?.aborted) throw new OAuthError("cancelled");
			const email = await userEmail(t.access, signal);
			if (signal?.aborted) throw new OAuthError("cancelled");
			const projectId = await discoverProject(t.access, ctrl);
			return { type: "oauth", access: t.access, refresh: t.refresh, expires: t.expires, ...(email ? { email } : {}), projectId };
		},

		async refresh(grant, { signal } = {}) {
			if (!grant?.refresh) throw new OAuthError("missing_refresh_token");
			if (!grant.projectId) throw new OAuthError("missing_project");
			const t = await token(
				{
					grant_type: "refresh_token",
					client_id: CLIENT_ID,
					client_secret: CLIENT_SECRET,
					refresh_token: grant.refresh,
				},
				signal,
			);
			const email = (await userEmail(t.access, signal)) ?? grant.email;
			// Project, identity and any other stored metadata carry over; the old refresh token survives an unrotated response.
			return { ...grant, access: t.access, refresh: t.refresh || grant.refresh, expires: t.expires, ...(email ? { email } : {}) };
		},

		// Key order and fields match the SDK getOAuthApiKey "structured" format; undefined values drop out of JSON.
		apiKey(grant) {
			return JSON.stringify({
				apiEndpoint: grant.apiEndpoint,
				token: grant.access,
				enterpriseUrl: grant.enterpriseUrl,
				projectId: grant.projectId,
				refreshToken: grant.refresh,
				expiresAt: grant.expires,
				email: grant.email,
				accountId: grant.accountId,
			});
		},
	};
}

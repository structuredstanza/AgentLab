// Owned port of the OpenAI Codex (ChatGPT) OAuth flow. Constants and claim handling follow the
// pinned SDK 18.13.3 registry/oauth/openai-codex.ts and catalog compat/rules/auth/openai-codex*.kdl.
import { OAuthError, abortableDelay, authorizationCode, createPkce, decodeJwt, requestJSON } from "./common.mjs";

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const SCOPE = "openid profile email offline_access api.connectors.read api.connectors.invoke";
const ORIGINATOR = "omp";
const AUTH_CLAIM = "https://api.openai.com/auth";
const PROFILE_CLAIM = "https://api.openai.com/profile";
const DEVICE_USERCODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token";
const DEVICE_REDIRECT_URI = "https://auth.openai.com/deviceauth/callback";
const DEVICE_AUTH_URL = "https://auth.openai.com/codex/device";
const DEVICE_FIRST_POLL_MS = 5_000;
const DEVICE_SAFETY_MARGIN_MS = 3_000;
const DEVICE_MAX_POLLS = 120;

const nonEmpty = v => (typeof v === "string" && v.length > 0 ? v : undefined);

// The ChatGPT workspace id is the subscription pool; plan type may exist only in the id_token.
function tokenProfile(access, idToken) {
	const a = decodeJwt(access);
	const i = idToken ? decodeJwt(idToken) : null;
	const accountId = nonEmpty(a?.[AUTH_CLAIM]?.chatgpt_account_id) ?? nonEmpty(i?.[AUTH_CLAIM]?.chatgpt_account_id);
	const email = (a?.[PROFILE_CLAIM]?.email ?? i?.[PROFILE_CLAIM]?.email);
	const plan = a?.[AUTH_CLAIM]?.chatgpt_plan_type ?? i?.[AUTH_CLAIM]?.chatgpt_plan_type;
	return {
		accountId,
		email: typeof email === "string" ? nonEmpty(email.trim().toLowerCase()) : undefined,
		planType: typeof plan === "string" ? nonEmpty(plan.trim().toLowerCase()) : undefined,
	};
}

function tokenGrant(data, stored, phase) {
	const access = nonEmpty(data?.access_token);
	const refresh = nonEmpty(data?.refresh_token) ?? (phase === "refresh" ? stored.refresh : undefined);
	if (!access || !refresh || typeof data.expires_in !== "number" || !Number.isFinite(data.expires_in)) {
		throw new OAuthError("codex_token_response_invalid");
	}
	const { accountId, email, planType } = tokenProfile(access, data.id_token);
	if (phase === "login" && !accountId && !email) throw new OAuthError("codex_identity_missing");
	const resolvedAccount = accountId ?? stored?.accountId;
	const resolvedEmail = email ?? stored?.email;
	const orgId = phase === "login" ? resolvedAccount : stored?.orgId;
	const orgName = phase === "login" ? planType : stored?.orgName;
	return {
		...(stored ?? {}),
		type: "oauth",
		access,
		refresh,
		expires: Date.now() + data.expires_in * 1000,
		...(resolvedAccount ? { accountId: resolvedAccount } : {}),
		...(resolvedEmail ? { email: resolvedEmail } : {}),
		...(orgId ? { orgId } : {}),
		...(orgName ? { orgName } : {}),
	};
}

export function createCodexOAuth({ fetchImpl = globalThis.fetch } = {}) {
	const form = (params, signal) =>
		requestJSON(
			fetchImpl,
			TOKEN_URL,
			{
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
				body: new URLSearchParams(params),
			},
			{ signal },
		);

	const exchange = (code, verifier, redirectUri, signal) =>
		form(
			{ grant_type: "authorization_code", client_id: CLIENT_ID, code, code_verifier: verifier, redirect_uri: redirectUri },
			signal,
		).then(data => tokenGrant(data, null, "login"));

	async function loginBrowser(ctrl) {
		const { verifier, challenge, state } = createPkce();
		const buildAuthUrl = redirectUri =>
			`${AUTHORIZE_URL}?${new URLSearchParams({
				response_type: "code",
				client_id: CLIENT_ID,
				redirect_uri: redirectUri,
				scope: SCOPE,
				code_challenge: challenge,
				code_challenge_method: "S256",
				state,
				id_token_add_organizations: "true",
				codex_cli_simplified_flow: "true",
				originator: ORIGINATOR,
			})}`;
		// Native catalog: OpenAI allowlists only this URI, so a busy port must fail, not fall back.
		const { code, redirectUri: actualRedirectUri } = await authorizationCode({
			buildUrl: buildAuthUrl,
			redirectUri: REDIRECT_URI,
			state,
			ctrl,
			manualOnBindError: false,
			allowRandomPort: false,
		});
		ctrl.onProgress?.("Exchanging authorization code for tokens…");
		return exchange(code, verifier, actualRedirectUri, ctrl.signal);
	}

	// Native headless variant (login id openai-codex-device); same credential store as the browser flow.
	async function loginDevice(ctrl) {
		const { signal } = ctrl;
		ctrl.onProgress?.("Initiating device authorization…");
		const init = await requestJSON(
			fetchImpl,
			DEVICE_USERCODE_URL,
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_id: CLIENT_ID }) },
			{ signal },
		);
		const deviceAuthId = nonEmpty(init?.device_auth_id);
		const userCode = nonEmpty(init?.user_code);
		if (!deviceAuthId || !userCode) throw new OAuthError("codex_device_response_invalid");
		const seconds = typeof init.interval === "number" ? init.interval : Number.parseInt(String(init.interval ?? "5"), 10) || 5;
		const intervalMs = seconds * 1000 + DEVICE_SAFETY_MARGIN_MS;
		ctrl.onAuth?.({ url: DEVICE_AUTH_URL, instructions: `Enter code: ${userCode}` });
		ctrl.onProgress?.("Waiting for browser authorization…");
		for (let poll = 0; poll < DEVICE_MAX_POLLS; poll++) {
			await abortableDelay(poll === 0 ? Math.min(intervalMs, DEVICE_FIRST_POLL_MS) : intervalMs, signal);
			if (signal?.aborted) throw new OAuthError("codex_login_cancelled");
			let data;
			try {
				data = await requestJSON(
					fetchImpl,
					DEVICE_TOKEN_URL,
					{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_auth_id: deviceAuthId, user_code: userCode }) },
					{ signal },
				);
			} catch (error) {
				// 403/404 mean authorization is still pending.
				if (error instanceof OAuthError && (error.status === 403 || error.status === 404)) continue;
				throw error;
			}
			const code = nonEmpty(data?.authorization_code);
			const verifier = nonEmpty(data?.code_verifier);
			if (!code || !verifier) throw new OAuthError("codex_device_response_invalid");
			ctrl.onProgress?.("Exchanging authorization code for tokens…");
			return exchange(code, verifier, DEVICE_REDIRECT_URI, signal);
		}
		throw new OAuthError("codex_device_timeout");
	}

	return {
		login: loginBrowser,
		loginDevice,
		async refresh(grant, { signal } = {}) {
			if (!nonEmpty(grant?.refresh)) throw new OAuthError("codex_refresh_missing");
			const data = await form({ grant_type: "refresh_token", refresh_token: grant.refresh, client_id: CLIENT_ID }, signal);
			return tokenGrant(data, grant, "refresh");
		},
		apiKey: grant => grant.access,
	};
}

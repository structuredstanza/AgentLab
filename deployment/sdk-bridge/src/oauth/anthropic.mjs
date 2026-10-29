// Owned port of the Anthropic (Claude Pro/Max) native OAuth flow.
// Sources: @oh-my-pi/pi-catalog 18.13.3 rules/auth/anthropic.kdl (endpoints, scopes, claims, skew) and
// @oh-my-pi/pi-ai 18.13.3 registry/oauth/anthropic.ts (anthropic-identity bootstrap hook),
// registry/engine/{oauth-code,refresh,common}.ts, providers/claude-code-fingerprint.ts (versions).
import { authorizationCode, createPkce, OAuthError, requestJSON } from "./common.mjs";

const CLIENT_ID = Buffer.from("OWQxYzI1MGEtZTYxYi00NGQ5LTg4ZWQtNTk0NGQxOTYyZjVl", "base64").toString("utf8");
const AUTHORIZE_URL = "https://claude.ai/oauth/authorize";
const TOKEN_URL = "https://api.anthropic.com/v1/oauth/token";
const BOOTSTRAP_URL = "https://api.anthropic.com/api/claude_cli/bootstrap";
const REDIRECT_URI = "http://localhost:54545/callback";
const SCOPES = [
	"org:create_api_key",
	"user:profile",
	"user:inference",
	"user:sessions:claude_code",
	"user:mcp_servers",
	"user:file_upload",
];
const EXPIRY_SKEW_MS = 300_000;
const CLAUDE_CODE_VERSION = "2.1.280";
const CLAUDE_CODE_SDK_VERSION = "0.112.1";
const BOOTSTRAP_MODEL = "claude-opus-4-8";
const BOOTSTRAP_TIMEOUT_MS = 30_000;
const INSTRUCTIONS =
	"Complete login in your browser. If the browser cannot reach this machine, paste the final redirect URL or authorization code when prompted.";

const nonEmpty = v => (typeof v === "string" && v.length > 0 ? v : undefined);
const JSON_HEADERS = { "Content-Type": "application/json", Accept: "application/json" };

// Token response -> grant; expiry is relative to receipt minus the catalog skew.
function mapTokens(body, previous) {
	const access = nonEmpty(body?.access_token);
	const seconds = body?.expires_in;
	if (!access || typeof seconds !== "number" || !Number.isFinite(seconds)) throw new OAuthError("invalid_token_response");
	const refresh = nonEmpty(body.refresh_token) ?? previous?.refresh;
	if (!refresh) throw new OAuthError("invalid_token_response");
	const grant = { type: "oauth", access, refresh, expires: Date.now() + seconds * 1000 - EXPIRY_SKEW_MS };
	const fields = {
		accountId: nonEmpty(body.account?.uuid),
		email: nonEmpty(body.account?.email_address),
		orgId: nonEmpty(body.organization?.uuid),
		orgName: nonEmpty(body.organization?.name),
	};
	for (const k in fields) if (fields[k] !== undefined) grant[k] = fields[k];
	return grant;
}

export function createAnthropicOAuth({ fetchImpl = globalThis.fetch } = {}) {
	// Best effort: any failure (including cancellation) leaves the grant untouched.
	async function bootstrap(grant, { includeOrg, signal }) {
		if (grant.accountId && grant.email && (!includeOrg || grant.orgId)) return grant;
		try {
			const url = `${BOOTSTRAP_URL}?entrypoint=cli&model=${encodeURIComponent(BOOTSTRAP_MODEL)}`;
			const data = await requestJSON(
				fetchImpl,
				url,
				{
					method: "GET",
					headers: {
						Accept: "application/json, text/plain, */*",
						Authorization: `Bearer ${grant.access}`,
						"Content-Type": "application/json",
						"User-Agent": `claude-code/${CLAUDE_CODE_VERSION}`,
						"anthropic-beta": "oauth-2025-04-20",
					},
				},
				{ signal, timeoutMs: BOOTSTRAP_TIMEOUT_MS },
			);
			const acct = data?.oauth_account ?? {};
			const next = { ...grant };
			next.accountId ??= nonEmpty(acct.account_uuid);
			next.email ??= nonEmpty(acct.account_email);
			if (includeOrg) {
				next.orgId ??= nonEmpty(acct.organization_uuid);
				next.orgName ??= nonEmpty(acct.organization_name);
			}
			for (const k of Object.keys(next)) if (next[k] === undefined) delete next[k];
			return next;
		} catch {
			return grant;
		}
	}

	return {
		async login(ctrl) {
			const { verifier, challenge, state } = createPkce();
			const buildAuthUrl = redirectUri => {
				const params = new URLSearchParams({
					client_id: CLIENT_ID,
					response_type: "code",
					redirect_uri: redirectUri,
					scope: SCOPES.join(" "),
					code_challenge: challenge,
					code_challenge_method: "S256",
					state,
					code: "true",
				});
				return `${AUTHORIZE_URL}?${params}`;
			};
			const { code: raw, redirectUri: actualRedirectUri } = await authorizationCode({
				buildUrl: buildAuthUrl,
				redirectUri: REDIRECT_URI,
				state,
				ctrl: { ...ctrl, onAuth: info => ctrl.onAuth?.({ ...info, instructions: INSTRUCTIONS }) },
				manualFormat: "code-state",
				allowRandomPort: true,
			});
			// A pasted `code#state` fragment wins over the callback state (upstream behavior).
			const hash = raw.indexOf("#");
			const code = hash >= 0 ? raw.slice(0, hash) : raw;
			const exchangeState = (hash >= 0 && raw.slice(hash + 1)) || state;
			const body = await requestJSON(
				fetchImpl,
				TOKEN_URL,
				{
					method: "POST",
					headers: JSON_HEADERS,
					body: JSON.stringify({
						grant_type: "authorization_code",
						client_id: CLIENT_ID,
						code,
						state: exchangeState,
						redirect_uri: actualRedirectUri,
						code_verifier: verifier,
					}),
				},
				{ signal: ctrl.signal },
			);
			const grant = mapTokens(body);
			if (ctrl.signal?.aborted) throw new OAuthError("cancelled");
			return bootstrap(grant, { includeOrg: true, signal: ctrl.signal });
		},

		async refresh(grant, { signal } = {}) {
			if (!grant?.refresh) throw new OAuthError("reauthentication_required");
			const body = await requestJSON(
				fetchImpl,
				TOKEN_URL,
				{
					method: "POST",
					headers: {
						...JSON_HEADERS,
						"anthropic-beta": "oauth-2025-04-20",
						"User-Agent": `anthropic-sdk-typescript/${CLAUDE_CODE_SDK_VERSION} userOAuthProvider`,
					},
					body: JSON.stringify({ grant_type: "refresh_token", client_id: CLIENT_ID, refresh_token: grant.refresh }),
				},
				{ signal },
			);
			// Organization is fixed at login: never remapped from the refresh response.
			const { orgId: _o, orgName: _n, ...tokens } = mapTokens(body, grant);
			const refreshed = { ...grant, ...tokens };
			// Rotated tokens are already issued; bootstrap must never discard them.
			return bootstrap(refreshed, { includeOrg: false, signal });
		},

		apiKey: grant => grant.access,
	};
}

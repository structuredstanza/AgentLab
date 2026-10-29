import { createAnthropicOAuth } from "./anthropic.mjs";
import { createAntigravityOAuth } from "./antigravity.mjs";
import { createCodexOAuth } from "./codex.mjs";

// Canonical provider id -> owned OAuth driver. fetchImpl is injectable so fixtures can fail closed on every URL.
export function createAuthProviders({ fetchImpl = globalThis.fetch } = {}) {
	return {
		anthropic: createAnthropicOAuth({ fetchImpl }),
		"openai-codex": createCodexOAuth({ fetchImpl }),
		"google-antigravity": createAntigravityOAuth({ fetchImpl }),
	};
}

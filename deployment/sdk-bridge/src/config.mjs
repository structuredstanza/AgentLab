import { readFileSync } from "node:fs";
import { isAbsolute } from "node:path";

export const PROVIDERS = Object.freeze(["anthropic", "openai-codex", "google-antigravity"]);
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1"]);
const MIN_TOKEN_LENGTH = 32;

// Env: ARTEX_SDK_BRIDGE_TOKEN_FILE (required), ARTEX_SDK_BRIDGE_DATA_DIR (required, absolute),
// ARTEX_SDK_BRIDGE_HOST (default 127.0.0.1, loopback only), ARTEX_SDK_BRIDGE_PORT (default 8788).
export function loadConfig(env = process.env) {
	const tokenFile = env.ARTEX_SDK_BRIDGE_TOKEN_FILE;
	const dataDir = env.ARTEX_SDK_BRIDGE_DATA_DIR;
	if (!tokenFile) throw new Error("ARTEX_SDK_BRIDGE_TOKEN_FILE is required");
	if (!dataDir || !isAbsolute(dataDir)) throw new Error("ARTEX_SDK_BRIDGE_DATA_DIR must be an absolute path");

	const host = env.ARTEX_SDK_BRIDGE_HOST ?? "127.0.0.1";
	if (!LOOPBACK_HOSTS.has(host)) throw new Error("ARTEX_SDK_BRIDGE_HOST must be a loopback address");

	const portText = env.ARTEX_SDK_BRIDGE_PORT ?? "8788";
	const port = Number(portText);
	if (!/^[0-9]{1,5}$/.test(portText) || port < 1 || port > 65535) {
		throw new Error("ARTEX_SDK_BRIDGE_PORT must be 1-65535");
	}

	const token = readFileSync(tokenFile, "utf8").trim();
	if (token.length < MIN_TOKEN_LENGTH) throw new Error("bridge token file is missing or too short");

	return { host, port, dataDir, token };
}

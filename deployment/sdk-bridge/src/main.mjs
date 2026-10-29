import { loadConfig } from "./config.mjs";
import { createAuthProviders } from "./oauth/index.mjs";
import { createProfiles } from "./profiles.mjs";
import { startServer } from "./server.mjs";
import * as sdk from "./sdk.mjs";

// Files and directories the bridge creates are private to its user.
process.umask(0o077);

// Hard ceiling below systemd TimeoutStopSec=35. Drains are bounded per step; this only guards against a hung close.
const SHUTDOWN_WATCHDOG_MS = 30_000;

const cfg = loadConfig();
const profiles = createProfiles({ dataDir: cfg.dataDir, sdk, authProviders: createAuthProviders() });
const server = startServer({ host: cfg.host, port: cfg.port, token: cfg.token, profiles });

console.log(`artex-sdk-bridge listening on ${server.hostname}:${server.port}`);

let stopping = null;

// Order: stop accepting new connections, drain attempts and inference (bounded), close stores without deleting grants,
// then close remaining connections. Exit code 1 if a drain timed out, so the supervisor sees the unclean stop.
function shutdown(signal) {
	if (stopping) return stopping;
	console.log(`artex-sdk-bridge stopping on ${signal}`);
	const watchdog = setTimeout(() => process.exit(1), SHUTDOWN_WATCHDOG_MS);
	stopping = (async () => {
		server.stop(false);
		let code = 0;
		try {
			await profiles.shutdown();
		} catch {
			code = 1;
		}
		server.stop(true);
		clearTimeout(watchdog);
		process.exit(code);
	})();
	return stopping;
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

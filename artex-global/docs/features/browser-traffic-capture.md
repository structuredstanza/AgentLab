# Browser traffic capture

`extension/` contains an unpacked Chromium Manifest V3 extension for operator-driven capture on an authorized target. It sends text request/response exchanges to the configured ARTEX `/api/traffic/ingest` endpoint; binary bodies are skipped and bodies are bounded to 256 KiB per response. A request that receives no response at all — blocked by the target's WAF, aborted, DNS failure — is recorded too, with status 0 and the transport error in an `x-capture-error` response header, because a block is usually the most informative result of a capture session. The extension requires the `debugger` permission, so it is not installed or enabled as part of AgentLab deployment. Install it manually in a separate, controlled browser profile only when explicitly conducting a synthetic capture session; do not use a signed-in personal profile. Stop capture when finished. Existing PCAPs and raw traffic logs remain private.

The extension's local settings store its ARTEX URL and bearer token in that browser profile. Do not share or export the profile. Never capture private or third-party browsing.

## Manual AgentLab rebuild

`./install.sh` builds the customized application locally before starting Compose. To manually rebuild later, run `./update.sh` and select the Docker rebuild option. It invokes this fork's `build.sh`, then `docker compose build artex` and restarts that locally built image. It does not pull an application image or run `git pull`; updates from upstream must be reviewed and integrated into this customized tree before rebuilding. `./build.sh` alone produces the platform binary under `dist/`.

The browser extension and tools/skills are part of the local source tree. Do not replace this tree with a stock ARTEX release; database, OAuth bridge, capture, and customized AgentLab behavior are not present in stock images.
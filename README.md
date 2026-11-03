# ARTEX autonomous-task capture environment

Installed at `/mnt/Research/AgentLab`. The running workload is a **microsandbox hardware-isolated VM**, not a Docker container. Docker was used only to build its OCI image. No host home directory, Docker socket, or host model credentials are mounted.

- UI: <http://127.0.0.1:8787>
- Username: `ARTEX`
- Password: `secrets/admin-password` (0600; generated locally, not printed)
- Model: **AgentLab Bonsai Thinking**, using the shared, manually started `bonsai.service` and the verified open-weight Bonsai 27B artifact. Real local inference/tool trajectories have been captured; no synthetic examples were inserted into the application dataset.
- Resources: 4 vCPUs, 8 GiB guest RAM. Runtime storage, persistent state and exports are on this mount. Docker's ordinary image/build cache and the host Go toolchain cache remain in their existing locations.
- Network: public outbound access, host DNS, and narrowly scoped host TCP allowances for local model inference (8080) and the authenticated native provider proxy (8788). Other private/LAN, cloud-metadata and host services are blocked by policy. UI publication is loopback-only; PostgreSQL and the guest capture proxy are not published.
- Original source base: https://github.com/jiwoochris/artex-global.git at `fdfb7a17b7da5e2de716c0e98475ec77a41c64c6`, with local reasoning-capture, OAuth and refusal-fallback changes. Version/toolchain and model identity: `deployment/provenance.json`. Upstream is AGPL-3.0; see `artex-global/LICENSE`.

This private AgentLab monorepo tracks the ARTEX working tree, deployment source, tests and build configuration. Credentials, OAuth stores, VM disks, captures, datasets, exports, caches, generated binaries, local reviews and downloaded reference packages remain local and are excluded by `.gitignore`. Rebuild generated artifacts and provision credentials separately on a new machine; this repository is not a backup of the running environment. The original ARTEX Git history is retained locally at `.upstream-git/artex-global.git` (not published); normal Git commands now use the AgentLab repository.

The current ARTEX upstream for future selective imports is [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX), reviewed at `7f8c7cb` on 2026-10-29. In the preserved ARTEX Git metadata, `origin` points there and `previous-upstream` retains `jiwoochris/artex-global`. The AgentLab monorepo's `origin` remains the private `structuredstanza/AgentLab` repository. Changing this reference does not merge upstream code or change the running VM; do not replace the customized deployment with a stock upstream release.

## Operate

Run from this directory:

```sh
./lab start       # Create or restart the VM, start services, enable capture
./lab status      # VM details and effective ARTEX settings
./lab primary     # Select/verify the installed local thinking model, without paid fallbacks
./lab export      # Consistent database rows + backups, artifact snapshot, training export
./lab stop        # Gracefully stop ARTEX, flush tcpdump, stop PostgreSQL, then stop VM
```

The VM is currently left running. After a host reboot, run `./lab start`; it also starts the host native provider proxy and the selected local model. Detached task execution does not depend on a browser tab remaining open. Use `./lab stop`, not a force-kill, so packet statistics and session end-state are finalized. The separate host proxy can be stopped with `systemctl --user stop artex-cliproxy.service`; its private credential stores persist.

`lab` targets `artex-agentlab-astra-reviewed-20261031t010522z`, using the reviewed application and freshly rebuilt native CLIProxyAPI OAuth/inference host. The replaced `artex-agentlab-native-codex-capture` VM has been removed; persistent `state/`, native OAuth stores and captures are preserved. Earlier historical VMs remain stopped; never start two against the shared `state/` directory. The pre-cutover export is `exports/20261031T010522.561238Z`. Installed VM capture verification is in `exports/20261031T010908.806480Z`. Bonsai has been manually started for testing at the user's request; the selected primary profile is unchanged.

Open the UI and review its Usage Notice yourself. Provider profiles, authentication and reasoning settings live under **System → LLM** (`/system/llm`). The setup did not accept the notice on your behalf. Start user-directed tasks through ARTEX's Tasks page. Explicitly specify authorized assets, the objective, success criteria and time/resource limits. This is an autonomous security-testing application: only direct it at systems you are authorized to test. Verification tasks use only local fixtures, not external targets.

Only English UI catalogs and documentation variants are retained; language selectors have been removed. Application-authored visible text, role/tool metadata, editable built-in prompts, errors, and transcript framing are English. Upgrade migrations replace only exact recognized shipped defaults, preserve custom prompts and settings, and retain previous prompt versions. User/model/target content, historical capture data, legacy format readers, and genuinely model-only context are not rewritten.

ARTEX's `llm_record`, `traffic_capture`, `agent_traffic_binding`, and `llm_refusal_fallback_enabled` settings are enabled. `./lab start` enforces them. If you later change the admin password in the UI, update the private `secrets/admin-password` file to match; the control/export commands authenticate with that file.

### Provider authentication and fallback

**Deployed replacement:** the running VM uses the native CLIProxyAPI backend. The retired Bun bridge source and service unit have been removed from the active deployment; no legacy grants were imported. Native Codex inference and reasoning capture are live-verified; Claude, Antigravity and live refresh remain unexercised on this backend. Private rollback state is historical evidence, not an active bridge.

In **System → LLM**, save a profile and choose its native Claude Code, Codex, or Antigravity sign-in button. Login, PKCE/callback validation, token exchange, refresh, inference and model discovery run on the native provider host using pinned CLIProxyAPI v8.0.47; ARTEX's VM receives neither provider tokens nor an OMP OAuth/AuthStorage dependency. Enter account credentials yourself only on the provider's page. Follow any manual callback prompt in the UI. Preferred host callback ports are 54545, 1455, and 51121 respectively. Anthropic and Antigravity can select a free loopback port if theirs is busy; Codex requires port 1455. `localhost` callbacks bind both loopback address families when IPv6 is available.

The host `artex-cliproxy.service` owns per-profile native credential stores under private `proxy-state/`, handles refresh, and gives the VM only a capability—not provider tokens. Refresh is single-flight and persists rotated tokens even if the waiting caller cancels; failed or canceled re-login preserves the previous grant. Disconnect drains active calls and refresh before removing the grant. Unknown credential-store schemas are rejected without modification. Replay of native state follows the verified-origin policy in `.upstream-work/cliproxy-contract.md`. Offline native-host lifecycle and inference fixtures have passed; native Codex acceptance is live-verified, while other providers and live refresh remain unexercised. Credential stores are excluded from training exports. Subscription profiles are excluded from automatic rotation and are not the default. Live authorization requires human consent; current connection status appears under **System → LLM**.

The native bearer capability must be a private regular file. Host and app both ignore surrounding whitespace; empty or whitespace-only files are rejected. This permits ordinary newline-terminated secret files without weakening bearer authentication.

**Login is not anonymous.** Native provider OAuth client identities remain visible. No ARTEX-specific OAuth application was registered, but task prompts, tool results, file paths, files and screenshots can disclose ARTEX. There is no guarantee that providers cannot identify or infer the application. Leave cloud accounts disconnected if zero disclosure of ARTEX identifiers is required.

Model discovery works before login and supplies supported reasoning efforts. Unsupported explicit efforts are rejected rather than silently downgraded. API-key profiles retain their existing transport. Subscription profiles use native internal streaming, but ARTEX displays completed-turn output so native thinking signatures, tool history and encrypted replay state survive subsequent turns.

Only provider-exposed reasoning is recoverable. Codex summaries, exposed Claude thinking, Antigravity thoughts, and local open-weight reasoning are retained with their observed provenance; ambiguous kinds remain unclassified. Opaque signatures/encrypted state are preserved separately, not converted into training text. An unset effort leaves the provider/model default unchanged. See the [provider's reasoning documentation](https://developers.openai.com/api/docs/guides/reasoning).

Codex requests use the existing Responses-to-Codex converter, including `store:false`, `stream:true` and `reasoning.encrypted_content`, while responses retain native Codex format. GPT Astra diagnosed the previous pass-through path, which produced upstream `Store must be set to false` rejections. Privacy denials now retain their bounded `403/denied` identity instead of becoming generic unavailability. Automatic chat and attachment notices use workspace-relative paths; physical tool working directories, attachment validation and privacy admission are unchanged.

Live verification `conv-5`, record `8`, returned the correct arithmetic answer `3283` through `gpt-6.1-sol`. The record retains the provider's 33-character summary, 2,828-character opaque encrypted reasoning state, replay receipt, usage and native wire artifacts. The HTTP response capture closed after the semantic terminal event without observing EOF (`Complete:false`, `Truncated:false`); this is not proof of an EOF-complete HTTP stream. This historical sample did not exercise tools or refresh. The reviewed build now forwards Codex function-tool definitions and accepts valid captured native tool-loop history during export; a standalone native fixture executed real Bash and exported both turns. No new live provider inference or refresh was run during this deployment.

Export `exports/20261030T195756.399338Z` accepts record `8` into `training/train.jsonl` and indexes its summary and opaque-state hash separately in `raw/reasoning.jsonl`; native wire artifacts are in `raw/provider-proxy-traffic/native-sse.ndjson`. Usage includes 121 reasoning tokens, which does not make their hidden text available. Per-row `model_backend` and `provenance` labels remain `unknown`; the observed deployment identities are recorded separately in `deployment/provenance.json`.

Each provider profile has its own ordered **Refusal fallback chain** in **System → LLM → (profile) → Refusal fallback chain**: models, each with an optional reasoning effort, tried in order on the same account. Order them from newest to progressively older or lower-thinking models; the list is operator-editable, with no hard-coded model versions, and every entry is validated against the provider's catalog and supported efforts. **LLM → Rotation settings → Fall back when a model refuses** is the master switch (enabled by `./lab start`). On a refusal before any answer or tool call is committed, only that model request is retried with the profile's next chain entry; when the chain is exhausted, the task's ordered profile chain advances as before. When transitioning between models on a native subscription chain, multi-turn history retains visible user and assistant text while prior-model tool calls and results are rendered as readable transcript text in the copied outbound request, omitting old-model thinking, signatures, and opaque provider states; uninspectable attachment blocks fail closed with an error. Subsequent turns continue on the active branch model and replay its new valid native state while independent sessions start on the primary model. Recorded request bodies capture explicit local handoff metadata (`handoff` with from_models, to_model, kind `readable_history`, and prefix_count) without leaking to providers or modifying the database schema. Already delivered output and executed tools are never replayed. The chain applies where refusal fallback already applied, i.e. calls pinned to a task profile; direct agent bindings and chat conversations do not run it. Records distinguish `refused` from `error`; exhausted refusal chains block with `llm_refused`, not quota exhaustion. The local primary has no paid fallbacks enabled automatically.

Branch identity includes reasoning effort: a same-model high-to-low transition is a new choice, and subsequent turns remain on that choice. The editor permits repeated model IDs with different effective efforts; an empty fallback effort inherits the profile's effort, while duplicate effective choices (including the primary) are rejected. Handoff provenance is recorded locally in `request_body.handoff`, not added to provider wire requests. Original private traces remain intact; accepted training samples redact task-vault secrets, including JSON-escaped forms emitted by Go.

### Subscription allocation

Provider-reported **5-hour** and **7-day** allocation windows, when available, appear in the profile drawer (**Remaining allocation**) and the main dashboard's **Subscription Allocations** card, with their reset times. Values come from the provider's usage endpoints through the native host (`GET /v1/profiles/:id/usage`, exposed as `/api/llm/usage`); nothing is estimated. Explicit exhaustion is **0% remaining**. Missing, null or unsupported measurements are unavailable, not 100% remaining; Antigravity model availability is not treated as measured quota. Results are cached for 120 seconds, a 429 pauses that profile for 5 minutes, and failures preserve the last measured value only with a visible stale indication. Unavailable subscriptions remain visible without invented percentages. The dashboard polls every 120 seconds while visible. Usage refreshes can contact the provider with your account, but do not send model prompts.

### Adapt the guest

`lab exec` runs **noninteractive** commands and records argv, separate stdout/stderr bytes, timestamps, command IDs and exit status:

```sh
./lab exec -- python3 -c 'print("guest execution")'
./lab exec -- bash -lc 'apt-get update && apt-get install -y python3-venv'
```

Python 3, Node.js 22, Chromium/Playwright, Git, curl, jq, ripgrep, nmap and DNS/network tools are installed. Guest root can install task-specific packages. Rootfs changes survive ordinary stop/start. For rebuildable additions, update `deployment/Dockerfile` and rebuild the image rather than relying only on mutable guest changes. Put files that must be exported under `/state/artex` (ARTEX task workspaces already live there); arbitrary `/tmp` or `/root` contents are not copied by `lab export`.

Chromium was exercised successfully headless inside the VM. Guest-root launches need `--no-sandbox`; the outer VM supplies the host-isolation boundary. Do not use this image as an ordinary privileged host container.

## Captured data

| Surface | Artifacts and behavior |
|---|---|
| Model inputs/outputs | ARTEX PostgreSQL `llm_records`: normalized requests/responses and provider recordings. API-key transports retain wire bodies; native subscription transports retain the proxy's capture records and replay state—not hidden provider internals. Only real configured-provider calls become application training samples. |
| Reasoning | Explicitly exposed thinking/reasoning text is retained separately from provider summaries and opaque replay state. `raw/reasoning.jsonl` indexes text and opaque-field hashes for accepted and rejected records. Opaque signatures are not proof of recoverable chain-of-thought. Hidden internal reasoning cannot be captured. |
| Tools and agent state | Native `activity`, task/session, intercept, usage and server-log tables; task workspace files and transcripts, including actual local verification trajectories. |
| HTTP(S) | ARTEX's built-in proxy records inspectable requests/responses, bodies, status and traffic index. Agent traffic binding is enabled. Proxy-aware tools use its CA/proxy integration. |
| Raw network | `state/captures/<session>/pcap/capture.pcap*`: guest `tcpdump -i any -s0 -U`, including loopback, DNS and non-HTTP traffic. TLS payloads stay encrypted in PCAP. |
| Processes/files/network syscalls | `state/captures/<session>/strace/strace.<pid>`: ARTEX and descendants, with timestamps and syscall durations. Decoded strings/arguments are limited to 256 bytes; this is not full file-content capture. |
| Host native provider proxy | Private `proxy-state/network/` syscall traces cover the proxy's process/file/socket activity, with 256-byte decoded strings. Plaintext socket buffers can contain the guest capability token and OAuth callback material, so these logs are secret-bearing and private. Guest PCAP sees the host API connection, not the proxy's upstream provider connection; no host-wide PCAP is installed. |
| Resource use | `resources.jsonl`: guest CPU tick counters, memory counters and per-interface byte/packet counters, sampled approximately once per second. Model usage/latency are separately recorded by ARTEX. |
| Supervision | Session manifests contain source-binary hash, service PIDs, start/end/error states, capture limits and final tcpdump packet/drop statistics on clean shutdown. PostgreSQL log: `state/runtime/logs/postgres/postgres.log`. |
| Runtime/manual execution | Microsandbox runtime/exec logs plus `host-events.jsonl` for `lab exec`. Native runtime job output may be pruned; durable host events and ARTEX records are the intended trace sources. |

`tcpdump` starts before ARTEX. If it exits unexpectedly while ARTEX is running, the supervisor stops the app rather than continuing an uncaptured run. Packet capture rotates at **128 million bytes per segment, 32 segments per service session**: approximately 4.096 GB total per session. Older segments in that session are overwritten once the ring is full. A restart creates a new session directory. Other application, syscall, resource and export data do not have automatic retention limits; monitor free space. Raw capture deliberately includes sensitive traffic, potentially including localhost login traffic.

Traffic from commands that bypass ARTEX's proxy remains visible as packets, but their HTTPS plaintext is not automatically available. Certificate-pinned clients or unsupported protocols may not be inspectable. No global host TLS interception was installed.

## Export for training and post-training

`./lab export` prints its export directory:

```text
exports/<UTC timestamp>/
  manifest.json                 # File SHA-256 hashes, counts, consistency/privacy limits
  raw/
    postgres.dump               # Complete transactional PostgreSQL custom-format backup
    <table>.jsonl               # All public tables, captured in one repeatable-read transaction
    application/                # Task files, transcripts, traffic blobs/index, reports
    captures/                   # PCAP, strace, resources and session manifests
    runtime-logs/
    provider-proxy-network/     # Host proxy syscall logs only; secret-bearing and private; never credential stores
    host-events.jsonl
    sandbox.json
    sandbox.yaml
    provenance.json
    capture-export.json         # Guest-local filesystem snapshot details and skipped nonregular entries
    rejects.jsonl               # Unredacted original rejected model records + reasons
    reasoning.jsonl             # Private reasoning text/summary and opaque-field index
  training/
    train.jsonl                 # Accepted, heuristically redacted conversation samples
    NOTICE.txt
```

SQLite backups are created **inside the guest**, in the same kernel as the recording process; the host never opens the live guest-owned SQLite database. Files stream out as a tar archive into a fresh, host-only export directory. Host extraction rejects links and escaping paths. PostgreSQL JSONL tables form one consistent database snapshot; `postgres.dump` is a separate consistent snapshot. Files/PCAP are an online copy, not an atomic whole-machine checkpoint; a live packet-file copy can end with an incomplete trailing packet.

The training exporter accepts Anthropic, OpenAI chat/Responses, native Gemini/Antigravity JSON/SSE, and native SDK event NDJSON. It reconstructs tool calls/results with actual schemas and carries exposed reasoning, model/session/task provenance, timing and token metadata. Provider summaries, generated open-weight reasoning, and opaque replay state remain distinct; ambiguous reasoning is not guessed into a stronger classification. Unsupported, refused, failed, truncated or mismatched records remain in raw rejects; available reasoning still receives a sidecar entry. Conversation samples contain the prior history plus the recorded assistant turn. Configure your trainer to learn the intended target turn rather than repeatedly training every historical assistant turn.

`train.jsonl` is a **curation interchange format**, not a claim of one-click compatibility with every finetuning service. Preserve the raw files for alternate trainers, reward/outcome analysis and filtering. No reward, success label or hidden reasoning is fabricated. Tool/task outcomes and failures are available in the raw tables/workspaces for later task-specific labeling. Source format changes may require exporter updates.

Train-file secret redaction is heuristic, **not a PII/secrets guarantee**. OAuth databases are excluded, but raw tables, backups, rejected records, packets and syscall logs can still contain secrets, bridge capabilities or callback codes. Review/minimize datasets before sharing or training. The root directory is private to the host user; exports use private permissions. This does not provide encryption at rest. Guest root can tamper with guest-side recordings; post-export hashes detect later changes but do not prove the original recording was authentic. Do not treat this as tamper-proof forensic isolation.

VM disk/full snapshots do **not** checkpoint the external `/state` bind mount. Do not fork/restore VMs against the same live PostgreSQL directory. Keep the persistent state and database backup with any independent experiment/checkpoint.

## Verification performed

- Microsandbox 0.7.11 `doctor`: usable AMD hardware virtualization and `/dev/kvm`.
- Real guest boot, directory/file mounts, loopback-only UI publication and authenticated capture settings.
- Automated exporter/archive/model-identity checks; rerun the commands below for the current result rather than relying on a historical count.
- `python3 deployment/verify_capture.py`: a unique, guest-local HTTP fixture through the actual ARTEX proxy; correlated stdout/stderr; matching PCAP frames; current-session strace and resource samples; actual exported PostgreSQL backup readability; exported SQLite integrity and exact fixture; every exported checksum.
- Graceful stop: services stopped, manifest finalized, no capture errors and zero reported kernel packet drops for the first completed service session.
- Restart: pre-restart traffic persisted; the full unique-fixture capture/export smoke passed again.
- Headless Chromium inside the guest and visual browser inspection of the installed login page.
- `python3 deployment/verify_reasoning.py`: real local open-weight thinking, one autonomous Bash call, independent nonce/product artifact, tool result, every recorded model turn exported, raw-reasoning classification and checksum verification.
- Isolated provider fixtures exercised actual Antigravity and Responses/Codex HTTP → recorder → training-export paths, including tool identity, summaries and opaque state. Actual ARTEX task runs verified refusal fallback, quota distinction and `llm_refused` exhaustion; browser checks verified raw reasoning, the refused badge, OAuth state-error presentation and saved fallback order. These are fixture interoperability checks, not proof of acceptance by live cloud accounts.
- Owned OAuth verification passed 100 tests across 11 files with external networking disabled and production HOME, credentials and state hidden. All three providers completed fixture OAuth/PKCE, persisted grants, parsed native SDK reasoning/state, replayed multi-turn messages and refreshed expired tokens without exposing credentials in captured output. Cases include dual-stack/busy-port callbacks, cancellation/re-login, refresh/disconnect races, unknown-schema preservation and unsupported efforts. The deployed helper also passed real HTTP health, unauthorized-request, disconnected-status and bundled-catalog smoke checks. These are local fixture results, not live account authorization.
- At the initial SDK cutover, the rebuilt VM's binary hash matched the host build. UI checks created the three disconnected profiles, verified SDK-managed controls, and proved that an unsupported saved-model effort could not be silently persisted. No provider sign-in button was activated during that cutover.
- Subsequent human-approved live OAuth completed for Codex, Claude Code and Google Antigravity; all three connections appeared in ARTEX. The Codex grant also survived a helper restart. A live expiry-format mismatch was corrected at the host bridge, and the 100-test isolated suite passed again. These checks did not send model requests, force token refresh, change the default profile or enable cloud rotation.

Rerun:

```sh
python3 -m unittest discover -s deployment -p 'test_*.py'
python3 deployment/verify_capture.py
python3 deployment/verify_reasoning.py
```

The capture verifier creates identifiable local fixture traffic without calling a model; it requires host `tshark`. The reasoning verifier separately calls the configured local model and leaves its genuine conversation and export available for inspection. Neither verifies cloud-provider acceptance, OAuth login/refresh, or access to hidden reasoning.

## Rebuild

From `artex-global`, run the upstream build with `ARTEX_OUTPUT=/mnt/Research/AgentLab/artex-global/dist/amd64/artex` and `ARTEX_COMPRESS=off`, using `./build.sh --target linux/amd64`. Then from the AgentLab root:

```sh
DOCKER_BUILDKIT=0 docker build --build-arg TARGETARCH=amd64 -f deployment/Dockerfile -t agentlab/artex:local .
docker save --output artex-image.tar agentlab/artex:local
MSB_HOME=/mnt/Research/AgentLab/microsandbox .venv/bin/msb load --input artex-image.tar
```

The legacy builder is used because this host lacks the buildx plugin. Importing a new image does not migrate an existing VM rootfs. Export and stop existing work before planning a replacement; do not delete live state casually. The pinned Python dependency is in `deployment/requirements.txt`. Base-image/system packages may change on a rebuild; retain the current imported image and provenance for exact replay. Built-in ARTEX self-update is not the deployment-update path; use an explicit rebuild.

The host native provider proxy is separate from the image. It is the CLIProxyAPI v8.0.47 host (`cmd/provider-proxy`, pinned to commit `90c447d3a8727d115aa7552ec93ce023736ed492`), built to `dist/provider-proxy`. `lab` creates the private capability `secrets/native-proxy-token` (0600) and installs/starts the dedicated user unit `deployment/artex-cliproxy.service`; it refuses to overwrite an unrelated unit or rotate an existing capability. The old owned Bun/OMP SDK bridge source and service unit have been removed from the active deployment. Native OAuth uses fresh human login; legacy grants are not migrated. Previous bridge deployments and exports remain historical evidence. Live native OAuth and refresh verification is still pending explicit human validation.
Manual host use: `dist/provider-proxy -listen 127.0.0.1:8788 -data <private-state-root> -token-file <private-capability-file>`. The listener accepts loopback IPs only and the capability must be a private regular file.

The private `<private-state-root>/captures/native-sse.ndjson` archive records provider inference HTTP requests and responses at the SDK HTTP transport boundary, before native executor translation or aggregation. Each line contains `Direction`, `Provider`, `Model`, `Profile`, `SessionID`, `Path`, `ContentType`, `ContentEncoding`, `Body` (base64), `Complete`, and `Truncated`. It is not packet capture or full decrypted wire capture, and cannot expose reasoning the provider did not return.


# ARTEX autonomous-task capture environment

Installed at `/mnt/Research/AgentLab`. The running workload is a **microsandbox hardware-isolated VM**, not a Docker container. Docker was used only to build its OCI image. No host home directory, Docker socket, or host model credentials are mounted.

- UI: <http://127.0.0.1:8787>
- Username: `ARTEX`
- Password: `secrets/admin-password` (0600; generated locally, not printed)
- Model: **AgentLab Bonsai Thinking**, using the shared, manually started `bonsai.service` and the verified open-weight Bonsai 27B artifact. Real local inference/tool trajectories have been captured; no synthetic examples were inserted into the application dataset.
- Resources: 4 vCPUs, 8 GiB guest RAM. Runtime storage, persistent state and exports are on this mount. Docker's ordinary image/build cache and the host Go toolchain cache remain in their existing locations.
- Network: public outbound access, host DNS, and narrowly scoped host TCP allowances for local model inference (8080) and the authenticated SDK bridge (8788). Other private/LAN, cloud-metadata and host services are blocked by policy. UI publication is loopback-only; PostgreSQL and the guest capture proxy are not published.
- Source: https://github.com/jiwoochris/artex-global.git at `fdfb7a17b7da5e2de716c0e98475ec77a41c64c6`, with local reasoning-capture, OAuth and refusal-fallback changes. Version/toolchain and model identity: `deployment/provenance.json`. Upstream is AGPL-3.0; see `artex-global/LICENSE`.

This private AgentLab monorepo tracks the ARTEX working tree, deployment source, tests and build configuration. Credentials, OAuth stores, VM disks, captures, datasets, exports, caches, generated binaries, local reviews and downloaded reference packages remain local and are excluded by `.gitignore`. Rebuild generated artifacts and provision credentials separately on a new machine; this repository is not a backup of the running environment. The original ARTEX Git history is retained locally at `.upstream-git/artex-global.git` (not published); normal Git commands now use the AgentLab repository.

## Operate

Run from this directory:

```sh
./lab start       # Create or restart the VM, start services, enable capture
./lab status      # VM details and effective ARTEX settings
./lab primary     # Select/verify the installed local thinking model, without paid fallbacks
./lab export      # Consistent database rows + backups, artifact snapshot, training export
./lab stop        # Gracefully stop ARTEX, flush tcpdump, stop PostgreSQL, then stop VM
```

The VM is currently left running. After a host reboot, run `./lab start`; it also starts the host SDK helper and the selected local model. Detached task execution does not depend on a browser tab remaining open. Use `./lab stop`, not a force-kill, so packet statistics and session end-state are finalized. The separate host helper can be stopped with `systemctl --user stop artex-sdk-bridge.service`; its private OAuth stores persist.

`lab` targets `artex-agentlab-quota`. The previous allocation, SDK, English-only and older VMs are retained, stopped; never start two against the shared `state/` directory. The pre-cutover backup is retained at `exports/20261029T215217.941467Z`. Bonsai was left stopped during this cutover; the selected primary profile is unchanged.

Open the UI and review its Usage Notice yourself. Provider profiles, authentication and reasoning settings live under **System → LLM** (`/system/llm`). The setup did not accept the notice on your behalf. Start user-directed tasks through ARTEX's Tasks page. Explicitly specify authorized assets, the objective, success criteria and time/resource limits. This is an autonomous security-testing application: only direct it at systems you are authorized to test. Verification tasks use only local fixtures, not external targets.

Only English UI catalogs and documentation variants are retained; language selectors have been removed. Application-authored visible text, role/tool metadata, editable built-in prompts, errors, and transcript framing are English. Upgrade migrations replace only exact recognized shipped defaults, preserve custom prompts and settings, and retain previous prompt versions. User/model/target content, historical capture data, legacy format readers, and genuinely model-only context are not rewritten.

ARTEX's `llm_record`, `traffic_capture`, `agent_traffic_binding`, and `llm_refusal_fallback_enabled` settings are enabled. `./lab start` enforces them. If you later change the admin password in the UI, update the private `secrets/admin-password` file to match; the control/export commands authenticate with that file.

### Provider authentication and fallback

In **System → LLM**, save a profile and choose its native Claude Code, Codex, or Antigravity sign-in button. Login, PKCE/callback validation, token exchange and refresh are owned implementations ported from OMP 18.13.3 under its MIT license; they do not call OMP OAuth or AuthStorage at runtime. The pinned SDK remains responsible for inference and model discovery only. Enter account credentials yourself only on the provider's page. Follow any manual callback prompt in the UI. Preferred host callback ports are 54545, 1455, and 51121 respectively. Anthropic and Antigravity can select a free loopback port if theirs is busy; Codex requires port 1455. `localhost` callbacks bind both loopback address families when IPv6 is available.

The host `artex-sdk-bridge.service` owns per-profile SQLite OAuth stores under private `sdk-state/profiles/`, handles refresh, and gives the VM only a bridge capability—not provider tokens. Refresh is single-flight and persists rotated tokens even if the waiting caller cancels; failed or canceled re-login preserves the previous grant. Disconnect drains active calls and refresh before removing the grant. Unknown credential-store schemas are rejected without modification; no production grants existed at the initial cutover. OAuth databases are excluded from training exports. The three subscription profiles were provisioned disconnected, excluded from automatic rotation, and not the default. Live authorization requires human consent; current connection status appears under **System → LLM**.

**Login is not anonymous.** Native provider OAuth client identities remain visible. No ARTEX-specific OAuth application was registered, but task prompts, tool results, file paths, files and screenshots can disclose ARTEX. There is no guarantee that providers cannot identify or infer the application. Leave cloud accounts disconnected if zero disclosure of ARTEX identifiers is required.

Model discovery works before login and supplies supported reasoning efforts. Unsupported explicit efforts are rejected rather than silently downgraded. API-key profiles retain their existing transport. SDK profiles use native internal streaming, but ARTEX displays completed-turn output so native thinking signatures, tool history and encrypted replay state survive subsequent turns.

Only provider-exposed reasoning is recoverable. Codex summaries, exposed Claude thinking, Antigravity thoughts, and local open-weight reasoning are retained with their observed provenance; ambiguous kinds remain unclassified. Opaque signatures/encrypted state are preserved separately, not converted into training text. An unset effort leaves the SDK/model default unchanged. See the [provider's reasoning documentation](https://developers.openai.com/api/docs/guides/reasoning).

Each provider profile has its own ordered **Refusal fallback chain** in **System → LLM → (profile) → Refusal fallback chain**: models, each with an optional reasoning effort, tried in order on the same account. Order them from newest to progressively older or lower-thinking models; the list is operator-editable, with no hard-coded model versions, and every entry is validated against the provider's catalog and supported efforts. **LLM → Rotation settings → Fall back when a model refuses** is the master switch (enabled by `./lab start`). On a refusal before any answer or tool call is committed, only that model request is retried with the profile's next chain entry; when the chain is exhausted, the task's ordered profile chain advances as before. Already delivered output and executed tools are never replayed. The chain applies where refusal fallback already applied, i.e. calls pinned to a task profile; direct agent bindings and chat conversations do not run it. Records distinguish `refused` from `error`; exhausted refusal chains block with `llm_refused`, not quota exhaustion. The local primary has no paid fallbacks enabled automatically.

### Subscription allocation

Each connected subscription's remaining **5-hour** and **7-day** allocation, with reset times, appears in its profile drawer (**Remaining allocation**) and in the **Subscription Allocations** card on the main dashboard. Values come from the provider's own usage endpoints, read by the host helper with the stored grant (`GET /v1/profiles/:id/usage`, exposed as `/api/llm/usage`); nothing is estimated. Results are cached for 120 seconds, a 429 pauses that profile for 5 minutes, and the last good value is shown marked stale on errors. Antigravity reports its own "Five Hour Limit" and "Weekly Limit" buckets. The dashboard polls every 120 seconds and only while the tab is visible. Each refresh is a live request to the provider with your account; usage reads do not send model prompts.

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
| Model inputs/outputs | ARTEX PostgreSQL `llm_records`: normalized requests/responses and provider recordings. API-key transports retain wire bodies; SDK transports retain native event NDJSON, terminal messages, payload/SSE hooks and replay state—not full upstream HTTP headers/bodies. Only real configured-provider calls become application training samples. |
| Reasoning | Explicitly exposed thinking/reasoning text is retained separately from provider summaries and opaque replay state. `raw/reasoning.jsonl` indexes text and opaque-field hashes for accepted and rejected records. Opaque signatures are not proof of recoverable chain-of-thought. Hidden internal reasoning cannot be captured. |
| Tools and agent state | Native `activity`, task/session, intercept, usage and server-log tables; task workspace files and transcripts, including actual local verification trajectories. |
| HTTP(S) | ARTEX's built-in proxy records inspectable requests/responses, bodies, status and traffic index. Agent traffic binding is enabled. Proxy-aware tools use its CA/proxy integration. |
| Raw network | `state/captures/<session>/pcap/capture.pcap*`: guest `tcpdump -i any -s0 -U`, including loopback, DNS and non-HTTP traffic. TLS payloads stay encrypted in PCAP. |
| Processes/files/network syscalls | `state/captures/<session>/strace/strace.<pid>`: ARTEX and descendants, with timestamps and syscall durations. Decoded strings/arguments are limited to 256 bytes; this is not full file-content capture. |
| Host SDK helper | Private `sdk-state/network/` syscall traces cover the helper's process/file/socket activity, with 256-byte decoded strings. SDK payload/SSE hooks supply application-level events. Guest PCAP sees the bridge connection, not the helper's upstream provider connection; no host-wide PCAP is installed. |
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
    sdk-network/                # Host helper syscall logs only; never OAuth databases
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

The host SDK helper is separate from the image. Its pinned inference/catalog packages and lockfile are in `deployment/sdk-bridge`; install with `npm ci --ignore-scripts --no-audit --no-fund`. Owned OAuth modules are in `src/oauth/`, with upstream source attribution and license in `THIRD-PARTY-NOTICES.txt`. Native browser OAuth, refresh/account metadata and Antigravity project onboarding are retained; the Codex device-flow implementation is retained internally but is not an additional UI login option. Provider fingerprints are pinned rather than fetched by the owned OAuth layer at runtime. The service uses OMP 18.13.3's embedded Bun 1.4.4 runtime, isolated HOME and explicit per-profile stores; using that runtime does not delegate authentication to OMP. `lab` creates a private bridge capability and installs/starts the dedicated user unit; it refuses to overwrite an unrelated unit or rotate an existing valid capability.

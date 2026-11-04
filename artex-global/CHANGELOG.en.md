# Changelog

English

This document records the changes that the ARTEX global edition (this fork) adds on top of the upstream repository. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The upstream ARTEX project's per-version release history (0.3.x and earlier) and contributor list are preserved verbatim in the upstream repository. As with the original README, the original text is kept unchanged so that it stays easy to compare against upstream changes. The detailed content and rationale for each change can be found in the repository's commit history.

## [Unreleased]

### Codebase review

- Remove the write-only Gemini accumulator `terminal` field and its assignment; completion still depends on candidate finish reasons and function calls. Preserve the separate Claude and Codex terminal checks.
- Enforce tool approval against canonical names in both planner and worker paths, including aliases, cancellation, and explicit rejection.
- Prepare profile runtimes before committing activation or replacement, serialize cache publication, and report profile-deletion failures without disconnecting rejected deletions.
- Persist session-scoped native selection and readable-history handoff grants before dispatch. Verify source receipts locally against the credential epoch; preserve only the destination's signed suffix, and do not count rejected history as a provider failure.
- Keep per-turn native Complete mode through SDK wrappers, profile changes, pools, and compaction. Run judges and side questions independently of the main native transcript; reject unsafe or incomplete judge answers.
- Own the Norma SDK source locally, based on BaaRai/Norma v0.4.4, with its license and modification notices. Exercise the nested SDK module explicitly in CI. Translate imported shell-tool messages, notifications, archive labels, and comments to English with syntax-aware utility checks.
- Preserve exact JSON numbers through signed replay, readable handoffs, tool execution, and export. Advertise Codex tool definitions so native agents can discover and execute their tools.
- Bound SSE setup cancellation without canceling a successfully established MCP connection. Drain disconnect operations once, even when concurrent callers cancel.
- Constrain workspace access to its opened root, including symlink races. Create attachments atomically, retain the original destination on read failure, and remove multipart scratch files.
- Commit initial task credentials with task creation, preserving password bytes exactly. Complete supervisor cleanup despite full capture storage or broken diagnostics; retain browser-capture headers.
- Round-trip legacy evidence archives without changing binary bodies or treating literal blob markers as references. Reject missing, incomplete, ambiguous, or corrupt evidence before import commits.
- Recover final native wire schemas and effective thinking metadata; keep provider summaries and opaque reasoning digests distinct. Export valid native tool-loop history without leaking replay envelopes, and reject malformed or duplicate historical envelopes.
- Preserve empty-candidate Antigravity safety refusals as refusals rather than truncated streams, including refusal-chain handling.

### Subscription allocation correctness

- Keep explicit exhausted quota at zero remaining for Codex, Claude and Antigravity; omit missing or unmeasured windows instead of treating them as full allocation.
- Remove Antigravity's model-availability fallback from quota measurement; only measured quota-summary buckets are displayed.
- Preserve last-good allocation as visibly stale when native status, dashboard polling or settings refresh fails. Keep unavailable subscriptions visible without fabricated percentages.
- Show subscription resets as remaining days/hours (for example, `4d2hr`) on both the dashboard and profile settings, instead of displaying only a clock time.

### Upstream feature integration

- Integrate BaaRai/ARTEX at `7f8c7cb`, retaining AgentLab's owned OAuth, refusal status and provider fallbacks, subscription allocation, English-only interface, and private trace capture.
- Add task credentials with explicit password reveal/copy, outcome and capability-gap APIs, evidence-backed RSI candidate extraction and off/shadow/inject modes. No automatic lesson adoption or harness self-modification.
- Add goal validation, repeated-direction warnings, consecutive-failure escalation, opt-in per-intent profile rotation, planner quiet mode, and pause-aware task deadlines.
- Add keyless Ollama profiles, token pricing and EUR cost accounting, MCP connection health and per-server timeouts, and authenticated browser traffic ingestion with an optional extension.
- Import recon tooling and gated skills, benchmark and submission-review utilities, finding-evidence standards, and prompt-injection hardening; use the Norma 0.4.4 fork.
- Remove application self-update endpoints, components, and restart machinery. Local builds retain customizations; binary staging recognizes identical absolute and relative output paths.
- Preserve generated reasoning, provider summaries and opaque replay state separately. Redact task-vault passwords from accepted training samples while retaining raw private archives unchanged.

### OAuth-authenticated LLM profiles

- Run Claude Code, Codex and Antigravity subscription OAuth through the owned native executor; the app uses the authenticated nativeproxy API configured by `ARTEX_NATIVE_PROXY_URL` and `ARTEX_NATIVE_PROXY_TOKEN_FILE`. Keep login, PKCE/callback, refresh, account/project onboarding, cancellation, and disconnect on the native host; never call OMP OAuth or AuthStorage at runtime.
- Remove the retired owned Bun/OMP SDK bridge, its deployment unit, and bridge-only dependencies after native cutover. New connections use fresh human OAuth on the native host; no legacy grants are imported. Earlier bridge deployment records and captures remain historical evidence, while live native OAuth/refresh checks remain pending human validation.
- Use real per-provider native input codecs and preserve terminal response/state, signatures, encrypted reasoning, and the host-issued replay receipt in the v2 `provider_state` envelope. Store that envelope in `response_body.provider_state`; preserve API-key and Ollama transports unchanged.
- Include configured reasoning effort in native state and training metadata. Treat same-model thinking downgrades as distinct fallback choices, retain the branch across turns, and keep handoff provenance local rather than adding it to provider requests. Allow repeated model IDs at different effective efforts in profile settings; label inherited effort explicitly and reject duplicate effective choices, including the primary.
- Discover model-specific reasoning efforts from the local native catalog before login, reject unsupported explicit settings, and prevent stale model responses from changing another profile's options. Failed or canceled re-login preserves existing grants; disconnect drains active requests before deleting credentials.
- Request native Codex reasoning summaries with `reasoning.summary: "auto"` and Gemini thoughts with `includeThoughts: true` whenever thinking is enabled; preserve explicit disabled behavior and capture only provider-returned reasoning.
- Serialize OAuth grant expiry as RFC 3339 timestamps across the native host API so completed logins and saved connections decode correctly in ARTEX instead of reporting an unavailable login status.
- Refresh expired native grants directly before inference, independently of allocation polling. Preserve upstream quota and authorization failures as bounded HTTP 429/401/403 errors without exposing private provider error details.
- Keep local worker-chat deduplication markers out of provider inputs, and redact Go JSON-escaped task-vault secrets from accepted training samples while leaving original private captures intact.
- Normalize surrounding whitespace consistently when the native host and app read private bearer capability files; reject empty/whitespace-only files and retain private-file permission checks.
- Move the refusal fallback chain into each provider profile: an ordered, editable list of fallback models (with optional reasoning effort) tried on the same account, validated against the provider catalog, before the task's profile chain advances. The global refusal switch remains the master control.
- Show remaining 5-hour and 7-day subscription allocation with reset times in each subscription profile and on the main dashboard, read through native host usage endpoints with caching, 429 backoff, and stale-on-error display.
- Capture native Gemini thought summaries and opaque replay signatures from JSON/SSE, preserve signed multi-turn tool history, and export the actual native tool schemas. Summaries, open-weight reasoning traces, and opaque state remain distinct dataset types. Signatures are not recoverable chain-of-thought.
- Record provider refusals as `refused`, distinct from quota exhaustion and transport errors. Optional refusal fallback follows the task's customizable ordered profile chain and retries only the current model request before any answer or tool call is committed. When transitioning between models on a native chain, prior-model multi-turn history retains visible user and assistant text while historical tool interactions are converted into readable transcript text in the outbound request without opaque provider state or thinking signatures; uninspectable attachment blocks fail closed. Subsequent turns remain on the branch model and replay its new valid native state while separate sessions start on the primary model, and local trace request bodies capture explicit handoff metadata (`from_models`, `to_model`, `readable_history`, `prefix_count`). Already delivered output and executed tools are never replayed.

### English-only application

- Retain only English UI catalogs and documentation variants; remove language selectors and localized server/config message wrappers.
- Translate application-authored errors, notifications, role/tool metadata, editable built-in prompts, and conversation framing. Use English date formatting and native English mention kinds while retaining readers for historical mention syntax.
- Migrate only exact known shipped prompt/tool/trigger defaults. Preserve operator-custom values, tool bindings, limits, historical conversations, and all previous prompt versions.
- Write model approval reasons with `[Model]` while retaining classification and display support for historical `[模型]` records.
- Translate authored source comments into English, including embedded SQL, script heredocs, and Markdown code fences. Preserve non-comment code and literal legacy protocol data.

### Fixed

- Distinguish task report loading failures from empty reports and offer a retry button. Late responses from a previous task cannot replace the current task report.
- Standardize benchmark runner (`scripts/benchmark/run_bench.py`) authentication on valid session `ARTEX_TOKEN` or `/api/auth/login` session tokens via `ARTEX_PASSWORD`, removing obsolete raw `ARTEX_JWT_KEY` minting to match password-hash-derived JWT signing.
- Strengthen trace exporter test coverage in `deployment/test_export_traces.py` to exercise task credential scrubbing across open-weight reasoning, provider summaries, tool arguments, tool results, and text, ensuring corrupt snapshots fail closed and raw snapshots remain byte-for-byte unchanged.

#### Data loss and correctness (audit)

- **Behaviour change.** Archive compaction refuses to delete a host whose exchange count grew after the archive snapshot, and records the refusal as a task-archive warning. Captures taken while a package is compressing are no longer deleted from the hot store, so an archived task may retain traffic until a later cleanup.
- **Behaviour change.** A provider key taken from a saved LLM profile is now only ever sent to that profile's stored `base_url`. Testing a different endpoint requires supplying that endpoint's own key.
- **Behaviour change.** `traffic.json` in an archive package is written as a stream instead of being assembled in memory and marshalled. The structure and meaning are unchanged; field order differs and memory use drops from roughly six times the captured bytes to one exchange.
- **Behaviour change.** The tool-approval gate now denies when its rule set cannot be read — it keeps enforcing the last set that loaded, and refuses rather than allowing if none ever loaded. Previously a database outage silently let every call through.
- Credential re-saves with a blank password keep the stored one instead of overwriting the agent-generated secret with an empty string.
- Workspace uploads stage to a temporary name and rename on success, so a copy that fails partway no longer truncates the file already on disk.
- Failed captures (blocked, aborted, DNS failure) are recorded with status 0 and the transport error instead of being dropped by the browser extension, and are no longer rewritten to HTTP 200 by ingest.
- Exchange ids no longer wrap within one second, so a burst no longer overwrites already-stored captures.
- A task-delete staging journal records the task id, so a process exit between the PostgreSQL and SQLite commits is resolved on restart rather than leaving traffic orphaned.
- Skill-editor file reads are guarded against out-of-order responses, so a slow read can no longer save one file's contents into another.
- JSON request bodies are bounded at 8 MiB, with the skill-file route raised to its documented per-file limit; an unauthenticated oversized body no longer amplifies into gigabytes of heap.
- Exporter redaction covers scheme auth headers, `Cookie`/`Set-Cookie`, camelCase credential keys and URL-encoded task passwords; unparseable records are rejected rather than aborting the run, and `train.jsonl` is replaced atomically so a failed export leaves the previous dataset intact.
- Provider error bodies are bounded and scrubbed of credential shapes before reaching `llm_health.last_error` and `llm_records.error`, both of which are displayed in the UI.
- The worker conclusion read by the planner and `get_worker_output` reads newest-first, so a long tool-heavy run no longer reports that its worker produced no output.

#### Runtime failures found by running an engagement

- **Behaviour change.** The pcap ring is sized from the filesystem it writes to instead of a fixed 32 x 128 MB. On a 4096 MB `/state` quota the fixed ring was 4 GB: a live engagement reached 3.4 GB of capture, the volume hit zero bytes free, and ARTEX, PostgreSQL and the supervisor all went down with it. The ring now leaves a 1536 MB reserve, keeps the 32-segment value as an upper bound and a 4-segment floor, and the manifest records the ring actually used rather than the one requested.
- The built-in critical-path rule matched a bare `/` as its first alternative, so it denied any command where `rm` stood within 60 characters of an absolute path — an agent's own cookie-jar cleanup was rejected because `curl` later in the same line used `-D /dev/null`. The gap now excludes `;`, `&` and `|` so the path must belong to `rm`'s own simple command, and root matches only as a whole token. Existing databases are rewritten by `migrateCriticalPathRuleV5`, which touches only a row still holding the shipped bytes.
- Captured response bodies no longer end mid-rune. The capture bound is a byte count, so the cut landed inside a 3-byte character and PostgreSQL rejected the entire `llm_records` insert on that byte (SQLSTATE 22021), losing the record. The cut now backs off to a character boundary first.
- Tool output returned to the model is bounded at 8000 characters instead of the 30000 default. A live worker call carried 253 KB of tool results — 76% of a 341 KB request — and the transcript is re-sent every turn, so five oversized messages accounted for 22% of every request. The spill file still keeps the full output and the tool returns a head plus a pointer.

### Added

- **Enforced engagement boundary.** `scope` evaluates an asset against include/exclude rules and the tool guard refuses a call naming an excluded host, so the boundary is a decision rather than a sentence in the prompt. An exclusion always wins over a more specific include; among includes the longest pattern wins; an asset no rule mentions is `unknown`, never `out`, because a pasted scope table is routinely incomplete. `task_scope` gains an `effect` column and a row with `effect='exclude'` is enforced. `scope.Problem` rejects a rule that could never match an asset — a program's out-of-scope section is usually a mix of *where* and *what*, and filing "denial of service by flooding" as a scope rule leaves the engagement looking bounded when it is not. (`scope/`, `guard/scope.go`, `db/task_scope_check.go`)
- **Asset kind derived from the value.** `AddAutoScope` now decides whether a value is an apex, a subdomain, an IP or a CIDR from the value itself, keeping the caller's label as a hint. One host filed as both `domain` and `subdomain` made a boundary that matched neither. (`db/scope_kind.go`)
- **TOML manifest layer for external tools.** 32 manifests declare a tool's parameters, its argv template, how its output splits into records, and which record fields become an asset or a fact. The set is embedded in the binary, so a deployment cannot ship without it. `run_tool` executes a manifest-backed tool and returns parsed assets and facts; `list_tools` exposes the catalog. `GET /api/tool-manifests` serves the same declarations to the UI. Every manifest has a golden case in `manifest/testdata/golden/`, and `TestEveryManifestHasAGoldenCase` fails when a new tool ships without one. (`manifest/`, `server/manifest_tools.go`)
- **Finding evidence spilled to files.** Evidence above 8 KiB is written content-addressed under the evidence directory and referenced from `findings.evidence_path`, so a list query no longer carries megabytes of request bodies it never reads. Content addressing means the same evidence recorded twice writes one file, and the filename doubles as an integrity check. (`evidence/finding_evidence.go`, `findings.evidence_path`)

#### Regressions restored from the upstream base

Four behaviours that this fork had lost relative to its own base commit (`7f8c7cb`), each with the test that guards it:

- **Behaviour change.** `POST /api/skills` and `PUT /api/skills/{name}` emit YAML-quoted frontmatter values and re-parse the written file before answering. A description containing a colon, `#`, flow bracket, quote or comma used to produce unparseable YAML: every field after the metacharacter was dropped, the skill loaded under its directory name with an empty description, and a skill-gated MCP server was skipped without a word. A write that does not round-trip now returns 500 and is rolled back instead of landing silently. (`server/skill_frontmatter_test.go`, `server/shipped_skills_test.go`)
- **Behaviour change.** `GET /api/tasks/{id}` returns the same token and goal aggregates as `GET /api/tasks`. The detail response previously carried zeros, so a task page showed no spend and no goal progress until the separate stats poll resolved. (`server/task_detail_metrics_test.go`)
- **Behaviour change.** The `mcp_status` platform tool reports each MCP server's transport, enabled state, cached tool count and last connect outcome, so an agent can tell a broken server from one it never needed. It seeds on the next start and defaults to the Auto agent, like the other platform tools. (`server/platform_tools.go`)
- **Behaviour change.** Testing a saved LLM profile with the form's `streaming` field omitted now uses the profile's stored stream mode. A non-streaming profile tested from the list view was sent a streaming request and reported "no return text" for a provider that had answered correctly. (`server/llm_test_fallback_test.go`)

### Added

- **`privesc` skill** covering Linux and Windows escalation: enumeration order, sudo/SUID/capability escapes, service and cron misconfiguration, credential discovery, and the four-part proof standard for an escalation finding. Ships two generated indexes — `reference/gtfobins.json` (458 executables by escape class and context) and `reference/lolbas.json` (248 signed Windows binaries by category) — plus the PEASS-ng `linpeas.sh` release artifact, all usable offline at a pinned version. `scripts/build-indexes.py` regenerates the indexes from the upstream trees; provenance and checksums are in `reference/README.md`.


## [0.3.15-global.1] · 2026-10-14 · ARTEX-global transition release

The release that turns the Korean edition (`0.3.15-ko.1`) into ARTEX-global, a multilingual edition for defenders and researchers worldwide. Based on upstream ARTEX 0.3.15; no agent features were changed.

### Identity · multilingual (ARTEX-global rename)

- **Rebranded the ARTEX Korean edition as the ARTEX global edition.** The identity shifts from a region-specific edition to a multilingual edition that defenders and researchers worldwide can reach. No agent features were changed; only the multilingual layer and the docs were touched.
  - **Switched the default language from Korean to English.** User-facing output now defaults to English (bootstrap layer `config.DefaultLanguage`, web `DEFAULT_LOCALE`, `config.example.json`, and the `.env.example` comment); Korean, Chinese, and Spanish are selectable in Settings. The agent-package standalone fallback (`agent.defaultOutputLang`) and the Korean golden tests were left in place to avoid regressions.
  - **Reworded the identity strings to the global edition.** Replaced the "Korean edition" wording in the READMEs (Korean, English, Chinese), CONTRIBUTING, SECURITY, the maintainer runbook, and the issue/PR templates, and renamed the English README's "Why a Korean edition" section and its anchor (`#why-a-korean-edition` → `#why-a-global-edition`). The repository slug and image path are renamed to `artex-global` together in the 'Repository rename' section below in this release.

### English-first README and screenshots

- **Promoted the English README to the repository landing page.** The English document is now `README.md` (the first screen), the Korean body moved to a separate file that has since been removed, and the links and anchors from the root docs to the top-level README were rewired to English. The README links inside the detections tree were left as-is.
- **Replaced the preview screenshots with English ones.** Recaptured the mock UI in the default English and placed them under `screenshots/en/` (dashboard, findings, chat); the old Korean captures (`screenshots/ko/`) were removed.
- **Made on-screen dates follow the app language.** Replaced 18 hard-coded `ko-KR` locales with `getDateLocale()` in `web/src/i18n/datetime.ts` (display language → BCP47), so dates render in English by default.
- **Translated the demo data to English.** Translated ~220 user-facing Korean strings in the mock data (`web/src/lib/mock/{data,handler}.ts`) to English, preserving commands, payloads, URLs, and identifiers verbatim.

### Repository rename (artex-ko → artex-global)

- **Renamed the repository to `artex-global`.** Changed the GitHub slug to `jiwoochris/artex-global` (old URLs kept via GitHub redirects) and the container image path to `ghcr.io/jiwoochris/artex-global`. Replaced 126 occurrences across 37 files in the repo — badges, clone URLs, `docker-compose.yml`, `release.yml`, `install.sh`, docs, edition labels, detection-rule authors, the MISP event name. The upstream Go module (`github.com/Autumn-27/artex`) and the historical version tag (`0.3.15-ko.1`) were left unchanged.

### Localization (i18n)

- **Show built-in agent names and descriptions per language.** The built-in agents (goal decomposition, planning, main, execution, Auto, penetration test, vulnerability retest) are DB seed data (`builtinAgents` in `db/db.go` and the retest agent in `server/finding_retests.go`), so their names, descriptions, and prompt-variable labels used to appear only in Chinese. They are now looked up by agent `key` in `web/messages/` and shown in the current language (falling back to the DB value). User-created agents keep showing their DB values. Applied to the agent list, the editor drawer, and the chat screen; approval/intercept records that come from a chat now show the agent name instead of its internal key (e.g. `pentest`).

### Upstream sync

- **Model judge (fallback approval) token usage is reported separately (upstream 0.3.15, #191).** This upstream change was missing from 0.3.15-ko.1. Judge calls are metered as `worker=judge`, served by the new `GET /api/intercept/judge/usage`. Under the model judge switch in "System → Command interception", a card shows cumulative calls, input, output and cache read/write plus a 30-day daily bar chart.

### Security

- **Closed the remaining gaps in the #22 auth hardening.** A failed password-hash read was still folded into "no password" in token verification and in startup first-run handling, caching an empty hash. Token verification now refuses on a failed read, and startup skips env-var initialisation and setup-token issuance. `ARTEX_ADMIN_PASSWORD` initialisation is also stored once via `InsertSettingIfAbsent` and checked against the 72-byte limit. The `/setup` screen shows a retry notice instead of the form when it cannot confirm the state (the UI part of upstream #197).

## [0.3.15-ko.1] · 2026-10-12 · First Korean-edition release

The first release of the Korean edition, based on upstream ARTEX 0.3.15.

### Distribution

- **The Korean-edition Docker image is now published.** Upstream's `autumn27/artex` image was taken down from Docker Hub, which broke the `docker compose up -d` quick start. Each release tag now pushes a multi-architecture (amd64/arm64) image to `ghcr.io/jiwoochris/artex-global`, and `docker-compose.yml` pulls that image.

### Security

- **Blocked remote takeover of the first-run admin account.** An instance without a password accepted `POST /api/auth/init` unauthenticated, so whoever reached the port first could set the admin password and obtain a JWT (privately reported by Dangel). Initialisation now requires the setup token (`setup_token`) printed only on the server console at startup, and wrong attempts are rate-limited. Added `ARTEX_SETUP_TOKEN` and `ARTEX_ADMIN_PASSWORD` for unattended deployments and a token field on the `/setup` screen.
- **Default bind address is now 127.0.0.1.** The `artex -addr` default moves from `:8787` to `127.0.0.1:8787`, and `docker-compose.yml` publishes 8787 as `${ARTEX_BIND:-127.0.0.1}`. Deployments reached from other machines must pass `-addr :8787` or set `ARTEX_BIND=0.0.0.0` in `.env`. Starting without a password on a non-loopback address logs a warning.
- **Changing the password invalidates every existing token.** The JWT signing key is derived from the password hash, so a change through the UI, `reset-password.sh`, or a direct DB edit ends earlier sessions. Users must log in once after upgrading. The change-password response carries a fresh token so the current browser session continues.
- **Replaced wildcard CORS with an allowlist.** Instead of `Access-Control-Allow-Origin: *`, headers are only sent for origins in `ARTEX_CORS_ORIGINS` (default: `next dev` at `http://localhost:5173`). Also added server-side minimum password length (8) and audit logs for failed initialisation/login attempts (with client address).
- **Ported the authentication hardening from upstream ARTEX 0.3.15.** Password-setting reads now fail closed with 503 instead of reporting `initialized:false` (`authStatus`, `authInit`, `authLogin`, change-password). First-time setup is atomic via `INSERT ... ON CONFLICT DO NOTHING` ([`db.InsertSettingIfAbsent`](db/settings.go)), so the primary-key constraint protects the existing value even when the read check is unreliable. Passwords over 72 bytes are rejected with 400 instead of 500, and a database connection-pool cap (32) reduces the path where a `too many clients` error can masquerade as a read failure. Ported to match upstream commit `a951e4a` (0.3.15); only the parts not already covered by PR #20 were added.

### Localization (i18n)

- **Added switching to English, Chinese and Spanish.** Korean remains the default. Picking a language under "Display language" in Settings switches the web UI (`web/messages/{ko,en,zh,es}.json`), agent-written reports, summaries and chat replies, and server error messages and status labels together. Operator console logs and the server default followed the configured language. The agent's behavioural-instruction body is still left in its original language.
- **Forced user-facing output into Korean.** The benchmarked agent's behavioral-instruction body (the "brain") is left in its original language to preserve performance, and a code-level fixed segment (`langDirective`) instructs the agent to write only the user-facing output (vulnerability reports, fact summaries, final summaries, chat replies) in Korean. Commands, payloads, code, and raw logs are kept in their original form.
- **Translated the web UI into Korean.** Introduced `next-intl` into the Next App Router and split the strings into `web/messages/ko.json` and `web/messages/zh.json`. The original Chinese is preserved in `zh.json` so that it can be compared against upstream updates. Screen strings for the dashboard, vulnerabilities, chat, notification delivery, interception, LLM settings, and more were translated into Korean.
- **Translated the server API's user-facing errors and responses into Korean.** HTTP error and response text that is returned to the browser was replaced with Korean. Text that feeds back into the agent brain as input, however, was kept in its original language to prevent benchmark drift, and the reasoning behind each such decision is recorded in the repository's working documents.
- **Reorganized the documentation in Korean.** Created a Korean `README.md`, kept an English `README.en.md` alongside it, and preserved the original Chinese as an upstream-preserved file.

### Defense and detection resources

- **Added a defense and detection guide.** An English guide ([`docs/defense-en.md`](docs/defense-en.md)) that covers how an autonomous AI attack differs from a traditional scanner, the fingerprints (IoCs) a defender can observe, entry points and hardening, detection rules, and incident response.
- **Provides deployable detection rules.** The guide's fingerprints were turned into rules you can use directly. The host and log layer is covered by [Sigma](https://sigmahq.io) atomic and correlation rules ([`detections/sigma/`](detections/sigma/)), and the network layer by [Suricata](https://suricata.io) rules ([`detections/suricata/`](detections/suricata/)) that target the enrich prober and norma SDK WebFetch User-Agents.
- **Visualized ATT&CK coverage.** The techniques that the rules tag were organized into a MITRE ATT&CK Navigator layer ([`detections/attack/`](detections/attack/)).
- **Provides machine-readable indicators of compromise (IoCs) in standard formats.** The unique fingerprints that ARTEX emits were collected into a single CSV ([`detections/indicators/artex_indicators.csv`](detections/indicators/artex_indicators.csv)), along with a MISP event ([`detections/indicators/artex_indicators.misp.json`](detections/indicators/artex_indicators.misp.json)) carrying the same indicators that can be imported straight into a threat-intelligence platform. Indicators that a rule backs are marked with `to_ids`, while host-forensic ports are marked separately as triage clues.
- **Attached reproducible detection tests.** Eight test suites prove the rules by actually running them (Sigma structure and compilation checks, Sigma live event-matching, backend portability, SigmaHQ convention lint, Suricata load and firing, ATT&CK layer consistency, indicator-to-source matching, and MISP export ↔ CSV synchronization). A batch runner that runs them all at once and a pre-commit example were added and wired into the CI merge gate. Sigma live event-matching confirms that the rules not only compile but actually fire on malicious sample events and stay silent on benign ones, for both the atomic and the correlation rules.

### Repository hardening

- **Added security and misuse warnings and Korean legal notices.** The scope of use, notices under the Network Act and the Personal Information Protection Act, and a misuse-prohibition warning were added at the top of the README.
- **Replaced the screen preview with Korean UI screenshots.**
- **Set up a maintainer runbook and a contributing guide.** Added a runbook ([`MAINTAINING.en.md`](MAINTAINING.en.md)) for preventing upstream-sync and translation drift, and a detection-rule contribution contract ([`CONTRIBUTING.en.md`](CONTRIBUTING.en.md)). The runbook also documents the release pipeline's build assumptions and how to verify them locally without a tag.
- **Added push/PR merge-gate CI.** The upstream repository ran CI only on tag releases, but this fork runs — on every push and pull request — a Go build, static analysis (`go vet`), and unit tests ([`ci.yml`](.github/workflows/ci.yml)); a Korean UI static build ([`web.yml`](.github/workflows/web.yml)); and integrity checks for the documentation's repository-internal links and image references ([`docs.yml`](.github/workflows/docs.yml)), catching regressions introduced during localization before they merge. Integration tests that require a database are verified alongside a PostgreSQL service isolated per package. The documentation link check runs as a deterministic script ([`scripts/check-doc-links.py`](scripts/check-doc-links.py)) that does not depend on an external network, so the many relative links the multilingual documents point at one another — and the screen-preview images — cannot merge while broken. Documentation anchor (`#heading`) links are also checked against headings using the same slug rules as GitHub, catching table-of-contents and cross-reference links that silently break when heading text changes. The detection-rule suite is handled by the merge gate described in the "Defense and detection resources" section above.
- **Periodically checks external-link liveness.** External links the documents point at — the defense guide's incident-reporting channels and standards references — depend on remote server state and are flaky, so they are kept out of the merge gate; instead a non-blocking workflow ([`external-links`](.github/workflows/external-links.yml)) runs a browser-User-Agent, GET, redirect-following check ([`scripts/check-external-links.py`](scripts/check-external-links.py)) every Monday and on manual dispatch. A host that is alive but blocks the check method (bot protection, rate limiting) and upstream-inherited dead links we cannot fix (an allowlist) are not counted as failures, so it turns red only when an external link our documents curate newly breaks.
- **Established contribution and governance infrastructure.** Added bug and feature issue templates ([`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/)) and a pull-request template ([`PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)), a security-vulnerability reporting policy ([`SECURITY.en.md`](SECURITY.en.md)), and a code of conduct ([`CODE_OF_CONDUCT.en.md`](CODE_OF_CONDUCT.en.md)), so that external contributors submit issues, PRs, and security reports in a consistent format.
- **Completed an English documentation layer for overseas contributors.** This repository is Korean-first, but English versions of the core documents are provided so that contributors, security researchers, and defenders who do not read Korean can reach the same information. In addition to the English README and the defense guide ([`docs/defense-en.md`](docs/defense-en.md)), there are English versions of the changelog ([`CHANGELOG.en.md`](CHANGELOG.en.md)), the security reporting policy ([`SECURITY.en.md`](SECURITY.en.md)), the code of conduct ([`CODE_OF_CONDUCT.en.md`](CODE_OF_CONDUCT.en.md)), the contributing guide ([`CONTRIBUTING.en.md`](CONTRIBUTING.en.md)), the maintainer runbook ([`MAINTAINING.en.md`](MAINTAINING.en.md)), the traffic-evidence design document ([`docs/finding-traffic-evidence-en.md`](docs/finding-traffic-evidence-en.md)), and the bug and feature issue templates.

---

The upstream ARTEX project's per-version release history and contributor list can be viewed verbatim in the upstream repository.

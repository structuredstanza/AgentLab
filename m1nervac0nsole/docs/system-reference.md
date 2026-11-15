# System reference

The operational picture of m1nervac0nsole: what runs where, what talks to what, what is stored, and what breaks. It is written for an engineer who has the repository and wants the system without reading every package. For repository policy and commands, `AGENTS.md` is authoritative; this document explains the machine.

## 1. What this is

m1nervac0nsole is an autonomous multi-agent penetration-testing console. An operator states a goal and a scope; a planner decomposes it into intents; workers execute real tools against authorized targets and write facts, assets and findings back; a main agent answers the operator and can drive a browser. PostgreSQL is the system of record. The Next.js UI is statically exported and embedded in the Go binary, so a deployment is one file plus a database.

It is an AGPL-3.0 fork of upstream m1nervac0nsole. The rebrand is presentation-only: environment variables, the database name, the binary name and forensic identifiers remain compatibility contracts.

## 2. Topology

```
host                          sandbox (microsandbox VM)
  ./lab  ------------------>  guest-start.py (supervisor)
  state/  <--mount /state-->    PostgreSQL          127.0.0.1:5432
  guest-dist/ <-/dist:ro-->     execbox supervisor  /run/m1nervac0nsole/execbox.sock
  secrets/ <-/run/secrets-->    m1nervac0nsole      0.0.0.0:8787  (UI + API)
                                recording proxy     127.0.0.1:8788
                                masking egress      127.0.0.1:8888
                                tcpdump, strace, openvpn (optional)
```

Only `127.0.0.1:8787` is published to the host. Everything else is loopback inside the sandbox.

The host never runs application code. `lab` builds the binary and skills into `deployment/guest-dist/`, mounts it read-only at `/dist`, and the guest copies from it at every start. A source change reaches the VM on the next `./lab start`; the image's baked copies are only the fallback for a sandbox created before that mount existed.

## 3. Request path

```
browser -> /api/* -> server.Handler() -> Manager (lifecycle) -> Engine (per task)
        -> agent roles (planner, workers, main agent)
        -> tools -> execbox session -> recording proxy -> gateway -> target
        -> PostgreSQL (facts, assets, findings, activity, llm_records)
```

Every API response goes through `writeJSON` or `writeErr`. Every tool call passes the safety pipeline before it runs: base tool set, then `ToolAugment` (skills, MCP), then `ToolResolve` (database overrides), then the alias and panic wrapper, then harness hooks (`guard` audit, `intercept` allow/deny/ask, `scope` boundary).

## 4. Packages

| Path | Responsibility |
|---|---|
| `cmd/m1nervac0nsole/` | Binary entry, plus the `egress-proxy` and `execbox serve\|probe` subcommands |
| `server/` | HTTP API, `Manager`, `Engine`, LLM wiring, auth, scheduler, DTOs |
| `agent/` | LLM roles, prompts, tool surface, provider construction, capture |
| `db/` | PostgreSQL stores and the embedded idempotent `schema.sql` |
| `traffic/` | Recording proxy addon: file tree plus a SQLite index; streamed bodies spool to content-addressed blobs |
| `netpolicy/` | Session identity and destination authorization |
| `gateway/` | The origin transport every recorded request dials through |
| `execbox/` | Privileged supervisor that runs each tool session unprivileged in its own namespaces |
| `intercept/`, `guard/`, `scope/` | The tool-call safety pipeline; protected surfaces |
| `egress/`, `enrich/`, `limits/`, `useragent/` | Masking proxy, asset auto-completion, outbound rate policy, shared identity |
| `llmpool/`, `llmrec/`, `nativeproxy/`, `mcphttp/` | LLM transport decorators and MCP clients |
| `manifest/` | Declarative TOML tool manifests, embedded and overlaid by the `tool_manifests` table |
| `report/`, `evidence/` | Deterministic report rendering; content-addressed evidence |
| `web/` | Next.js App Router frontend, statically exported |
| `third_party/norma/` | Vendored agent SDK, a nested module with local changes |

**The web layer.** `web/` is a Next.js App Router application, statically exported (`NEXT_EXPORT=1 next build`) and embedded into the Go binary behind the `embedui` tag; without that tag the binary serves 404 for the UI. Route groups are `(auth)` for login and setup, `(main)` for the console, and `(external)` for pages reachable outside the shell. Every backend call goes through `web/src/lib/api.ts` and `web/src/lib/types.ts`; a component never fetches ad hoc, and local state lives in hooks and `localStorage`. The English-only edition has one catalog, `web/messages/en.json`, and `scripts/check-cjk.py` fails CI on Hangul, Han and CJK punctuation in authored source. The visual system is fixed in `web/src/app/globals.css` with locally packaged Manrope and DM Mono; there are no theme, preset or font preferences, and only the sidebar open state is configurable. Tests live in `web/tests/`, mirror `src/`, import via `@/...`, and mock `next-intl`, `sonner` and `@/lib/api`. Gates: `npm run build:static`, `npm run test -- --run`, `npm run check`.

## 5. The network boundary

There is one outbound HTTP boundary, and it is not optional.

- A run's proxy URL carries a `netpolicy` session credential. A request without one is refused, never dialled direct.
- The recording proxy (`traffic/`) sees the request and writes the file tree plus the SQLite index.
- Its origin side is the `gateway` transport: it authorizes against the session, resolves and pins the address, runs a uTLS Chrome handshake with strict verification, applies the operator exit, and tags its own failures with `X-M1nervac0nsole-Gateway`.
- Tool processes run unprivileged in their own network namespace via `execbox`. The namespace admits only the gateway and the resolver. A session's writable roots are the task and session workspaces; `/tmp` is a private tmpfs that dies with the session and is never the host's.
- A masking `egress-proxy` survives for asset-enrichment probes only. With neither `M1NERVAC0NSOLE_EGRESS_PROXY` nor `M1NERVAC0NSOLE_EGRESS_CA`, enrichment fails closed rather than dialling direct.

Authorization is per task. A scope rule is a grant only after the operator approves it, and every policy change moves the task's policy revision so cached verdicts and pooled connections stop being trusted.

## 6. Data model

PostgreSQL is authoritative. `db/schema.sql` is applied on every start, is idempotent, and migrates additively with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` under an advisory lock.

**Asset graph** — `companies`, `assets` (root_domain, ip, subdomain, app, service, endpoint, with partial unique indexes per type), `company_scope`, `task_asset_links` (provenance for the legacy `assets.task_ids` array).

**Exploration graph** — `explorations`, `exploration_nodes` (goal, intent, fact, finding, digest), `exploration_edges`, `exploration_anchors` (joins a node to an asset), `task_constraints`, `activity` (the transcript: tool_use, tool_result, result, text), `main_sessions` (resettable main-agent segments).

**Tasks** — `tasks`, `task_categories`, `task_templates`, `task_relations`, `task_archives`, `task_scope`, `task_scope_rules` (the authorization surface), `task_intercept_rules`, `task_credentials`, `task_llm_profiles`, `plan_drafts`.

**Findings** — `findings`, `finding_retests`, `traffic_evidence_snapshots`, `finding_traffic_bindings`. Evidence above the inline limit is content-addressed under the evidence directory and referenced, so a list query never carries megabytes it does not read.

**LLM** — `llm_profiles`, `oauth_grants`, `llm_profile_health` (circuit breaker with exponential cooldown), `llm_records` (raw wire bodies), `llm_usage` (dimensions only, never content).

**Memory** — `knowledge_entries` (scopes global/environment/company/task, full-text), `knowledge_usage`, `task_reflections` (per-task reflection pool), `rsi_lessons`, `rsi_lesson_evidence`, `rsi_lesson_usage`.

**Operations** — `settings`, `agents`, `agent_prompts`, `agent_prompt_vars`, `agent_triggers`, `mcp_servers`, `mcp_tools_cache`, `agent_visibility`, `agent_skill_visibility`, `skill_usage`, `tool_usage`, `tools`, `tool_manifests`, `intercept_rules`, `intercept_pending`, `asset_intercept_rules`, `notification_channels`, `notification_events`, `notification_deliveries`, `server_logs`, `policy_audit`, `cert_exceptions`, `api_tokens`, `mcp_audit`, `conversations`, `conversation_activities`, `side_question_sessions`, `side_question_requests`, `scheduler_state`.

Two tables deliberately have no foreign keys: `llm_usage`, `skill_usage` and `tool_usage` must survive the deletion of the task they describe.

## 7. The engine and agent roles

`Engine.Run` starts one planner loop, N worker loops (`workers` setting, default 3) and a deadline coordinator. The planner is the sole intent producer. A worker claims one intent, executes real tools, and writes facts, assets and findings back. When only a human can unblock the engagement, the planner calls `report_blocked`, which parks the task in `needs_operator` with a `blocked_reason` until the operator resumes it.

Roles: planner (decomposes and re-plans), worker (executes one intent), main agent (operator conversation, can drive the browser), chat (conversation without a task), retester (manual retest session), tool curator (proposes and installs tools behind approval).

Cancellation uses `context.WithCancelCause` plus a named `agent.AbortCause`, read back with `agent.AbortReason`. State lives in the `Manager` and `Engine` behind mutexes and is read through lifecycle snapshots.

## 8. Tools

Three kinds, one contract:

- **Manifest tools** — TOML in `manifest/builtin/` (32 shipped: nmap, nuclei, ffuf, sqlmap, hydra, masscan and others), overlaid at run time by the `tool_manifests` table. Adding one requires a golden case under `tests/go/manifest/testdata/golden/`.
- **Database tools** — seeded in `agent/toolcatalog.go`, handler in code.
- **Custom script tools** — written by the operator or the agent, executed by the backend.

Tools run inside an `execbox` session. Their working directory is a task workspace or the session's private `/tmp`. Their environment carries the proxy URL with the session credential.

Installation is approval-gated: `toolbox_install` runs in an install-purpose session, stages into a writable prefix, and the supervisor publishes the result into the persistent toolbox `bin/` with a temp name and a rename, owner root, mode 0755. The published artifact's path, size, install time and SHA-256 are reported on the manifest row. The install's process capture carries the tool call that caused it (`Origin: tool` plus its `tool_use_id`) when the curator triggered it, and `Origin: operator` with no id when the operator started it from the Toolbox, so an install is always attributable to whatever actually ran it.

## 9. Memory

`db/knowledge.go` holds a full-text knowledge base with scopes `global`, `environment`, `company`, `task`. `db/reflection.go` and `db/reflect_engine.go` derive a per-task reflection pool at intent end and task end. `db/scrub.go` scrubs credentials and target identifiers on every write.

Agents use `recall`, `knowledge_add` and `reflect`. `server/memory.go` builds the start-of-task block (adopted `environment` entries are always included) and the per-round provider (`M1NERVAC0NSOLE_MEMORY=off|inject`). An agent's writes are task-private candidates, generalized on write; only an owner promotes one. `knowledge_usage` records what was actually read back, so "refine the memory" is not guesswork.

## 10. Capture and evidence

`traffic/` is a go-mitmproxy addon. It writes a file tree plus a SQLite index, and nothing else: graphs, tasks, findings and LLM records live in PostgreSQL.

A captured exchange carries its URL, method, status, headers, body and the run's identity. Streamed bodies (SSE, WebSocket, large bodies) are spooled to content-addressed blobs with no per-exchange cap; the only bound is the capture filesystem reserve, which `guest-start.py` owns and hands to the recorder by environment. When the reserve trips, or the filesystem cannot be measured, capture stops and the stored head is labelled, never dropped silently; forwarding is unaffected.

A WebSocket exchange carries a JSONL transcript as its body: a header line stating that ordering is proxy-arrival order and that ping/pong are not observable, then one line per data frame (sequence, direction, text or binary, length, base64 payload) and one close line per direction with its code, reason or error. The stored body length is the transcript's length on disk, so archive, evidence and restore compare the same bytes; payload totals live in the capture marker. A session is labelled partial when a direction ended with a real transport error, or when no close frame was seen at all. The proxy closes one side as soon as the other ends, so a `use of closed network connection` error is that teardown and decides nothing; the direction that reported the real cause does. Close codes 1005 and 1006 are local reports of a torn-down connection, never an agreement between the peers.

`evidence/` pins finding evidence blobs independently of the disposable traffic store, so deleting traffic does not destroy a finding's proof.

`deployment/guest-export.py` produces a timestamped archive with a manifest of SHA-256 hashes; `./lab export` runs it. The archive is the training-data artifact, so it carries the raw request and response bodies, the provider's wire bodies, and the host event log.

## 11. Safety boundaries

- `scope/` decides whether a destination is inside the operator's authorization. It is consulted before a tool runs.
- `intercept/` decides whether a call needs approval, and parks it in `intercept_pending` when it does.
- `guard/` audits and can block. Its refusal prefix is a neutral platform-control marker, `[platform control - not target defense]`, so an agent can tell a platform block from a target-side defense.
- `netpolicy/` decides whether the network will authorize the destination at all, independently of the tool layer.

These three are protected surfaces: a change to them is a change to the authorization boundary.

## 12. Configuration

| Variable | Effect |
|---|---|
| `M1NERVAC0NSOLE_CONFIG` | Path to `config.json` |
| `M1NERVAC0NSOLE_PG_DSN` | PostgreSQL DSN; there is no built-in fallback and startup fails loudly |
| `M1NERVAC0NSOLE_SKILL_DIR` | Skill directory |
| `M1NERVAC0NSOLE_MEMORY` | `off` or `inject` for the per-round memory provider |
| `M1NERVAC0NSOLE_EGRESS_PROXY`, `M1NERVAC0NSOLE_EGRESS_CA` | Masking proxy for enrichment probes |
| `M1NERVAC0NSOLE_MAX_CONCURRENT_SCANS`, `..._MAX_SCANS_PER_TARGET`, `..._MAX_REQUESTS_PER_MINUTE` | Outbound rate policy |

Runtime toggles are rows in the `settings` table, read per run.

## 13. Operation

```sh
./lab start [--vpn PROFILE]   # build guest-dist if stale, create or reuse the sandbox, start the stack
./lab status                  # health, processes, capture state
./lab primary                 # rewrite deployment/provenance.json
./lab export                  # timestamped archive with a hash manifest
./lab exec -- bash -lc '...'  # run a command in the guest
./lab stop                    # stop the stack and the sandbox
```

Never start two VMs against the shared `state/`; `./lab start` refuses while another running sandbox exists. Use `./lab stop` rather than a force-kill.

## 14. Verification

| Gate | Command |
|---|---|
| Go build and vet | `cd m1nervac0nsole && go build ./... && go vet ./...` |
| Go tests | `go test -p 1 ./... -count=1 -timeout 2400s` (serial: DB suites share one database) |
| Web typecheck and build | `npm run build:static` |
| Web tests | `npm run test -- --run` |
| Web lint | `npm run check` |
| ASCII gate | `python3 scripts/check-cjk.py` |
| Doc links | `python3 scripts/check-doc-links.py` |
| Host suites | `tests/run.sh [all\|go\|proxy\|python\|web]` |
| Capture | `python3 deployment/verify_capture.py` |
| Completeness | `python3 deployment/verify_completeness.py` |
| Reasoning | `python3 deployment/verify_reasoning.py` |

DB-backed Go suites silently `--- SKIP` without `M1NERVAC0NSOLE_PG_DSN`, so a green local run can still fail CI. Root-only kernel tests report `BLOCKED` on the host and must run in the guest.

## 15. Known traps

- **The guest runs the host build, and only a restart deploys it.** `./lab start` on an already-healthy sandbox rebuilds `/dist` but leaves the running supervisor and its copied `/state/runtime` binary in place, so the old build keeps serving. Use `./lab stop && ./lab start`; the image's baked copies are only a fallback.
- **A rebuilt image is not the historical image.** `./lab image-build` rebuilds the configured tag from this repository and validates its capabilities; it does not reproduce the 2026-11-11 bytes.
- **No host-reachable surface mints a `netpolicy` session.** `Manager.IssueSession` and `ToolProxyURL` are in-process only. The capture verifier therefore drives `POST /api/tools/custom/test`, which mints and revokes a session server-side, instead of borrowing a credential.
- **The capture reserve has one authority.** `deployment/guest-start.py` computes it (20% of the volume, floor 1536 MiB, overridable with `AGENTLAB_CAPTURE_RESERVE_MB`/`_PCT`) and passes it to the recorder as `M1NERVAC0NSOLE_CAPTURE_RESERVE_MB`/`_PCT`. The recorder's own constants are only the standalone default for a run outside the lab.
- **Streamed bodies are not full-text indexed.** The stored head is indexed and the body is reachable through `traffic_get` and `traffic_blob`.
- **A child target Chromium refuses to intercept is released, never silently trusted.** If Chromium rejects `Fetch.enable` for a target type (iframe, worker, shared worker, service worker), the driver releases that target and the gateway is the enforcing layer; the excluded origin is still never contacted. Any other setup failure closes the target instead of resuming it.
- **Task deletion and archival select by task id, never by host.** A task operation removes only rows whose `task_id` matches and journals the exact exchange IDs, so a crash replay cannot widen to a host. Rows recorded before attribution (NULL `task_id`) and the legacy per-host tree are untouched by a task operation; only an explicit host or all delete removes them.
- **The web `.gitignore` ignores `*.sh`**, so a new script under `web/` is silently untracked.
- **The root `.gitignore` is deny-by-default.** Only `README.md`, `AGENTS.md`, `lab`, `deployment/`, `m1nervac0nsole/`, `.github/` and `tests/` are published; search tools that honour it silently miss the rest.

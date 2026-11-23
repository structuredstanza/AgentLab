# Repository Guidelines

## Project Overview

AgentLab is a private two-layer monorepo at `/mnt/Research/AgentLab`:

- **Root layer** — the lab/capture environment: `lab` (stdlib Python CLI driving a microsandbox VM), `deployment/` (guest image, host provider proxy, export + verification scripts), and local-only runtime state (`state/`, `exports/`, `proxy-state/`, `secrets/`).
- **`m1nervac0nsole/`** — the application under development: m1nervac0nsole, the m1nervac0nsole-based autonomous LLM multi-agent penetration-testing console. Go backend (`module github.com/structuredstanza/AgentLab/m1nervac0nsole`, `go 1.26.3`) + Next.js 16 frontend statically exported and embedded into the single binary. PostgreSQL is the system of record. The rebrand is presentation-only: m1nervac0nsole environment, authentication, database, binary and forensic identifiers remain compatibility contracts.

AGPL-3.0 fork of upstream m1nervac0nsole; do not replace the customized deployment with a stock upstream release. The tool is offensive-security software: verification work targets local fixtures or explicitly authorized scope only (`m1nervac0nsole/CONTRIBUTING.en.md`).

## Architecture & Data Flow

```
Next.js SPA (embedded) → /api/* → server.Handler() mux → Manager/Task/Engine
  → agent (Planner/Worker/MainAgent) → db stores (PostgreSQL) → JSON/SSE
```

- **Entry point**: `m1nervac0nsole/cmd/m1nervac0nsole/main.go` (`run()`). Wiring order: `server.NewManager` -> `server.New` -> `srv.Handler()`.
- **Recorded HTTP boundary** (see `m1nervac0nsole/docs/design/network-layer.md`): recorded tool traffic goes through the recording proxy (`traffic/`, `-proxy`, default `127.0.0.1:8788`) and then the `gateway/` transport. The gateway authorizes from a backend-issued `netpolicy` session before dialling, resolves and pins the address, runs a uTLS Chrome handshake with strict verification, applies the operator exit, and tags its own failures with `X-M1nervac0nsole-Gateway`. The proxy URL carries the run's credential (`netpolicy.ProxyURL`); a request without one is refused, never dialled direct. Tool processes run unprivileged in their own network namespace via `execbox/`; relay-only sessions admit only the gateway and the resolver. Asset enrichment uses per-probe recorder sessions and fails closed if the recorder is unavailable.
- **Per task**: `Engine.Run` (`server/engine.go:783`) starts 1 planner loop + N worker loops (`workers` setting, default 3) + deadline coordinator. Planner is the sole intent producer; workers claim one intent, execute real tools, write facts/assets/findings back. When only a human can unblock the engagement the planner calls `report_blocked`, which parks the task in `needs_operator` with a `blocked_reason` until the operator resumes it.
- **Dual graph**: global asset graph (`db/assets.go`, shared, program-computed hierarchy) and per-task exploration graph (`db/exploration.go`, goals/intents/facts/findings), joined by `exploration_anchors`.
- **Memory**: `db/knowledge.go` (full-text knowledge base, scopes `global|environment|company|task`), `db/reflection.go` + `db/reflect_engine.go` (per-task reflection pool, engine-derived at intent and task end), `db/scrub.go` (credential and target-identifier scrubbing on every write). Agents use `recall` / `knowledge_add` / `reflect` (`agent/tools_memory.go`); `server/memory.go` builds the start-of-task block (adopted `environment` entries always included) and the per-round provider (`M1NERVAC0NSOLE_MEMORY=off|inject`). Agent writes are task-private candidates, generalized on write; only an owner promotes. See `RSI.md`.
- **Agent SDK**: vendored `m1nervac0nsole/third_party/norma/` via `replace` in `go.mod` — `agentcore` (Session/Options), `harness` (turn loop), `llm` (Provider `Stream`/`Complete`), `tool` (CoreTool).
- **Decorator chains, not DI**: provider = `agent.Config` → optional `nativeproxy` → `llmrec` recorder → `llmpool.Pool` failover. Tools = base set → `ToolAugment` (skills/MCP) → `ToolResolve` (DB overrides) → alias/panic wrapper → harness hooks (`guard` audit, `intercept` allow/deny/ask, `scope` boundary).
- **Capture**: `traffic/` is a go-mitmproxy addon writing a file tree plus a **SQLite index only** (`traffic/traffic.go:194`); graphs/tasks/findings/LLM records live in PostgreSQL. `evidence/` pins finding evidence blobs independently of disposable traffic.
- **State ownership**: PG authoritative; in-memory mirrors in `Manager`/`Engine`/`Server` guarded by mutexes and read through lifecycle snapshots. Runtime toggles are rows in the `settings` table, read per run.

## Key Directories

| Path | Purpose |
|---|---|
| `m1nervac0nsole/cmd/m1nervac0nsole/` | Binary entry + `execbox serve\|probe` subcommands |
| `m1nervac0nsole/server/` | HTTP API, `Manager`, `Engine`, LLM wiring, auth, scheduler |
| `m1nervac0nsole/agent/` | LLM roles, prompts, tool surface, provider construction |
| `m1nervac0nsole/db/` | PostgreSQL stores + embedded `schema.sql` (idempotent, advisory-locked migration) |
| `m1nervac0nsole/traffic/`, `intercept/`, `guard/`, `scope/` | Recording MITM proxy; tool-call safety pipeline |
| `m1nervac0nsole/netpolicy/`, `gateway/`, `execbox/` | Session identity and destination authorization; the origin transport every recorded request dials through; the privileged supervisor that runs each tool session unprivileged in its own namespaces |
| `m1nervac0nsole/enrich/`, `limits/`, `useragent/` | Engine-side asset auto-completion; concurrent tool-run limits; shared outbound identity |
| `m1nervac0nsole/llmpool/`, `llmrec/`, `nativeproxy/`, `mcphttp/` | LLM transport decorators, host proxy client, MCP clients |
| `m1nervac0nsole/manifest/` | Declarative TOML tool manifests: `builtin/*.toml` (embedded) overlaid at run time by the `tool_manifests` table (Toolbox page) |
| `m1nervac0nsole/third_party/norma/` | Vendored agent SDK (separate module `github.com/structuredstanza/norma`, from BaaRai/Norma v0.4.6 plus local changes) |
| `m1nervac0nsole/third_party/go-mitmproxy/` | Pinned go-mitmproxy v1.9.2 copy plus the `OriginTransport` hook; `PATCH` names the base tag and every hunk. Bumping upstream is a three-way merge, never a copy |
| `m1nervac0nsole/web/` | Next.js App Router frontend (`src/app`, `src/lib`, `src/components`) |
| `m1nervac0nsole/skills/`, `docs/` | Agent skills, design docs |
|`deployment/`|Guest `Dockerfile`(+`.toolchain`), `sandbox.yaml`, `guest-start.py`, `export_traces.py`, `verify_capture.py`, `verify_completeness.py`, host proxy (`cliproxy/`), and `guest-dist/` (the host build mounted read-only at `/dist`, generated by `./lab build`); `README.md` is the deployment reference|
| `tests/` | Umbrella runner + Python suites (black-box Go suites are in `m1nervac0nsole/tests/go/`) |
| `.github/` | GitHub Actions workflows (ci, web, docs, external-links, release) and issue/PR templates; jobs run from `m1nervac0nsole/` |
| `m1nervac0nsole/graphify-out/` | Generated knowledge graph of `m1nervac0nsole/` (gitignored; query it, don't rebuild) |

## Development Commands

All Go/web commands run **inside `m1nervac0nsole/`** — there is no module, Makefile, or `package.json` at the root.

```sh
# Go
cd m1nervac0nsole && go build ./... && go vet ./...
go test ./agent/ -count=1
go test -p 1 ./... -count=1 -timeout 2400s        # serial: DB suites share one database

# Web
cd m1nervac0nsole/web && npm ci
npm run build:static     # NEXT_EXPORT=1 next build — the TypeScript/merge gate
npm run test -- --run    # vitest (merge gate)
npm run check            # biome check (CI gate; use check:fix to autofix)

# Umbrella suites (from repo root)
tests/run.sh [all|go|proxy|python|web|dev]

# Full binary (embeds UI; requires the static export first)
cd m1nervac0nsole && M1NERVAC0NSOLE_COMPRESS=off ./build.sh --target linux/amd64
./dev.sh                 # backend :8787 + recording proxy :8788 + next dev :5173

# Lab VM (host control plane)
./lab start [--vpn PROFILE] | status | export | stop
./lab exec -- bash -lc '...'
```

- DB integration tests in `agent config db evidence guard intercept llmrec server` **silently `--- SKIP`** without `M1NERVAC0NSOLE_PG_DSN` (e.g. `postgres://m1nervac0nsole:m1nervac0nsole@localhost:5432/m1nervac0nsole?sslmode=disable`). A green local run can still fail CI's `go-db` job.
- `-tags embedui` is mandatory for any deployable binary; without it `server/webui_stub.go` serves 404 for the UI. `server/webui/dist/` is generated and gitignored.
- Provider proxy: `deployment/build-cliproxy.sh` (pinned CLIProxyAPI v8.0.47 + `core.patch`); tests via `deployment/cliproxy/run-tests.sh`.

## Code Conventions & Common Patterns

**Go**
- Files `snake_case.go`; tests colocated as `*_test.go` with a per-package `testmain_test.go`. Exported identifiers carry doc comments that explain *why* and often cite design-doc sections.
- Errors: `fmt.Errorf("context: %w", err)`, package sentinels (`db.ErrIntentStateConflict`, `llmpool.ErrExhausted`), SQLSTATE inspection via `errors.As(err, &pgErr)`. HTTP responses only through `writeJSON` / `writeErr` (`server/server.go:4101`).
- Cancellation: `context.Context` first everywhere; long runs use `context.WithCancelCause` plus a named `agent.AbortCause`; read it back with `agent.AbortReason(ctx)`.
- Concurrency: goroutine-per-role with `WaitGroup`/routine registry; `sync.RWMutex` over lifecycle state, `sync.Map`/`atomic` for hot counters; channel + timer debounce (800 ms planner wake) instead of polling.
- Dependency injection: constructors take explicit deps; optional wiring via `Set*` methods; DB-backed overrides are package-level function variables (`agent.ToolAugment`, `agent.ToolResolve`, `agent.PromptOverride`, `agent.WrapupOverride`, …) assigned once in `server.New`.
- Adding an external tool: a TOML manifest in `manifest/builtin/` plus a golden case under `m1nervac0nsole/tests/go/manifest/testdata/golden/` (`TestEveryManifestHasAGoldenCase` fails otherwise). Adding a DB-exposed tool: seed in `agent/toolcatalog.go`, handler stays in code.
- Adding a runtime toggle: a `setting*` constant in `server/manager.go` + row in the `settings` table, read per run.

**Frontend**
- All backend access goes through `web/src/lib/api.ts` + `web/src/lib/types.ts`; never fetch ad hoc from components.
- App Router groups `(auth)`, `(main)`, `(external)`; local state hooks + localStorage; shadcn/radix components; Biome formatting (2 spaces, 120 cols, double quotes, organized imports) — `src/components/ui` and `src/components/calendar` are excluded from lint.
- English-only edition: one catalog `web/messages/en.json`; `scripts/check-cjk.py` fails CI on Hangul, Han, **and CJK/fullwidth punctuation** in authored source. Test files are exempt by rule. There are **no content exceptions**: every string that must *match* non-English input (legacy intercept prefixes, seeded names, quota markers, ICP filings, mention tokens, the guard's forensic framing marker) is written with ASCII escapes — `\u6a21\u578b` in Go/TS, `\x{...}` for `grep -P`, `U&'...'` in SQL — so the source stays pure ASCII while the compiled value is unchanged. Add a new match string the same way; never add an exception entry.
- Appearance is fixed: there are no theme, preset or font preferences or generators, and only the sidebar open/closed state remains configurable.

## Important Files

- `m1nervac0nsole/cmd/m1nervac0nsole/main.go`, `server/server.go` (route table at `Handler()`), `server/engine.go`, `server/manager.go`, `server/task_llm.go` — process wiring and orchestration semantics.
- `m1nervac0nsole/agent/planner.go`, `agent/worker.go`, `agent/tools.go`, `agent/toolcatalog.go`, `agent/assembly.go`, `agent/cancelcause.go` — agent behavior and tool contract.
- `m1nervac0nsole/db/exploration.go`, `db/assets.go`, `db/db.go`, `db/schema.sql` — graph invariants and migration.
- `m1nervac0nsole/db/knowledge.go`, `db/reflection.go`, `db/scrub.go`, `agent/tools_memory.go`, `server/memory.go` — knowledge base and reflection pool; protected by tests that prove task isolation and scrubbing, so keep those passing.
- `m1nervac0nsole/intercept/intercept.go`, `guard/guard.go`, `scope/scope.go` — authorization boundary; treat as protected surfaces.
- `m1nervac0nsole/config/config.go` — `config.json` + `M1NERVAC0NSOLE_CONFIG` / `M1NERVAC0NSOLE_PG_DSN` / `M1NERVAC0NSOLE_SKILL_DIR`; no built-in DSN fallback, startup fails loudly.
- `deployment/provenance.json` — machine-written image and toolchain record; never hand-edit.
- `deployment/sandbox.yaml`, `deployment/guest-start.py`, `deployment/export_traces.py` — VM definition, guest supervision, training export.
- `m1nervac0nsole/docs/system-reference.md` and `deployment/README.md` — the as-built system and deployment references. Keep them current when behaviour changes; they are the map, not a policy.
- `m1nervac0nsole/graphify-out/graph.json` + `GRAPH_REPORT.md` — prebuilt graph (13.3k nodes / 76.0k edges / 496 communities), **generated and gitignored**, so it is absent from a fresh clone. Query with `graphify query "<question>"`, `graphify path "A" "B"`, `graphify explain "X"`; rebuild with `graphify update m1nervac0nsole`.

## Runtime/Tooling Preferences

- **Go 1.26.x** (`go.mod` pins 1.26.3; the proxy module pins 1.26.10). `CGO_ENABLED=0` everywhere; SQLite is pure-Go `modernc.org/sqlite`. No `golangci-lint`, `gofmt` gate, or `go.work`.
- **Node 22** for CI/web (lockfile needs ≥22.22.2); npm with `package-lock.json` (lockfileVersion 3). No Bun, pnpm, yarn, or root `package.json`.
- **Python 3.13** host venv (`.venv`, uv-created) holding only `microsandbox==0.7.11`; all host/deployment scripts are stdlib-only. Guest image uses Debian bookworm `python3`.
- **PostgreSQL 16** required; **Docker** for building the guest image (`./lab image-build`; buildx is installed and `docker build` uses BuildKit); **KVM** for the microsandbox VM.
- Detections suites and the provider-proxy suite need Docker/network and are outside the default Go loop.

## Testing & QA

- **Go**: stdlib `testing` only (no testify/gomock). White-box tests stay beside their package (they call unexported functions); black-box `package foo_test` tests live in `m1nervac0nsole/tests/go/{manifest,scope,useragent,nativeproxy,config}/`. Patterns: table-driven cases with `httptest.NewRequest`/`NewRecorder`, `t.TempDir()`, `t.Setenv`, `t.Cleanup` registered first so it runs last, `pg_advisory_lock` per package.
- **Python**: stdlib `unittest`; `tests/python/{test_lab,test_guest_start,test_export_traces}.py` load scripts by path (`SourceFileLoader` / `sys.path`), synthesize fixtures inline, and touch no deployment state.
- **Web**: Vitest + jsdom + Testing Library; all tests live in `m1nervac0nsole/web/tests/` (mirrors `src/`, imports via `@/…`; `vitest.config.ts` includes only `tests/**/*.test.ts(x)`); `vi.mock` for `next-intl`, `sonner`, `@/lib/api`. Go white-box tests stay beside their package because they call unexported symbols; everything that can be black-box is central (`m1nervac0nsole/tests/go/`, `tests/python/`, `m1nervac0nsole/web/tests/`).
- **Coverage**: none configured anywhere — quality gates are pass/fail (`go vet`, `go test`, `build:static`, `biome check`, `check-cjk.py`, `check-doc-links.py`).
- **Verification beyond unit tests**: `python3 deployment/verify_capture.py` (host `tshark` required; drives the authenticated custom-tool test endpoint, so it needs no credential) and `python3 deployment/verify_completeness.py` (nonces through HTTP, SSE, a 6 MiB body and a WebSocket, plus a keylog fixture; runs its own isolated gateway and recorder, so it needs no credential and changes no policy).

## Traps

- **Root `.gitignore` is deny-by-default** (`/*` plus a short whitelist). Only `README.md`, `AGENTS.md`, `lab`, `deployment/`, `m1nervac0nsole/`, `.github/` and `tests/` are published; `.audit/`, `.upstream-work/`, `state/`, `exports/`, `secrets/` and the empty root `skills/` stay untracked by design; search tools honoring gitignore silently miss them — pass `gitignore: false`.
- **Do not edit vendored/pinned trees as first-party**: `m1nervac0nsole/third_party/norma/` (nested module), `deployment/cliproxy/` (upstream clone + `core.patch`), `.upstream-work/CLIProxyAPI/` (its own `AGENTS.md`/`CLAUDE.md` are not repo policy). The norma tree carries local changes, so an SDK bump is a three-way merge (`git merge-file` with the old upstream tag as base), never a copy; upstream tests are not vendored.
- **Generated, never hand-edit**: `server/webui/dist/`, `web/out/`, `web/.next/`, `dist/`, `next-env.d.ts`, `tsconfig.tsbuildinfo`, `skills/privesc/reference/{gtfobins,lolbas}.json`, `deployment/guest-dist/`.
- **The guest runs the host build, not the image**: `lab start` rebuilds `deployment/guest-dist/` (binary, skills, guest scripts) when any source is newer, mounts it read-only at `/dist`, and the supervisor copies the binary and syncs skills into `/state/skills` from it. But `lab start` only launches the supervisor when `/api/health` fails, so on a healthy sandbox it updates `/dist` and leaves the running binary alone — a change reaches the VM only after `./lab stop && ./lab start`. The image's baked copies are only the fallback for a sandbox created before the mount. Never swap artifacts into the guest by hand — see `deployment/guest-dist` staleness in `lab` (`guest_dist_stale`).
- **`web/.gitignore` ignores `*.sh`** inside `web/`; new scripts there are silently untracked.
- **Secrets and large local data** — never read, print, or copy: `secrets/`, `jwt.key`, `proxy-state/` (secret-bearing strace), `vpn-profiles/`, `.env`, `state/` (PostgreSQL, pcap, strace), `exports/`, `microsandbox/`, root `*.tar.gz` capture archives.
- **The guard prefix is a neutral platform-control marker** (`[platform control - not target defense]` in `guard/guard.go`); the m1nervac0nsole-branded forensic string was removed and nothing checks it automatically. Keep the wording stable: agents rely on it to tell a platform block from a target-side defense.
- **Known-broken references**: `tests/run.sh` uses stdlib `unittest` (pytest is installed system-wide but is not declared anywhere). CI lives in the root `.github/` (GitHub ignores `m1nervac0nsole/.github/`); every job runs from `m1nervac0nsole/` via `working-directory`, and the `deployment-scripts` job runs the root `tests/python` suites.
- **Operational**: never start two VMs against the shared `state/` — `./lab start` refuses while any other running `m1nervac0nsole-agentlab-*` sandbox exists; use `./lab stop` rather than a force-kill. `lab` targets the VM name at `lab:23` (also quoted in `README.md`).

# Repository Guidelines

## Project Overview

AgentLab is a private two-layer monorepo at `/mnt/Research/AgentLab`:

- **Root layer** — the lab/capture environment: `lab` (stdlib Python CLI driving a microsandbox VM), `deployment/` (guest image, host provider proxy, export + verification scripts), and local-only runtime state (`state/`, `exports/`, `proxy-state/`, `secrets/`).
- **`artex-global/`** — the application under development: ARTEX Global Edition, an autonomous LLM multi-agent penetration-testing system. Go backend (`module github.com/Autumn-27/artex`, `go 1.26.3`) + Next.js 16 frontend statically exported and embedded into the single binary. PostgreSQL is the system of record.

AGPL-3.0 fork of upstream ARTEX; do not replace the customized deployment with a stock upstream release. The tool is offensive-security software: verification work targets local fixtures or explicitly authorized scope only (`artex-global/CONTRIBUTING.en.md`).

## Architecture & Data Flow

```
Next.js SPA (embedded) → /api/* → server.Handler() mux → Manager/Task/Engine
  → agent (Planner/Worker/MainAgent) → db stores (PostgreSQL) → JSON/SSE
```

- **Entry points**: `artex-global/cmd/artex/main.go` (`run()` at :48) and the same binary's `egress-proxy` subcommand (`cmd/artex/egress.go`). Wiring order: `server.NewManager` → `server.New` → `srv.Handler()`.
- **Two outbound paths**: worker/tool traffic goes through the recording MITM proxy (`traffic/`, `-proxy`, default `127.0.0.1:8788`); traffic the backend generates itself (asset enrichment probes, MCP handshakes) goes through the masking `egress-proxy` (`egress/`, `-addr`, default `127.0.0.1:8888`), which owns the uTLS Chrome fingerprint, the header set, the CA and the per-host rate cap. `ARTEX_EGRESS_PROXY` / `ARTEX_EGRESS_CA` configure the client side; with neither, enrichment probes fail closed rather than dialling direct.
- **Per task**: `Engine.Run` (`server/engine.go:783`) starts 1 planner loop + N worker loops (`workers` setting, default 3) + deadline coordinator. Planner is the sole intent producer; workers claim one intent, execute real tools, write facts/assets/findings back.
- **Dual graph**: global asset graph (`db/assets.go`, shared, program-computed hierarchy) and per-task exploration graph (`db/exploration.go`, goals/intents/facts/findings), joined by `exploration_anchors`.
- **Memory**: `db/knowledge.go` (full-text knowledge base), `db/reflection.go` + `db/reflect_engine.go` (per-task reflection pool, engine-derived at intent and task end), `db/scrub.go` (credential and target-identifier scrubbing on every write). Agents use `recall` / `knowledge_add` / `reflect` (`agent/tools_memory.go`); `server/memory.go` builds the start-of-task block and the per-round reflections provider (`ARTEX_MEMORY=off|inject`). Agent writes are task-private candidates; only an owner promotes, and promotion re-scrubs with the origin task's scope identifiers. See `RSI.md`.
- **Agent SDK**: vendored `artex-global/third_party/norma/` via `replace` in `go.mod` — `agentcore` (Session/Options), `harness` (turn loop), `llm` (Provider `Stream`/`Complete`), `tool` (CoreTool).
- **Decorator chains, not DI**: provider = `agent.Config` → optional `nativeproxy` → `llmrec` recorder → `llmpool.Pool` failover. Tools = base set → `ToolAugment` (skills/MCP) → `ToolResolve` (DB overrides) → alias/panic wrapper → harness hooks (`guard` audit, `intercept` allow/deny/ask, `scope` boundary).
- **Capture**: `traffic/` is a go-mitmproxy addon writing a file tree plus a **SQLite index only** (`traffic/traffic.go:194`); graphs/tasks/findings/LLM records live in PostgreSQL. `evidence/` pins finding evidence blobs independently of disposable traffic.
- **State ownership**: PG authoritative; in-memory mirrors in `Manager`/`Engine`/`Server` guarded by mutexes and read through lifecycle snapshots. Runtime toggles are rows in the `settings` table, read per run.

## Key Directories

| Path | Purpose |
|---|---|
| `artex-global/cmd/artex/` | Binary entry + `egress-proxy` subcommand |
| `artex-global/server/` | HTTP API, `Manager`, `Engine`, LLM wiring, auth, scheduler |
| `artex-global/agent/` | LLM roles, prompts, tool surface, provider construction |
| `artex-global/db/` | PostgreSQL stores + embedded `schema.sql` (idempotent, advisory-locked migration) |
| `artex-global/traffic/`, `intercept/`, `guard/`, `scope/` | Recording MITM proxy; tool-call safety pipeline |
| `artex-global/egress/`, `enrich/`, `limits/`, `useragent/` | Masking egress proxy (identity, CA, rate gate); engine-side asset auto-completion; shared outbound identity |
| `artex-global/llmpool/`, `llmrec/`, `nativeproxy/`, `mcphttp/` | LLM transport decorators, host proxy client, MCP clients |
| `artex-global/manifest/` | Declarative TOML tool manifests + `builtin/*.toml` |
| `artex-global/third_party/norma/` | Vendored agent SDK (separate module) |
| `artex-global/web/` | Next.js App Router frontend (`src/app`, `src/lib`, `src/components`) |
| `artex-global/skills/`, `detections/`, `docs/` | Agent skills, detection rules, design/defense docs |
| `deployment/` | Guest `Dockerfile`(+`.toolchain`), `sandbox.yaml`, `guest-start.py`, `export_traces.py`, host proxy (`cliproxy/`) |
| `tests/` | Umbrella runner + Python suites (black-box Go suites are in `artex-global/tests/go/`) |
| `.github/` | GitHub Actions workflows (ci, web, detections, docs, external-links, release) and issue/PR templates; jobs run from `artex-global/` |
| `artex-global/graphify-out/` | Generated knowledge graph of `artex-global/` (gitignored; query it, don't rebuild) |

## Development Commands

All Go/web commands run **inside `artex-global/`** — there is no module, Makefile, or `package.json` at the root.

```sh
# Go
cd artex-global && go build ./... && go vet ./...
go test ./agent/ -count=1
go test -p 1 ./... -count=1 -timeout 2400s        # serial: DB suites share one database

# Web
cd artex-global/web && npm ci
npm run build:static     # NEXT_EXPORT=1 next build — the TypeScript/merge gate
npm run test -- --run    # vitest
npm run check            # biome check (CI gate; use check:fix to autofix)

# Umbrella suites (from repo root)
tests/run.sh [all|go|proxy|python|web|dev]

# Full binary (embeds UI; requires the static export first)
cd artex-global && ARTEX_COMPRESS=off ./build.sh --target linux/amd64
./dev.sh                 # backend :8787 + recording proxy :8788 + masking egress proxy :8888 + next dev :5173

# Lab VM (host control plane)
./lab start [--vpn PROFILE] | status | primary | export | stop
./lab exec -- bash -lc '...'
```

- DB integration tests in `agent config db evidence guard intercept llmrec server` **silently `--- SKIP`** without `ARTEX_PG_DSN` (e.g. `postgres://artex:artex@localhost:5432/artex?sslmode=disable`). A green local run can still fail CI's `go-db` job.
- `-tags embedui` is mandatory for any deployable binary; without it `server/webui_stub.go` serves 404 for the UI. `server/webui/dist/` is generated and gitignored.
- Provider proxy: `deployment/build-cliproxy.sh` (pinned CLIProxyAPI v8.0.47 + `core.patch`); tests via `deployment/cliproxy/run-tests.sh`.

## Code Conventions & Common Patterns

**Go**
- Files `snake_case.go`; tests colocated as `*_test.go` with a per-package `testmain_test.go`. Exported identifiers carry doc comments that explain *why* and often cite design-doc sections.
- Errors: `fmt.Errorf("context: %w", err)`, package sentinels (`db.ErrIntentStateConflict`, `llmpool.ErrExhausted`), SQLSTATE inspection via `errors.As(err, &pgErr)`. HTTP responses only through `writeJSON` / `writeErr` (`server/server.go:4101`).
- Cancellation: `context.Context` first everywhere; long runs use `context.WithCancelCause` plus a named `agent.AbortCause`; read it back with `agent.AbortReason(ctx)`.
- Concurrency: goroutine-per-role with `WaitGroup`/routine registry; `sync.RWMutex` over lifecycle state, `sync.Map`/`atomic` for hot counters; channel + timer debounce (800 ms planner wake) instead of polling.
- Dependency injection: constructors take explicit deps; optional wiring via `Set*` methods; DB-backed overrides are package-level function variables (`agent.ToolAugment`, `agent.ToolResolve`, `agent.PromptOverride`, `agent.WrapupOverride`, …) assigned once in `server.New`.
- Adding an external tool: a TOML manifest in `manifest/builtin/` plus a golden case under `artex-global/tests/go/manifest/testdata/golden/` (`TestEveryManifestHasAGoldenCase` fails otherwise). Adding a DB-exposed tool: seed in `agent/toolcatalog.go`, handler stays in code.
- Adding a runtime toggle: a `setting*` constant in `server/manager.go` + row in the `settings` table, read per run.

**Frontend**
- All backend access goes through `web/src/lib/api.ts` + `web/src/lib/types.ts`; never fetch ad hoc from components.
- App Router groups `(auth)`, `(main)`, `(external)`; zustand stores; shadcn/radix components; Biome formatting (2 spaces, 120 cols, double quotes, organized imports) — `src/components/ui` and `src/components/calendar` are excluded from lint.
- English-only edition: one catalog `web/messages/en.json`; `scripts/check-cjk.py` fails CI on Hangul, Han, **and CJK/fullwidth punctuation** in authored source. Test files are exempt by rule. There are **no content exceptions**: every string that must *match* non-English input (legacy intercept prefixes, seeded names, quota markers, ICP filings, mention tokens, the guard's forensic framing marker) is written with ASCII escapes — `\u6a21\u578b` in Go/TS, `\x{...}` for `grep -P`, `U&'...'` in SQL — so the source stays pure ASCII while the compiled value is unchanged. Add a new match string the same way; never add an exception entry.
- Regenerate theme presets with `npm run generate:presets`; the husky pre-commit hook does this and rewrites only the marked block of `web/src/lib/preferences/theme.ts`.

## Important Files

- `artex-global/cmd/artex/main.go`, `server/server.go` (route table at `Handler()`), `server/engine.go`, `server/manager.go`, `server/task_llm.go` — process wiring and orchestration semantics.
- `artex-global/agent/planner.go`, `agent/worker.go`, `agent/tools.go`, `agent/toolcatalog.go`, `agent/assembly.go`, `agent/cancelcause.go` — agent behavior and tool contract.
- `artex-global/db/exploration.go`, `db/assets.go`, `db/db.go`, `db/schema.sql` — graph invariants and migration.
- `artex-global/db/knowledge.go`, `db/reflection.go`, `db/scrub.go`, `agent/tools_memory.go`, `server/memory.go` — knowledge base and reflection pool; protected by tests that prove task isolation and scrubbing, so keep those passing.
- `artex-global/intercept/intercept.go`, `guard/guard.go`, `scope/scope.go` — authorization boundary; treat as protected surfaces.
- `artex-global/config/config.go` — `config.json` + `ARTEX_CONFIG` / `ARTEX_PG_DSN` / `ARTEX_SKILL_DIR`; no built-in DSN fallback, startup fails loudly.
- `deployment/provenance.json` — machine-rewritten by `./lab primary`; never hand-edit.
- `deployment/sandbox.yaml`, `deployment/guest-start.py`, `deployment/export_traces.py` — VM definition, guest supervision, training export.
- `artex-global/graphify-out/graph.json` + `GRAPH_REPORT.md` — prebuilt graph (10.8k nodes / 62.3k edges / 512 communities), **generated and gitignored**, so it is absent from a fresh clone. Query with `graphify query "<question>"`, `graphify path "A" "B"`, `graphify explain "X"`; rebuild with `graphify update artex-global`.

## Runtime/Tooling Preferences

- **Go 1.26.x** (`go.mod` pins 1.26.3; the proxy module pins 1.26.10). `CGO_ENABLED=0` everywhere; SQLite is pure-Go `modernc.org/sqlite`. No `golangci-lint`, `gofmt` gate, or `go.work`.
- **Node 22** for CI/web (lockfile needs ≥22.22.2); npm with `package-lock.json` (lockfileVersion 3). No Bun, pnpm, yarn, or root `package.json`.
- **Python 3.13** host venv (`.venv`, uv-created) holding only `microsandbox==0.7.11`; all host/deployment scripts are stdlib-only. Guest image uses Debian bookworm `python3`.
- **PostgreSQL 16** required; **Docker** only for building the guest image (`DOCKER_BUILDKIT=0`, host lacks buildx); **KVM** for the microsandbox VM.
- Detections suites and the provider-proxy suite need Docker/network and are outside the default Go loop.

## Testing & QA

- **Go**: stdlib `testing` only (no testify/gomock). White-box tests stay beside their package (they call unexported functions); black-box `package foo_test` tests live in `artex-global/tests/go/{manifest,scope,useragent,nativeproxy,config}/`. Patterns: table-driven cases with `httptest.NewRequest`/`NewRecorder`, `t.TempDir()`, `t.Setenv`, `t.Cleanup` registered first so it runs last, `pg_advisory_lock` per package.
- **Python**: stdlib `unittest`; `tests/python/{test_lab,test_guest_start,test_export_traces}.py` load scripts by path (`SourceFileLoader` / `sys.path`), synthesize fixtures inline, and touch no deployment state.
- **Web**: Vitest + jsdom + Testing Library; all tests live in `artex-global/web/tests/` (mirrors `src/`, imports via `@/…`; `vitest.config.ts` includes only `tests/**/*.test.ts(x)`); `vi.mock` for `next-intl`, `sonner`, `@/lib/api`. Go white-box tests stay beside their package because they call unexported symbols; everything that can be black-box is central (`artex-global/tests/go/`, `tests/python/`, `artex-global/web/tests/`).
- **Detections**: bash drivers under `artex-global/detections/tests/` (8 suites + 3 gates, Docker-only); `run-all.sh` locally, the root `.github/workflows/detections.yml` in CI.
- **Coverage**: none configured anywhere — quality gates are pass/fail (`go vet`, `go test`, `build:static`, `biome check`, `check-cjk.py`, `check-doc-links.py`).
- **Verification beyond unit tests**: `python3 deployment/verify_capture.py` (host `tshark` required) and `python3 deployment/verify_reasoning.py` (starts the local model).

## Traps

- **Root `.gitignore` is deny-by-default** (`/*` plus a short whitelist). Only `README.md`, `AGENTS.md`, `lab`, `deployment/`, `artex-global/`, `.github/` and `tests/` are published; `.audit/`, `.upstream-work/`, `state/`, `exports/`, `secrets/` and the empty root `skills/` stay untracked by design; search tools honoring gitignore silently miss them — pass `gitignore: false`.
- **Do not edit vendored/pinned trees as first-party**: `artex-global/third_party/norma/` (nested module), `deployment/cliproxy/` (upstream clone + `core.patch`), `.upstream-work/CLIProxyAPI/` (its own `AGENTS.md`/`CLAUDE.md` are not repo policy).
- **Generated, never hand-edit**: `server/webui/dist/`, `web/out/`, `web/.next/`, `dist/`, `next-env.d.ts`, `tsconfig.tsbuildinfo`, `web/src/lib/preferences/theme.ts` (generated block), `skills/privesc/reference/{gtfobins,lolbas}.json`.
- **`web/.gitignore` ignores `*.sh`** inside `web/`; new scripts there are silently untracked.
- **Secrets and large local data** — never read, print, or copy: `secrets/`, `jwt.key`, `proxy-state/` (secret-bearing strace), `vpn-profiles/`, `.env`, `state/` (PostgreSQL, pcap, strace), `exports/`, `microsandbox/`, root `*.tar.gz` capture archives.
- **Detection indicators are pinned to source strings** (`enrich/`, `guard/`, `db/schema.sql`, `traffic/`, `cmd/artex/main.go`); changing those values requires updating `detections/indicators/*`, Sigma/Suricata rules, and the ATT&CK layer or CI goes red.
- **Docs drift**: `CONTRIBUTING.en.md` understates gates (`npm run check` and vitest are merge gates now). `docs/features/benchmarks.md` ≡ `scripts/benchmark/README.md` and `docs/features/submission-review.md` ≡ `scripts/submission_review/README.md` — edit both or neither.
- **Known-broken references**: `tests/run.sh` uses stdlib `unittest` (pytest is installed system-wide but is not declared anywhere). CI lives in the root `.github/` (GitHub ignores `artex-global/.github/`); every job runs from `artex-global/` via `working-directory`, and the `deployment-scripts` job runs the root `tests/python` suites.
- **Operational**: never start two VMs against the shared `state/` — `./lab start` refuses while any other running `artex-agentlab-*` sandbox exists; use `./lab stop` rather than a force-kill. `lab` targets the VM name at `lab:23` (also quoted in `README.md`).

<!-- Design record (2026-11-13). Plan D shipped; Plan E pending. -->

# Implementation plans: features pulled from Executioner

Companion to `local://executioner-pull-plan.md` (what Executioner does and why each item is worth pulling). This file is the build plan. Nothing here is implemented. Paths are under `/mnt/Research/AgentLab/m1nervac0nsole` unless stated. Executioner source for reference: `/tmp/executioner` (re-clone `structuredstanza/executioner` at c21c844 if gone); MIT - keep the dbx0 copyright notice in a `NOTICE` entry for any ported file.

Order: A -> B -> (decision gate) -> C -> D -> E. A and B are independent and can run in parallel.

## Status

- **A: shipped** (commit ac90e6f). The graph tab subscribes to the activity SSE and folds events through a pure reducer (`web/src/lib/graph-live.ts`: 2 s activation window, per-node tail capped at 40 lines), with one debounced refetch per burst; the 20 s poll survives only while the stream is down. Intent state transitions are announced from `Engine.setIntentState` (server/engine.go), so a terminal state repaints immediately; claim rollbacks stay silent. Clicking an intent opens a drawer with its live tail plus pause/resume/cancel and a worker message (`web/src/components/intent-live-panel.tsx`).
- **B: shipped** (commit ac90e6f). The browser MCP is seeded enabled with a one-shot migration that never resurrects a later toggle-off; `skills/browser/SKILL.md` teaches the snapshot-then-act loop and the operator hand-off, and is visible to auto/pentest/worker/planner; `server/mcp_scope.go` judges every `mcp__browser__navigate|open` against the task boundary and refuses out-of-scope hosts, non-http(s) schemes, non-ASCII hosts, non-canonical IPv4 spellings and backslash tricks, and refuses rather than guesses when no checker exists.
- **D: shipped** (commit 5224fc9). `plan/` holds the proposal contract and a pure validator; `db/plan_drafts.go` holds one pending draft per task and the apply transaction (goals, open intents anchored to their assets, active hints, scope rows, created node ids, second apply refused; inclusions need `allow_include`). The `drafter` assistant has `plan_context` and `propose_plan` bound to it alone and reads the catalogue through the shared `list_tools`. Routes: `GET /api/tasks/{id}/plans`, `POST .../{draft}/apply`, `DELETE .../{draft}`. The task detail page has a **Plan** tab with the drafter chat and a proposal preview; every message names the task, because a wrong guess stores a draft against a real engagement. Measured on the running guest: apply created the nodes and both scope rows, a second apply returned 409, an inclusion was refused without the flag, and the drafter produced a valid draft through `propose_plan`.
- **C, E: not started.** The decision gate after B is closed: the browser connects, navigates through the recorder and its snapshot is adequate, so Plan C is not justified.
- Open limitation from B: `ask_operator` refuses an attached screenshot when provider credentials are configured (server/ask_operator.go:42-44), which is the normal deployment state, so the hand-off is text-only until that is revisited.


---

## Plan A - Live exploration graph (S-M, no new subsystem)

Goal: the task graph tab updates as intents change state, shows a live output tail per intent, and lets the operator act on an intent from the canvas.

Today: `web/src/components/exploration-graph.tsx` (@xyflow/react 12, layered layout) fed by `function/tasks/detail/_tabs/graph-tab.tsx`, which polls `api.explorationGraph` every 20 s. Activity already streams over SSE: `GET /api/exploration/activity/stream?task=&intent=&since=` with `Last-Event-ID` replay (`server/server.go:838, 3167-3263`), consumed by `sessions-tab.tsx:988-994`.

Steps
1. Backend: confirm the activity stream carries intent state transitions. If transitions are not emitted as activity rows, emit one per transition from the single choke point `transitionIntentState` (server/engine.go) through the existing `emitActivity`. No new endpoint.
2. Web: port two pure reducers from `/tmp/executioner/apps/desktop/src/renderer/components/canvas/useNodeStatus.ts` and `useNodeOutputs.ts` into `web/src/lib/graph-live.ts`: `reduceIntentStatus(events, sinceSeq)` and `reduceIntentOutput(events, sinceSeq)` (tail capped at 20,000 chars). Keep the `sinceSeq` baseline so a reload does not replay stale state.
3. `graph-tab.tsx`: subscribe to the stream once per task; coalesce events per animation frame; patch only nodes whose status changed; keep one full refetch on `visibilitychange` and on reconnect instead of the 20 s poll.
4. `exploration-graph.tsx`: status ring per intent state (open, running, paused, done, exhausted, blocked, stopped) and a running pulse; edge accent when the source intent is done.
5. Node drawer: add the output tail (`whitespace-pre`, horizontal scroll) and the controls that already exist as endpoints - pause, resume, cancel (`POST /api/tasks/{id}/intents/{iid}/control`), steer (`.../messages`). No new backend.

Tests: vitest for both reducers (baseline, out-of-order seq, cap) and for "only changed nodes re-render". Go test only if step 1 adds an emit.
Acceptance: start a task, watch an intent go open -> running -> done on the canvas without a refresh; pause and resume it from the drawer.
Risk: event volume on tasks with many workers - the per-frame coalescing is the mitigation; measure with task 1's activity replay.

---

## Plan B - Browser for workers on what is already installed (S)

Goal: workers can drive a real browser whose traffic lands in the recording proxy as pinnable evidence, and can hand a CAPTCHA/MFA step to the operator. Almost no new code; this is also the experiment that decides Plan C.

Today: Chromium + `@playwright/mcp` are in the guest image; the `browser` MCP row is seeded `enabled=false` (`db/db.go:263-286`); `server/manager.go:705-754` already injects `--proxy-server` and the MITM CA into that row when capture is on. `ask_operator` (`server/ask_operator.go:24-68`) pauses the intent, accepts an image and resumes on reply.

Steps
1. Enable the `browser` MCP row by default when traffic capture is on (seed change + a migration statement for existing rows that still equal the seed). Keep Obscura for stealth fetches; document in `skills/obscura/SKILL.md` that it bypasses capture.
2. Add a `skills/browser/SKILL.md` (declares `mcps: browser`): when to use it, snapshot-then-act loop, re-snapshot after every action, and the hand-off rule below.
3. Hand-off: in the skill, instruct the worker to call `ask_operator` with a screenshot when it meets a CAPTCHA, MFA prompt or consent wall. Verify `ask_operator.go:42-44` (screenshots refused when provider credentials are configured) does not block this in the lab; if it does, that restriction needs an explicit decision.
4. Scope: confirm the scope hook sees MCP browser navigation. If MCP tool calls bypass `scope/`, add the navigation URL check in the MCP tool wrapper (`mcphttp/` call path), fail closed.
5. Evidence: verify a browser request appears in the traffic index with the task/intent attribution needed by `POST /api/exploration/findings/{id}/traffic`. If attribution is missing for MCP-originated traffic, fix it at the proxy tagging point - this is the one item that may grow.

Tests: Go test for the seed/migration and for the scope check on a browser navigation; a lab run against a local fixture with a JS login form.
Acceptance: on a fixture, a worker logs in through the browser, the requests are listed under the task's traffic, one is bound to a finding, and an `ask_operator` round trip resumes the intent.
Decision gate after B: build Plan C only if the Playwright MCP proves insufficient on one of: no live operator view, no take-over, snapshot quality, scope enforcement.

---

## Plan C - Own browser driver, live view and take-over (M + M)

Only after the gate. Two separable halves.

C1 Driver (Go, new package `browser/`)
- `browser.Driver` over a two-method CDP seam `{Send, On}` (so tests use a fake CDP, as Executioner does - see `/tmp/executioner/apps/desktop/src/main/browser/cdp-driver.test.ts:17-42`). Launch the guest's headless Chromium with `--remote-debugging-port=0 --user-data-dir=<task dir> --proxy-server=<recording proxy>`; one profile per task.
- Snapshot: `Accessibility.getFullAXTree` rendered as `- role "name" [ref=g3e17]`, 2,000-line cap, refs `g{generation}e{n}` invalidated on top-level navigation, `STALE_REF` error text "stale reference, take a new snapshot". Improve on the original: also render value, checked, disabled, required.
- Tools (agent/toolcatalog.go seed + handlers): `browser_open`, `browser_navigate`, `browser_snapshot`, `browser_click`, `browser_type`, `browser_press`, `browser_select`, `browser_wait`, `browser_screenshot`, `browser_upload`. Each mutating tool takes `dialog?`/`promptText?`. No `browser_eval`.
- Navigation goes through the existing scope hook and is refused out of scope (Executioner only reports it). Refuse `file:` and other non-http(s) schemes.
- Network tools read the recording proxy's index, not CDP: `browser_network {since?, urlContains?, limit}` -> `{entries, next}`, `browser_response_body {id, offset?, maxBytes}`.
- Screenshots are written to the task evidence dir and returned as an image; `report_finding` accepts the path.
- Crash recovery: rebuild on the same profile, restore URL.
- Tests: fake-CDP unit tests for ref staleness, iframe offsets, dialog policy; one integration test behind an env flag with real Chromium.

C2 Live view and take-over
- Backend: `Page.startScreencast` (JPEG, ack-based backpressure) fanned out per browser. The product has no WebSocket; add one endpoint `GET /api/tasks/{id}/browser/{bid}/live` (WebSocket: frames down, input events up) behind the same auth. Input: `Input.dispatchMouseEvent`, `dispatchKeyEvent`, `insertText`, with viewport scaling.
- Ownership: `PATCH /api/tasks/{id}/browser/{bid} {owner: agent|operator}`. While the operator owns it, agent browser tools return "operator has the page" instead of acting.
- Ask protocol on top of `ask_operator`: join a pending ask instead of re-notifying; on agent-side timeout return `{pending:true}`; keep an unclaimed operator answer for 30 minutes keyed by the message.
- Web: a Browser tab on task detail - canvas for frames, pointer/keyboard capture, ask banner, take/hand-back buttons.
- Risk: frame bandwidth and input latency over the lab network are unmeasured; prototype the screencast alone first and measure before building the tab.

---

## Plan D - Engagement-plan drafting (M-L)

Goal: the operator describes an approach in plain language; the model proposes goals, seed intents, standing rules and scope exclusions; the operator reviews the proposal on the graph and applies it in one transaction.

Pattern taken from Executioner (`packages/engine/src/mcp/toolset.ts:443-466`, `routes/assistant.ts:23-114`): the catalogue is fetched by a tool, the proposal is a validated tool call, nothing is written until the operator applies it.

Steps
1. Schema (parent-owned `db/schema.sql`): `plan_drafts(id, task_id, status draft|applied|discarded, summary, proposal JSONB, created_at, applied_at)`.
2. Proposal contract (Go struct + JSON schema used as the tool schema):
   ```json
   { "summary": "...",
     "goals":   [{"ref":"g1","title":"...","success":"..."}],
     "intents": [{"ref":"i1","goal":"g1","description":"...","asset_ids":[12],"depends_on":["i0"]}],
     "hints":   [{"text":"...","rule":true}],
     "scope":   [{"effect":"exclude","pattern":"*.thirdparty.example","note":"..."}] }
   ```
3. Drafting agent: reuse the chat stack the curator uses (propose-only binding, like `curator`). Tools bound to it alone: `plan_context` (task goal, scope, asset summary, existing goals/intents/hints), `list_tools` (projection of `manifest/builtin/*.toml`: id, description, params), `propose_plan` (the contract above). `propose_plan` validates and stores a draft; on failure it returns the errors so the model retries.
4. Validation (Go, pure function + table tests): unique refs, every intent points at a goal, `depends_on` acyclic, `asset_ids` belong to the task, scope patterns parse, hint text within the existing cap, counts bounded (for example 8 goals, 24 intents).
5. Apply: `POST /api/tasks/{id}/plan/{draft}/apply` creates goals, intents (open), hints and scope rows in one transaction through the existing store functions, marks the draft applied, wakes the planner. `DELETE` discards. An applied draft records the created node ids so it can be reverted while nothing has started.
6. Web: "Draft a plan" on task detail - chat panel plus a preview of the proposal rendered with the exploration-graph component (laid out with the existing layered layout, never at the origin), a diff-style list of what will be created, Apply/Discard.
7. Draft-instead-of-write sink: the same mechanism serves "paste the program policy -> proposed scope rules" as a second entry point with only the `scope` section.

Tests: validator table tests; apply transaction test (all-or-nothing, cross-task asset id refused); handler tests; vitest for the preview.
Acceptance: a plain-language request on a fixture task yields a draft; applying it creates exactly the listed nodes; the planner's next round sees them.
Risk: the planner already invents intents - seeded intents must not be duplicated by its first round. Mitigation: seeded intents are ordinary open intents, which the planner's overview already lists.

---

## Plan E - Smaller pulls (each S, independent)

E1 Server-computed command preview for tool manifests: `POST /api/tools/{id}/preview {target, params}` -> `{program, args}` from the same resolver that executes (`manifest/render.go`); a schema-driven parameter form in the UI. Test: preview equals the executed argv for every golden case.
E2 Findings upsert rule: dedupe on (target, lower(title)), refresh evidence, never reopen a status a human set; return `created`. **Shipped**: `db.RecordFindingTx` folds on task + case-insensitive name + the sorted asset set, refreshes the row and its exploration node, adds the new intent's link, leaves `status` and `evidence_version` untouched (the latter counts bound traffic), and `RecordedFinding.Created` tells the tool to say "updated".
E3 Scope rule model: `{effect, pattern, note}`; exclude wins, longest include wins, no match is `unknown`, not out. Port the ~120-line matcher from `/tmp/executioner/packages/protocol/src/scope.ts` with its tests. Decide first how it composes with the existing `scope/` boundary hook.
E4 Engagement as an MCP server: `POST /mcp` (JSON-RPC, `initialize` / `tools/list` / `tools/call`), per-session scoped token, profile allow-list enforced in both list and call. Start read-only (`list_assets`, `get_asset`, `list_findings`, `list_scope`) then record tools. Needs a security review before any write tool.
E5 Prompt text: adapt the impact gate ("as an attacker I could ...") and the reporter's structure into the worker and finding-report prompts.

Deliberately out: deterministic workflow executor (decide separately whether operator playbooks are wanted; Executioner's executor is serial, has no scope gate, retries or resume), `browser_eval`, CDP network capture/rewrite, Electron plumbing, the CLI/PTY assistant runner.

---

## Decisions
1. Plan B step 1: enable the Playwright MCP by default for capture-on tasks? **Settled (2026-11-13): yes.** It is seeded enabled, bound directly to the executing agents, and starts with `playwright-mcp --executable-path /opt/ms-playwright/current/chrome --no-sandbox` plus `--ignore-https-errors` when the recorder is attached.
2. Plan C: WebSocket endpoint or SSE + POST input? **Moot.** Plan C is closed: the browser is available, is used when the goal names it, and its snapshot is adequate.
3. Plan D: may an applied plan create scope exclusions directly? **Settled: exclusions yes, inclusions only with `allow_include`.** An exclusion narrows the engagement; an inclusion widens what the guard allows, so it needs the operator to say so explicitly.
4. Plan E3: does the rule model replace the `scope/` hook or feed it? **Settled (2026-11-13): it feeds it.** The rule model is data; `scope/` stays the single enforcement point and the matcher lands inside it. Existing `task_scope` rows keep working beside the rules, and a rule that matches takes precedence over a column row for the same host.
5. Plan E4: is exposing task state to external agent CLIs wanted at all? **Open.** If yes, read-only first and a security review before any write tool.

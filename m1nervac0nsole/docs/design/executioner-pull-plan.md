<!-- Design record (2026-11-12). Shipped. -->

# Executioner -> m1nervac0nsole: what is worth pulling

Source: github.com/structuredstanza/executioner at c21c844 (v0.0.8), MIT, copyright dbx0. Electron + TypeScript pnpm monorepo; it drives external agent CLIs (Claude Code, Codex, ...) through a local MCP server instead of calling a model API. Reviewed read-only by four agents; a fifth mapped what m1nervac0nsole already has. Nothing was built or run.

Licence: MIT code can be ported into the AGPL tree with the copyright notice kept. Go cannot take TypeScript, so for the backend only designs and schemas transfer; some React hooks transfer nearly verbatim.

## Where the two products stand

| Area | Executioner | m1nervac0nsole today |
|---|---|---|
| Browser | First-class: 19 `browser_*` tools over its own CDP driver, embedded view, operator hand-off | Chromium + Playwright MCP installed in the guest but the `browser` MCP row is seeded disabled (db/db.go:263-286); Obscura MCP enabled but ignores the recording proxy and its CA; no session registry, no live view |
| Traffic capture | CDP `Network`/`Fetch` domains, 1000-entry in-memory log | Recording MITM proxy with file tree + SQLite index, evidence pinning - stronger |
| Operator hand-off | `browser_ask_operator` banner; no parked state | `ask_operator` (question + image, pauses the intent, reply resumes), `report_blocked`, intercept `ask`, hints, worker steer - stronger, but not wired to a browser |
| Workflows | Static DAG on a canvas, serial executor, step mode, assistant drafts graphs | Dynamic planner/worker loop; no deterministic multi-step recipe; task templates are metadata only |
| Graph UI | reactflow 11 canvas, per-node status ring, output panel, undo/redo, auto-layout | Exploration graph already on @xyflow/react 12 with layered layout (web/src/components/exploration-graph.tsx) but polled every 20 s and read-only; coverage graph on @antv/g6 |
| Live channel | One WebSocket, `{type, executionId, nodeId, data, seq, at}` | SSE only; `/api/exploration/activity/stream` already has `Last-Event-ID` replay |
| Tool manifests | 33 TOML manifests, argv template + emit rules | 32 TOML manifests, same lineage, superset (limits, requires, more parsers, golden tests) |

## 1. Browser driving

### How Executioner does it
- Host: an Electron `WebContentsView` per (engagement, browser), CDP attached in-process, one persistent partition per engagement. The driver sees only a two-method interface `{send, on}`, so it is tested against a fake CDP with no browser (1,342 lines of tests).
- Model-facing page: the accessibility tree from `Accessibility.getFullAXTree`, rendered as indented `- role "name" [ref=g3e17]`, capped at 2,000 lines. Refs are `g{generation}e{n}`; the generation bumps on top-level navigation and a stale ref fails with "stale reference, take a new snapshot". Only role and name are rendered, so checked/disabled/value state is invisible to the model - a gap not to copy.
- Actions resolve a ref to geometry (scroll into view, box model centre, plus the offset of every owning frame) and dispatch raw input events. iframes are auto-attached and addressed as `[frame=f1]`. No implicit settling: every action returns `{url, title}` and the model must snapshot again.
- Tools (19): `browser_open`, `_navigate`, `_snapshot`, `_click {ref}`, `_type {ref,text,clear?,submit?}`, `_press {key}`, `_select {ref,values}`, `_eval {expression,frame?}`, `_wait {selector?,navigation?,timeoutMs}`, `_screenshot {fullPage?}`, `_log {since?}`, `_network {since?,urlContains?,limit}`, `_response_body {requestId,offset?,maxBytes}`, `_rewrite_rules {rules[]}`, `_upload {ref,paths}`, `_mouse`, `_drag`, `_emulate {userAgent?,geolocation?,locale?,timezone?}`, `_ask_operator {message,timeoutSec}`. Mutating tools carry `dialog?`/`promptText?` so the agent pre-answers a JS dialog its own action triggers.
- Network log: per request it keeps both the headers the page issued and the headers actually sent on the wire (`requestWillBeSentExtraInfo`), read with a cursor (`since` -> `next`); bodies are windowed (`offset`, `maxBytes`, `nextOffset`).
- Rewrite rules: `{urlPattern, stage: request|response, method?, setHeaders?, body?, status?}` via the CDP `Fetch` domain, first match wins.
- Hand-off: `browser_ask_operator` shows a bar above the page and waits. Three details: a second ask while one is pending joins it instead of re-notifying; if the agent's wait times out the ask stays open and returns `{pending: true}`; a late operator answer is kept for 30 minutes keyed by the message, so the agent's retry collects it. JS dialogs go to the agent if it acted within the last 2 s, otherwise to the operator.
- Crash recovery rebuilds the page on the same profile and restores URL, emulation and rewrite rules.
- Weak spots: scope is advisory (`scopeStatus` is returned, never enforced), agent navigation accepts any URL including `file:`, no download handling, screenshots are not linked to findings.

### What to pull
1. **A first-class browser tool set for workers (M).** A small Go CDP driver (chromedp or rod) against the headless Chromium already in the guest, exposing the snapshot/ref contract and roughly ten of the tools (`open/navigate/snapshot/click/type/press/select/wait/screenshot/upload`). One `--user-data-dir` per task gives the same isolation as Executioner's partitions. Improve on the original: render value/checked/disabled in the snapshot, and enforce scope on navigation through the existing scope hook instead of reporting it. The `{send, on}` seam and fake-CDP tests transfer as a design.
   - Cheaper alternative to weigh first: enable the already-installed Playwright MCP by default for tasks with capture on. It gives snapshot+ref driving today with no new code, but no live view, no operator take-over and no scope enforcement.
2. **Use the recording proxy instead of CDP for traffic (S).** Do not port `NetworkLog` or `Fetch` rewriting. Launch Chromium with `--proxy-server` at the recording proxy and its CA (the manager already does this for the Playwright MCP row), and expose the proxy's index through the same tool shape: cursor `since`/`next`, `urlContains`, windowed `response_body`. Every browser request then becomes pinnable finding evidence with no extra work, which Executioner cannot do.
3. **Live view and take-over for the remote operator (M).** Replaces the embedded pane: `Page.startScreencast` frames to the UI, pointer/keyboard forwarded with `Input.dispatch*`. This is the piece that makes MFA/CAPTCHA hand-off real in a headless VM. It needs a WebSocket (the product has none today) or SSE for frames plus POST for input.
4. **Wire hand-off to `ask_operator` (S).** The existing tool already pauses the intent, carries an image and resumes on reply. Add the three ask details above, and have the browser tool attach the current screenshot automatically.
5. **Dialog policy and crash-rebuild-with-state (S).** Small, easy to get wrong, worth copying as written.

Not pulling: all Electron view plumbing and the engine-to-desktop socket hop, CDP network capture and rewrite, client-hint injection, and `browser_eval` as an unrestricted tool (it bypasses the guard pipeline and Bash already exists).

## 2. Workflow drafting

### How Executioner does it
- The assistant is an agent CLI run headless with three MCP tools: `list_node_types` (the live node catalogue projected from the TOML manifests, including each node's output fields), `get_workflow_graph` (the current canvas, sent with every message), and `propose_workflow {name?, summary, graph}`.
- The output contract is a tool call, not JSON in prose: `graph = {nodes:[{id,type,data}], edges:[{id,source,target,sourceHandle}]}`, `sourceHandle` being `true|false` off an `if` and `body|done` off a `loop`.
- The prompt has no few-shot examples and does not contain the catalogue: four constant blocks (graph shape, node-choice rules with a hard "do not use an agent node for recon/scanning/parsing", templating syntax, save rules) plus the tool-fetched catalogue.
- Validation is server-side with the same schema the table stores (duplicate ids, dangling edges, cycles); on failure the tool returns the errors and the model retries itself. A proposal is captured per session, shown as a summary with "Apply to canvas".
- Defects: apply replaces the whole canvas, applies no layout (every node lands at the origin), and unknown node types are accepted and only fail at run time.

### What to pull
6. **Engagement-plan drafting (M-L).** The pattern - catalogue as a tool, proposal as a validated tool call, operator review, transactional apply - maps onto the planner model rather than onto a DAG. The operator describes an approach; the model proposes goals, seed intents, standing rules (hints) and scope exclusions; Go validates against the real manifests and scope; the operator reviews it on the exploration-graph canvas and applies it in one transaction. Proposed shape:
   ```json
   { "summary": "...",
     "goals":   [{"id":"g1","title":"Map the auth surface","success":"login pages enumerated"}],
     "intents": [{"id":"i1","goal":"g1","description":"...","asset_ids":[12],"depends_on":[]}],
     "hints":   [{"text":"do not brute-force credentials","rule":true}],
     "scope":   [{"effect":"exclude","pattern":"*.thirdparty.example","note":"out of scope"}] }
   ```
   This is a new capability: today a task starts from a one-line goal and the planner invents the rest.
7. **Draft-instead-of-write sink (S).** Executioner's scope parser runs an agent whose write tools are intercepted into a reviewable draft. The same trick gives "paste the program policy, get proposed scope rules" and is the mechanism behind item 6.
8. **Deterministic playbooks (L, decide separately).** A workflow is one deterministic unit the planner could invoke (a recon pipeline) or an on-new-asset automation. Complementary to the planner, but Executioner's executor is not the model to copy: serial, one target per run, no scope gate before tool nodes, no retries, no resume, in-memory step state.

## 3. Visualisation

### How Executioner does it
- reactflow 11: one node shell with a status ring and a pulse/tick/cross, labelled branch handles, an edge with a midpoint "+" for insert-between, edges turning green when their source succeeded.
- Live run: events `{type: status|stdout|done, executionId, nodeId, data, seq, at}` are coalesced per animation frame; two pure reducers turn them into per-node status and a capped output tail, both taking a `sinceSeq` baseline so a new run does not inherit the previous run's state; only nodes whose status moved are re-rendered.
- Step mode: a per-node gate with banked permits (`/step` releases one, `/resume` all).
- Undo/redo: history is recorded on a structural signature that excludes status and output, so live repaints never pollute it.
- Auto-layout: a 90-line longest-path layering.

### What to pull
9. **Make the exploration graph live (S-M).** It is already on @xyflow/react; it lacks the event feed. Port `reduceNodeStatus`/`reduceNodeOutputs` and the `sinceSeq` idiom (pure functions, MIT), feed them from the existing activity SSE stream, and replace the 20 s poll. Intent states map onto the ring; the output panel becomes the intent's transcript tail.
10. **Act from the graph (M).** The step bar maps onto controls that already exist as endpoints: pause, resume, cancel, steer, and the new hint state. Select an intent on the canvas and act on it there instead of switching to the sessions tab.
11. **Schema-driven parameter form + server-computed command preview (M).** `ParamDrawer` renders a form from a manifest's params; `POST /nodes/:id/preview` returns the exact argv from the same resolver that executes. m1nervac0nsole's manifests already carry the data; this gives operator-run tools with a form and no wrong-flag surprises.
12. **Undo signature trick and insert-between edge (S)** - only once the canvas is editable (item 6).

Not pulling: reactflow 11 itself (already on v12), the assistant's CLI/PTY runner, whole-canvas replace on apply, the manifest layer (ours is the superset).

## 4. Outside the two areas, briefly
- **Expose the engagement as an MCP server (S-M).** m1nervac0nsole consumes MCP but does not serve it. `POST /mcp` with a per-session scoped token and a profile allow-list enforced in both `tools/list` and `tools/call` would let an external agent CLI join a task. Highest-leverage idea in the repo outside the two areas.
- **Scope rule model (S).** `{effect, pattern, note}`; exclude always wins, longest include wins, no match is `unknown` rather than out. About 120 dependency-free lines.
- **Findings upsert rule (S).** Dedupe on (target, lower(title)), refresh evidence, never reopen a status a human set.
- **Prompt text.** The impact gate ("as an attacker I could ...") and the reporter's structure are the best writing in the repo.

## Suggested order
1. Item 9 (live exploration graph) - smallest, visible immediately, no new subsystem.
2. Items 2 + 4 with the Playwright MCP enabled - browser traffic as evidence and operator hand-off, almost no new code; shows whether a custom driver is needed.
3. Items 1 + 3 - own driver and live view, if step 2 shows the MCP path is too limited.
4. Item 6 with 7 - plan drafting.
5. Items 10, 11; item 8 only after a decision that deterministic playbooks are wanted.

## Not verified
- No Chromium was run: screencast frame rate, bandwidth and input latency over the lab's network are unknown.
- The Playwright MCP row being disabled means "workers have a browser" is a configuration fact, not something observed in a task.
- Effort sizes are the reviewers' estimates from reading code.

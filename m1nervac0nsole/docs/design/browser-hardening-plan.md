# Browser driver hardening (Plan C follow-up)

Companion to `executioner-implementation-plan.md` (Plan C, shipped 2026-11-13). This
file is the build plan for the defects and gaps found by reading the shipped code
against the plan's own promises. Nothing here is implemented.

Paths are under `m1nervac0nsole/`. Every item names the file it changes, the test
that proves it, and what an operator would observe.

## Status

| # | Issue | Severity | Effort |
|---|---|---|---|
| H1 | Idle reaper closes a browser under a running intent | correctness | S |
| H2 | Operator input leaves no activity row | audit | S |
| H3 | No `browser_close`, no cap on concurrent browsers | resource | S |
| H4 | `browser_navigate` returns no snapshot, `browser_open` does | cost | S |
| H5 | Out-of-scope subresource requests still leave the guest | boundary | M |
| H6 | No console or JS-error surface | capability | S |
| H7 | No download handling | capability | S |
| H8 | Snapshot is all-or-nothing | cost | S |
| H9 | No iframe support | capability | M, optional |
| H10 | Live view shows no page state; agent and operator can act at once | correctness | M |
| H11 | Screencast geometry and quality are fixed | cost | S |
| H12 | The real-Chromium test never runs in CI | verification | S |
| H13 | `browser_select` drives native `<select>` only | limitation | document |

Order: H1, H2, H4, H3 -> H6, H7, H8 -> H5 -> H10 -> H12 -> H9.

---

## H1 - The reaper must not close a browser under a running intent

Today: `reapBrowsers` (`server/browser_registry.go:113`) closes every session whose
`lastUsed` is older than `browserIdleTimeout` (10 min). A worker that logs in, then
spends 12 minutes on a scan, returns to a fresh page: the profile keeps its cookies,
but the tab, the URL and any in-page state are gone, and the next `browser_click`
acts on a blank page. The tool call succeeds, which is the worst part.

Change
1. `browserFor` sets `lastUsed` on every tool call (verify it does; if not, set it).
2. `reapBrowsers` skips a task with a running intent. Add
   `Engine.HasRunningWork(taskID string) bool` over `e.work` (already mutex-guarded),
   or reuse `ExplorationStore.HasActiveIntent` when the engine has no work entry.
3. Keep the 10-minute timeout; a session with no running intent and no tool call is
   genuinely idle.

Tests: a session idle 11 minutes with a running intent survives; the same session
with no running intent is closed; a tool call bumps `lastUsed`.

Acceptance: a 15-minute scan between two browser steps keeps the same page and the
same snapshot refs.

Risk: a `work` entry that leaks (a worker that died without cleanup) would pin a
browser forever. Mitigation: the engine's work map is already cleared on intent end;
the reaper logs what it skipped so a leak is visible.

---

## H2 - Operator input is an audited action

Today: `browserInput` (`server/browser_live.go:303`) dispatches the event and returns
`{"ok": true}`. An operator typing a password or clicking "delete" in the live view
leaves nothing in the task feed, so the timeline and the training export show a page
that changed by itself.

Change
1. Emit one activity row per input burst: `db.Activity{Kind: "text", Worker:
   "operator", Summary: "operator <kind> on <url>"}`.
2. Debounce to one row per task per 2 seconds, so a drag does not write a hundred rows.
3. Never include `Text`, `Key` or `PromptText` in the row. The URL is enough to
   reconstruct what was driven.

Tests: one burst writes one row; the row carries the URL and the kind and no typed
text; two bursts 3 seconds apart write two rows.

Acceptance: the task feed shows "operator mouse on https://target/login" before the
page changes.

---

## H3 - `browser_close` and a cap on concurrent browsers

Today: a session lives until the reaper. Nothing lets an agent say it is done, and
nothing bounds how many Chromium processes a 4 vCPU / 8 GiB guest runs.

Change
1. `browser_close` tool: idempotent, returns `closed` or `no session`, bound to the
   same agents as the rest. It does not need a ref.
2. `browserMaxSessions = 4`. `launchBrowser` checks the count; at the cap it closes
   the least-recently-used session that has no running intent, and if every session
   is busy it returns "all N browser sessions are busy; close one or wait".
3. Log every eviction with the task id and the reason.

Tests: the cap evicts the oldest idle session; a refusal when all sessions are busy;
`browser_close` twice is not an error.

Acceptance: five tasks with browsers leave four running and the fifth evicting the
oldest idle one.

---

## H4 - `browser_navigate` returns the snapshot

Today: `browser_open` returns the page line plus the tree; `browser_navigate` returns
the page line only, so every navigation costs a second call.

Change: return the snapshot from `browser_navigate` exactly as `browser_open` does.
Both tools already share `pageLine`; the extra call is `drv.Snapshot`.

Tests: the navigate result contains `- role` lines.

Acceptance: one navigation, one snapshot, one turn.

---

## H5 - Refuse out-of-scope requests before they leave

Today: the guard judges the URL argument and the landing page (`pageLine` exists so
the guard can read `- Page URL:`). A redirect, an `<img>`, an XHR or a click's
subresource is fetched and recorded before the post-check. The recorder is the
evidence store, so an excluded host ends up in the task's traffic.

Change
1. `browser.Options.AllowRequest func(rawURL string) error`. Nil means allow
   everything, which keeps the package usable without a scope.
2. On launch with a non-nil callback, `Fetch.enable` with `patterns: [{urlPattern:
   "*", requestStage: "Request"}]`; on `Fetch.requestPaused` call the callback and
   either `Fetch.continueRequest` or `Fetch.failRequest {errorReason:
   "BlockedByClient"}`.
3. The server passes a callback that resolves the host through
   `db.NewTaskScopeChecker` with a 60-second per-host cache, so a page with 200
   requests to one host costs one lookup.
4. Collect the blocked hosts per tool call and append one line to the result:
   `blocked 3 out-of-scope requests: cdn.thirdparty.example`.
5. Fail closed: a callback error blocks the request.

Tests: a paused request for an excluded host is failed and reported; an allowed one
is continued; the cache means one checker call for two requests to the same host; a
callback error blocks.

Acceptance: a page that includes an image from an excluded host produces zero
requests to that host in the recorder, and the tool result names it.

Risk: `Fetch` interception adds a round trip per request; measure a 200-request page
before and after. The interception happens inside the browser, before the proxy, so
it composes with `--proxy-server` without touching the recorder.

---

## H6 - Console and JS errors

Today: a page that fails to render yields an empty snapshot and no reason.

Change
1. `Runtime.enable` on launch; buffer `Runtime.consoleAPICalled` (type, text, url)
   and `Runtime.exceptionThrown` (message, url, line) in a ring of 200 entries with
   a sequence number.
2. `browser_log {since?, limit?}` returns `{entries, next}`; `since` is the cursor
   from the previous call, the same idiom as the traffic tools.
3. The snapshot tool appends a one-line note when new errors arrived since the last
   call, so the agent does not have to poll.

Tests: events land in order with increasing seq; the ring caps at 200; `since`
returns only newer entries; an error is summarised in the snapshot note.

Acceptance: a page with `throw new Error("boom")` shows it in `browser_log`.

---

## H7 - Downloads reach the workspace

Today: clicking "export CSV" downloads to a temp directory nobody sees.

Change
1. After launch, `Browser.setDownloadBehavior {behavior: "allow", downloadPath:
   <task dir>/downloads, eventsEnabled: true}`.
2. Track `Browser.downloadWillBegin` and `Browser.downloadProgress`; keep the
   completed paths.
3. Append `downloaded: tasks/<id>/downloads/<name>` to the result of the next tool
   call after a download completes, and expose them through `browser_log` as
   `download` entries.

Tests: a completed download is reported once; a cancelled one is not.

Acceptance: a CSV link click yields a file path the agent can read with Bash.

---

## H8 - Snapshot a subtree

Today: the snapshot is the whole page, capped at 2,000 lines. A large page costs the
context and a form deep in it is still buried.

Change: `browser_snapshot {ref?, max_lines?}`. With a ref, filter the flat AX tree to
that node's descendants (walk `parentId`); `max_lines` defaults to 2,000 and caps at
4,000. Without a ref, behaviour is unchanged.

Tests: a ref returns only its subtree; a leaf returns its own line; the cap truncates
with a marker.

Acceptance: a ref to a form returns the form, not the page.

---

## H9 - Iframes (optional, last)

Today: a login inside an iframe is invisible to the snapshot.

Change: `Target.setAutoAttach {autoAttach: true, waitForDebuggerOnStart: false,
flatten: true}`; every `Send` gains an optional session id; the snapshot walks the
attached frames and prefixes each block with `[frame=fN]`; refs carry the session so
an action lands in the right frame.

Tests: a two-frame fixture yields both blocks; a ref from frame 2 clicks inside
frame 2.

Acceptance: a login rendered in an iframe is solvable.

Risk: flatten mode changes the shape of every command, so it is the one item that
touches the whole driver. Do it only when a real engagement needs it; until then the
skill states the limit.

---

## H10 - The live view shows the page and owns the pointer

Today: the stream carries frames, the viewport and dialogs; it does not carry the URL
or the title, and the agent can act while the operator drives.

Change
1. Emit a `page` event ({url, title}) whenever `Page.frameNavigated` fires on the
   top frame, and once on stream start.
2. Implement the ownership Plan C specified: while an operator holds the slot, the
   agent's browser tools return "the operator has the page" instead of acting;
   releasing the slot (DELETE or disconnect) hands it back. The slot already exists;
   this adds the check in `browserRefAction` and the two navigation tools.
3. The tab shows the URL, the title, and "the agent is acting" when a tool call is in
   flight.

Tests: a tool call while the operator holds the slot returns the refusal and does not
reach CDP; releasing allows it; a navigation emits one `page` event.

Acceptance: an operator solves a CAPTCHA without the agent clicking underneath them.

---

## H11 - Screencast geometry per viewer

Today: `liveViewportWidth/Height` are constants and quality is 60.

Change: `GET /api/tasks/{id}/browser/stream?width=&height=&quality=` clamped to
320-1920, 240-1200 and 20-90. The viewport restore already records the agent's size,
so a custom size is safe.

Tests: clamping; the restore still uses the recorded size.

Acceptance: a 960x600 view moves roughly half the bytes.

---

## H12 - Run the real-Chromium test in CI

Today: `TestIntegrationRealChromium` is env-gated and CI never sets the flag, so the
only proof the driver works is a manual lab run.

Change
1. Add `browser-actions/setup-chrome` to the `go-db` job in `.github/workflows/ci.yml`
   and pass its path as `M1NERVAC0NSOLE_CHROMIUM`.
2. `browserExecutable` and the integration test read that variable first.
3. Run `go test ./browser/ -run TestIntegration -count=1` in the job.

Tests: the job itself.

Acceptance: a green CI run that launched a real Chromium.

---

## H13 - `browser_select` and custom dropdowns

Not a defect: `browser_select` drives a native `<select>`. A custom dropdown needs a
click on the trigger and a click on the option. Document it in
`skills/browser/SKILL.md` and leave the tool alone; a second tool would be a wrapper
around two clicks.

---

## Open decisions

1. H5: is a per-request scope lookup acceptable on the hot path, or should the
   callback only consult a pre-resolved host set built at task start?
2. H3: is 4 the right cap on the lab VM, or should it follow `workers`?
3. H9: do any current engagements need iframes, or is documenting the limit enough?
4. H10: should the operator's slot expire automatically (for example after 5 idle
   minutes) so a closed tab cannot lock the agent out?

## Not in this plan

`browser_eval` (still out), CDP network capture and rewrite rules (the recorder is
the evidence store), Electron-style embedded views, and any change to the MCP path.

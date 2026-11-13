<!-- Design record (2026-11-13). Browser gate closed; Plan C closed. -->

# Open items: what is left and how to close each

State at the time of writing: `checkpoint/memory-refactor` holds the cutover, the memory refactor, the reviewer fixes, and Plans A and B from the Executioner pull. CI is green on that branch. What follows is the remaining work, in the order it should happen. Detail for C/D/E lives in `local://executioner-implementation-plan.md`; this file adds the gate, the acceptance criteria and the release steps.

---

## 0. Release the current work (S)

1. `git checkout main && git merge --ff-only checkpoint/memory-refactor && git push` (CI already green on the branch; the merge commit is a fast-forward, so `main` inherits the same tree).
2. `./lab build && ./lab stop && ./lab start --vpn vpn-profiles/machines_us-4.ovpn` (the guest runs the pre-fix binary until this).
3. Verify in the guest: `GET /api/health` 200; `SELECT name, enabled FROM mcp_servers WHERE name IN ('browser','obscura')` shows `browser` enabled; `GET /api/memory/preview?task_id=1` still renders; open a task's graph tab and confirm it updates without a manual refresh.
4. If `main` is protected against direct pushes, open a PR from the checkpoint branch instead and merge after CI.

Risk: the browser MCP being enabled means every worker can now spawn Chromium. If a task does not need it, the cost is a process per worker; the skill gates use, but nothing stops a worker from opening a page. Watch the first task's memory and CPU.

---

## 1. Browser verification run (M) - closes the Plan B gate and decides Plan C

### First run (2026-11-13) - result: inconclusive, with three findings

Fixture: `/tmp/browser_fixture.py` served in the guest at `172.16.0.6:8099` (JS-injected CSRF, session cookie, `/admin`, a CAPTCHA page, a 302 to an excluded host). Task 2, scope include `172.16.0.6`, exclude `offscope.invalid`, goal "log in and reach /admin".

| Measurement | Result |
|---|---|
| Browser tools visible to the worker | **yes** - `mcp__browser__` appears in 14 of 15 worker prompts (`llm_records.request_body`) |
| Browser tool calls | **0** - the worker used Bash (14 calls), `tcp_probe`, `traffic_search` |
| Did it log in | yes, with `curl --noproxy '*'` and by guessing the CSRF format (`for t in "tok-" "tok-1" "abc"`), because the fixture only required the `tok-` prefix |
| Traffic captured | the first request through the recording proxy returned **502 Bad Gateway** for `172.16.0.6:8099`; the worker then bypassed the proxy with `--noproxy` and completed the flow |
| Hand-off / screenshot | not exercised (no CAPTCHA reached) |
| Task outcome | `done`, 4 findings recorded |

Findings, in order of importance:
1. **The recording proxy forwards nothing in this deployment.** Diagnosed: go-mitmproxy always CONNECTs to its upstream even for `http://` targets, and the egress proxy terminates every CONNECT as TLS, so plaintext HTTP dies inside the tunnel (502). HTTPS works when the client trusts the recorder CA. Full diagnosis, options and verification: `local://mitmproxy-egress-plan.md`. **This blocks the browser verification**: fix it first.
2. **The agent does not reach for the browser when curl appears to work.** The tools were listed in 14 of 15 worker prompts and the `browser` skill was visible, yet it never loaded the skill. That is a behaviour problem, not a wiring problem, so Plan C's driver would not fix it.
3. **The fixture was too weak.** Requiring only a `tok-` prefix let the agent guess the token (`for t in "tok-" "tok-1" "abc"`), so the run never needed JavaScript. A strict fixture (token validated against a server-side value the page computes, or a page whose form only exists after JS) is required for a decisive answer.

Decision: **do not start Plan C.** The gate's condition (a) "snapshot too poor" and (b) "operator cannot take over" were never exercised; condition (c) "scope bypass" did not occur. Fix finding 1, strengthen the fixture, re-run, and only then judge Plan C.

### Second and third runs (2026-11-13) - the relay fix, then the binding fix

Run 2 (strict fixture, relay not yet fixed): the worker hit the fixture 8 times and never used the browser; `SearchExtraTools` was called 6 times.

Run 3 (relay fixed, browser MCP bound directly to auto/pentest/worker/planner): still zero browser calls, and the reason is now visible - the MCP never connected. `mcp_servers.last_connect_ok = false`, `last_connect_err = "connect: mcp: connection closed"`, recorded during the run. The same command with the same args and env handshakes correctly from a shell in the guest (`initialize` answers with `serverInfo Playwright 1.64.0-alpha`), so the server is fine and the failure is in the app's spawn path. The SDK discards the child's stderr (`third_party/norma/mcp/stdio.go:32-61`), which is why the reason is invisible.

Next task, in order:
1. **Capture the child's stderr** in the stdio MCP client and include it in the initialize error (vendored SDK, three-way merge - or a first-party wrapper that pipes stderr). Without it every MCP connection failure is opaque.
2. Re-run the gate. If the browser then connects and is used, judge Plan C on snapshot quality and hand-off; if it connects and is still not used, the problem is prompt-level, not tooling.

The relay fix is verified independently: `curl -x 127.0.0.1:8788 http://example.com/` returns 200 and `-k https://...` returns 200 in the deployed guest.

### Done (2026-11-13, commit 09d9b43)

1. The stdio client now carries the child's last 4 KiB of stderr in the initialize error (`third_party/norma/mcp/stdio.go`), with tests.
2. Three startup faults, each hidden by the previous: `npx` hung because every child inherits `http_proxy` to the egress proxy (the image's global `playwright-mcp` is used instead); the MCP wanted the branded Chrome channel or a chromium revision the image lacks (`--executable-path /opt/ms-playwright/current/chrome`, a stable link the image now builds); Chromium refuses to start as root (`--no-sandbox`) and does not read `NODE_EXTRA_CA_CERTS` (`--ignore-https-errors`, added with the proxy). One-shot migrations rewrite only an untouched seeded row.

Measured in the guest: connect + tools/list in 0.5 s, `https://example.com` navigated through the recorder in 1.1 s. The gate fixture now lives in `m1nervac0nsole/tests/fixtures/browser_gate.py` and never prints its flag.

### Run 4 (task 5) - the browser is available, the model prefers curl

| Measurement | Result |
|---|---|
| prompts containing `mcp__browser__` | 30 of 32 |
| browser tool calls | 0 |
| fixture hits | 39 GET /login, 26 POST 403, 22 POST 302, 12 GET /dashboard 200 |
| outcome | done in 2.5 min, flag GATE-026ff9c07719b36e |

The worker read the page with curl, computed the token from the script and solved it. The wiring is now proven; **tool choice is the remaining gap**, and a custom driver does not change what the model reaches for. Plan C stays unjustified until a run shows the browser used and its snapshot found wanting.




### Protocol for the re-run

The whole point of Plan B was to avoid building Plan C on speculation. Run this before writing any driver code.

**Fixture.** A local target with a JavaScript login form behind a redirect, served from the guest or the host: `/login` (form + CSRF token injected by JS) -> `/dashboard` (session cookie) -> `/admin` (403 unless the cookie is present), plus one CAPTCHA-shaped page (an image and a text field) and one out-of-scope host in the task's exclusions.

**Task.** One task, scope = the fixture host, goal "log in and reach /admin". Let the planner run with the browser skill available.

**Record** (one row per question, from the task's activity and traffic index):
| Question | How to read it |
|---|---|
| Did a worker open the browser at all? | `mcp__browser__*` calls in the activity log |
| Did it re-snapshot after an action, or act on stale refs? | count of `STALE_REF`-shaped errors vs successful actions |
| Did the login succeed? | `/dashboard` reached; session cookie present in the traffic index |
| Did the traffic land in the recording proxy and become pinnable? | request rows for the fixture host; bind one to a finding |
| Did the CAPTCHA page trigger a hand-off? | `ask_operator` call, intent paused, question names the page |
| Was the screenshot named by path (not attached)? | hand-off text contains `uploads/`; activity detail has no attachment |
| Did an out-of-scope navigation get refused? | a refusal naming the host, and no request to that host in the proxy |
| Did a redirect off-scope get caught? | the landing-page refusal, and the request visible in the proxy |
| Token cost of the browser loop | LLM records for the intents that used it, compared with a non-browser intent |

**Decision rule.** Build Plan C only if at least one of these is true: (a) the snapshot is too poor to act on (repeated stale refs or wrong elements), (b) the operator needs to take over the page (the CAPTCHA hand-off is unusable because the operator cannot see or act on the live page), or (c) scope enforcement is bypassed in practice. If none holds, close Plan C as "not needed" and spend the effort on Plan D.

---

## 2. Plan C - own driver and live operator view (M + M), only if the gate fires

**C1 driver** (`browser/` package, Go, chromedp or rod):
- A two-method CDP seam (`Send`, `On`) so the driver is unit-testable against a fake CDP - this is the one design decision worth copying from Executioner.
- Snapshot from `Accessibility.getFullAXTree`, rendered `- role "name" [ref=g3e17]`, 2,000-line cap, refs invalidated on top-level navigation, `STALE_REF` error text. Improve on the original: render value, checked, disabled, required.
- Tools: `browser_open`, `_navigate`, `_snapshot`, `_click`, `_type`, `_press`, `_select`, `_wait`, `_screenshot`, `_upload`. Every mutating tool takes `dialog?`/`promptText?`. No `browser_eval`.
- Launch Chromium with `--proxy-server <recording proxy>` and the MITM CA, one `--user-data-dir` per task; navigation goes through the existing scope guard (reuse `server/mcp_scope.go`'s `browserURLHost` + `scopeRefusal` so there is one boundary implementation, not two).
- Network history comes from the proxy index, not CDP: `browser_network {since, urlContains, limit}` -> `{entries, next}`, `browser_response_body {id, offset, maxBytes}`.
- Acceptance: the fixture run in section 1 passes with the driver swapped in, with no change to the skill.

**C2 live view and take-over** (only if the gate's reason (b) fired):
- `Page.startScreencast` frames to the UI; input forwarded back. The product has no WebSocket, so either add one endpoint (`GET /api/tasks/{id}/browser/{bid}/live`) or use SSE for frames plus a POST for input - decide by measuring frame rate first, with a throwaway page that streams 10 fps.
- Ownership flag (`agent` | `operator`) so agent tools report "operator has the page" instead of acting.
- Ask protocol on top of `ask_operator`: join a pending ask instead of re-notifying, `{pending:true}` on agent timeout, keep an unclaimed operator answer for 30 minutes.
- Acceptance: a human solves the CAPTCHA page from the task detail tab and the run resumes with the answer.

---

## 3. Plan D - engagement-plan drafting (M-L)

The pattern: catalogue as a tool, proposal as a validated tool call, operator review, transactional apply.

1. Schema (`db/schema.sql`, parent-owned): `plan_drafts(id, task_id, status draft|applied|discarded, summary, proposal JSONB, created_at, applied_at)`.
2. Proposal contract (Go struct, reused as the tool schema):
   ```json
   { "summary": "...",
     "goals":   [{"ref":"g1","title":"...","success":"..."}],
     "intents": [{"ref":"i1","goal":"g1","description":"...","asset_ids":[12],"depends_on":[]}],
     "hints":   [{"text":"...","rule":true}],
     "scope":   [{"effect":"exclude","pattern":"*.thirdparty.example","note":"..."}] }
   ```
3. A propose-only agent (same chat stack and binding pattern as the curator): tools `plan_context` (goal, scope, asset summary, existing goals/intents/hints), `list_tools` (projection of `manifest/builtin/*.toml`), `propose_plan`. On invalid output the tool returns the errors so the model retries.
4. Validation (pure Go, table tests): unique refs, every intent points at a goal, `depends_on` acyclic, `asset_ids` belong to the task, scope patterns parse via `scope.Problem`, counts bounded (8 goals, 24 intents).
5. Apply: `POST /api/tasks/{id}/plan/{draft}/apply` creates goals, open intents, hints and scope rows in one transaction, records the created ids so an unstarted plan can be reverted, marks the draft applied, wakes the planner. `DELETE` discards.
6. Web: "Draft a plan" on task detail - chat panel, proposal preview on the exploration-graph canvas with the existing layout, Apply/Discard.
7. Acceptance: a plain-language request on the fixture task yields a draft; applying it creates exactly the listed nodes; the planner's next round sees them and does not duplicate them.

---

## 4. Plan E - smaller pulls (each S, independent, any order)

- **E1 command preview**: `POST /api/tools/{id}/preview` returning the argv from the same resolver that executes; a schema-driven parameter form in the UI. Test: preview equals the executed argv for every golden manifest case.
- **E2 findings upsert**: dedupe on (target, lower(title)), refresh evidence, never reopen a status a human set.
- **E3 scope rule model**: `{effect, pattern, note}` with exclude-wins and unknown-not-out; decide how it composes with the existing `scope/` boundary hook before writing code.
- **E4 engagement as an MCP server**: `POST /mcp` with a per-session scoped token and a profile allow-list enforced in both `tools/list` and `tools/call`; read-only tools first, security review before any write tool.
- **E5 prompt text**: the impact gate ("as an attacker I could ...") and the reporter's structure into the worker and finding-report prompts.

---

## 5. Known limits to keep in view

- The browser scope guard judges the argument and the reported landing page; a page can still *contain* links to off-scope hosts, and following one is a navigation that is judged. The proxy records every request either way.
- `browser_evaluate` (Playwright) takes no URL and is not judged. The skill forbids using it to sidestep the boundary; a hard block is a separate decision.
- The one-shot migration flips a pre-upgrade deliberate disable of the browser MCP once. Distinguishing it would need a per-row provenance marker.
- The review queue's redaction preview still compiles one regexp per identifier per field per candidate (M10 was not done).

# Unified network boundary and browser roles

Status: implemented, deployed and verified (2026-11-15). The running guest reports `413dffd-dirty`, `execbox probe` exits 0, the gateway refuses a request with no session credential, and `deployment/verify_completeness.py` proves the keylog fixture decrypts the gateway's origin flow. The gate figures below are from the 2026-11-14 pass. Verified: `go build ./...` and `go vet ./...` clean; `go test -p 1 ./...` green against a fresh PostgreSQL apart from one pre-existing host-timezone assertion in `enrich/proxy_failure_test.go` that fails identically on a clean HEAD worktree; `npm run check`, `npm run test -- --run` (138 tests) and `npm run build:static` green; `scripts/check-cjk.py`, `scripts/check-doc-links.py` and `tests/python` (157 tests) green. The acceptance matrix is covered by tests for policy denial before the dial, the single interception boundary, WSS, SSE, a 6 MiB body, honest failure recording, the research guard and its allow-list, curator install approval and publish, and the refusal of an unauthenticated CONNECT; the kernel boundary was proven by running the `execbox` kernel suite inside the guest, where every test PASSes with isolation verified (uid drop, netns/veth/iptables, cgroup v2, mount namespace, setpriv). Blocked on deployment: the guest image rebuild, the privileged supervisor install and the VPN/resolver health checks are unexercised outside a deployment. The tool-facing credential gap is closed: `netpolicy.ProxyURL` is the one construction site for a tool proxy URL (gateway address plus the run session's credential, empty when the run has no session), and the Bash/WebFetch env, Chromium `--proxy-server`, the custom `http` transport and `run_tool`'s argv and child env all take it from the session of the run they belong to; `manifest.SetProxy` is gone, and `server.TestNoToolFacingProxyURLIsBare` walks those sites so a bare address cannot come back. Accepted residuals: the application process still runs as root in the guest and only tool processes drop to uid 1000; in-process tools (`Read`/`Write`/`Edit`/`MultiEdit`/`LS`/`Glob`/`Grep`, `tcp_probe`, `WebFetch`, custom `http`, `create_skill`/`update_skill_file`, `browser_upload`, `ask_operator` staging) run in the backend outside the subprocess boundary; `Grep` falls back to its in-process implementation because its call site carries no context to give rg a session; the masking `egress-proxy` stays for asset-enrichment probes until the gateway can serve them; and a task's Chromium keeps the credential of the run that launched it for the life of the process, so a revoke ends that browser's authority until it is relaunched.

## Goal and completion contract

Implement the approved architecture completely: one HTTP interception and origin-transport path, backend-issued session policy, honest streaming evidence, isolated unprivileged tool processes, Obscura for research, native Chromium for testing, and an isolated Tool Curator ingest/install/validate/approve flow. Preserve model-provider separation, operator controls, raw-network testing capability, existing evidence, profiles and custom prompts.

A proxy environment variable, agent instruction, successful unit test, or configured-but-unexercised namespace is not proof of enforcement. Missing kernel capability must refuse tool execution; never fall back to unrestricted execution. No task restart or live host/guest firewall change without a separate deployment decision.

## Decisions

- Research and testing are distinct backend-issued purposes. An agent cannot select another task, promote itself to testing, or choose a privileged installation purpose through tool arguments.
- Research uses Obscura. Expose reading/extraction operations, not arbitrary evaluate, cookies/storage mutation or a second general testing browser. Use a separate profile per research session, never engagement cookies/credentials.
- Testing uses the existing Chromium/CDP driver. Task-bound chat carries its task context; unbound chat has research only. Workers and authorized task-bound testing agents get the existing browser tools. Planner delegates testing rather than acquiring another browser engine.
- Authorized destinations are operator-maintained scope rules, separate from discovered asset graph entries. Missing or unreadable authorization is fail-closed for testing. Discovered hosts do not expand access. Research refuses protected/internal addresses and known target destinations, including redirect and subresource connections.
- HTTP gateway applies session lookup, destination/port/protocol authorization, DNS/address checks, rate admission, origin transport, and evidence capture. Only one TLS interception boundary remains.
- Keep the existing recorder storage/evidence APIs. Prefer a minimal pinned extension of the current MITM dependency for replaceable origin transport and stream observation over writing another HTTP parser. Retain upstream license/provenance; no edits to the module cache. Exact patch surface is settled by the transport feasibility slice.
- Reuse uTLS and existing HTTP libraries. Preserve browser/API request semantics and repeated headers. Browser-like TLS is not a promise of Chrome-identical HTTP/2 or undetectability.
- Strict origin TLS by default. A certificate exception is explicit, narrowly authority/task-bound, and attached to evidence; it does not allow direct fallback. Preserve self-signed lab targets through an operator-visible exception mechanism.
- All requests count once, including subresources. Rate policy allows an explicit bounded burst, does not charge CONNECT as another HTTP request, and does not claim run-concurrency reservations enforce packet rates.
- global_proxy becomes the gateway's upstream exit, not a replacement for the gateway. VPN routing, DNS and any required tunnel failure are enforced by the privileged network boundary, not process-liveness checks alone.
- Model credentials and host-provider access remain in the backend/control plane. Tool namespaces cannot reach PostgreSQL, host services, control sockets, application credentials or another task's files.
- Existing stored data is preserved. Do not derive new authorization from old discovered assets. Existing tasks lacking explicit authorization are visibly blocked until the operator supplies it. Never auto-resume or restart them.
- Preserve edited prompts. Migrate only exact known built-in defaults; otherwise display the required behavioral change without overwriting user text.

## Threat and protocol contract

The backend/supervisor is trusted; tool code, browser pages, cloned repositories, MCP child processes and their output are untrusted. Tools may ignore proxy settings or try raw sockets, alternate DNS, redirects, loopback access, procfs, symlinks and subprocess escapes. A tool must not read controller credentials, use another session's gateway authority, or forge task identity.

Network enforcement covers IPv4 and IPv6; DNS results are checked and pinned to the actual dial, including multiple A/AAAA records and rebinding. Hostname, CIDR, port and protocol grants are explicit. A broader CIDR must not permit an excluded subrange. Gateway resolves HTTP destinations; approved raw tools use controlled DNS and task packet policy. Domain grants do not silently become a shared-IP hostname bypass for HTTP.

HTTP/1.1, HTTP/2, CONNECT, streaming, SSE, WebSocket upgrades, cancellation and connection reuse must work through the same policy. Unsupported CONNECT protocols fail explicitly; supported raw protocols take the raw-tool path rather than opaque HTTP-gateway tunnels. HTTP/3/QUIC and browser networking outside the HTTP gateway are blocked unless separately implemented and authorized. No automatic unrecorded passthrough.

## Resolved decisions (from feasibility slices)

1. **Transport.** go-mitmproxy v1.9.2 exposes no origin dial/handshake/round-trip seam, and an addon cannot deny a CONNECT before the dial or take over WSS. The gateway therefore adds one `Options.OriginTransport` hook by a pinned 7-hunk patch (6 files), delivered as a `replace`d module copy at `m1nervac0nsole/third_party/go-mitmproxy/` with `LICENSE` and a `PATCH` file naming base tag v1.9.2. Nil hook keeps upstream behaviour. On the pinned Go 1.26 toolchain `http.Transport` cannot do h2 over a uTLS conn (golang/go#78201), so the hook uses `http2.Transport` explicitly. `ServerConn.tlsConn` becomes `net.Conn`. `useSeparateClient` and `directTransfer` route through the hook. Buffered/streamed/SSE/WS observation stays in the dependency; only `sink` gains hooks.
2. **Isolation.** The guest supports network namespaces, user+network namespaces, cgroup v2, iptables, `setpriv`/`runuser` and a non-root `node` uid; `nft`, `bwrap`, `firejail`, `newuidmap` are absent and Landlock would need a new dependency. Mechanism: per-session netns + veth, iptables in the root namespace admitting only the gateway and resolver, mount namespace with bind mounts, `setpriv` to uid 1000 with no capabilities, cgroup v2 for accounting. In-process tools (`Read`/`Write`/`Edit`/`MultiEdit`/`LS`/`Glob`/`Grep`), `tcp_probe`, `WebFetch`, custom `http`, `create_skill`/`update_skill_file`, `browser_upload` and `ask_operator` staging bypass subprocess isolation and must move behind the supervisor or the backend must be confined.
3. **Authorization.** `task_scope_rules` is the only operator-written, discovery-free boundary table; it lacks port, protocol, purpose, approver and revision. `scope.Evaluate` cannot serve as authorization (Unknown is never Out, includes are auto-written from discovery and by the model). Delta: add port/protocol/scope/authorization columns to `task_scope_rules` (existing rows stay non-authorizing), new `cert_exceptions` and `policy_audit` tables, `tasks.policy_revision` with a bump trigger. Every existing task becomes unauthorized-by-default and is surfaced read-only.

## Binding interface contract

```go
// package netpolicy (new, first-party)
type Purpose string // research | testing | install

type Session struct {
    ID             string
    TaskID         int64 // 0 for unbound chat
    ConversationID int64
    Purpose        Purpose
    Revision       int64
    Credential     string // what the gateway resolves the session from; never logged
}

// ProxyURL is the one construction site for a tool-facing proxy URL: addr with
// the session credential, or "" when the session has none or addr is empty.
func ProxyURL(s Session, addr string) string

type Destination struct {
    Scheme   string // http, https, or "" for raw
    Host     string
    Port     int
    Protocol string // http, ws, tcp, udp, dns
}

type Decision struct {
    Allow  bool
    Stage  string // policy | dns | dial | tls | transport
    Reason string
}

type Authorizer interface {
    Authorize(ctx context.Context, s Session, d Destination) Decision
}

// Implemented by the gateway hook and consumed by the supervisor.
type Exit struct {
    ProxyURL string // operator global proxy; empty = direct
}
```

`Session` is issued by the backend from server-side state (task row, conversation row, purpose chosen by the calling subsystem), never from tool arguments. `Revision` is `tasks.policy_revision`; any change invalidates caches and pooled connections.

## Work packages and ownership

### A. Immediate boundary repairs

Own narrow existing paths: SDK WebFetch, custom HTTP proxy construction and resolved-URL checks, browser upload containment, remote MCP transports, provider key reuse, admin-origin/session ingress.

- Remove WebFetch's direct retry and explicitly propagate configured transport failures.
- Correct URL-valued proxy handling; insecure TLS settings must not implicitly select a direct route.
- Restrict legacy MCP SSE message endpoints to the configured origin before sending any credentials; preserve lawful relative endpoints.
- Root browser uploads in the current task workspace with descriptor/rooted-file protections, not lexical path checks; prevent cross-task and symlink escapes.
- Borrow a stored provider key only with its stored effective endpoint, including default endpoints.
- Remove browser-readable authentication cookies; enforce origin/CSRF semantics for cookie-authenticated mutations while preserving external bearer clients and development UI. Do not expose a new admin route or weaken scoped /mcp tokens.
- Add consumer-visible regression tests; no broad unrelated cleanup.

### B. Authorization and session identity

Own new policy/session package and DB authorization accessors; shared schema changes and route wiring have one integration owner.

- Reuse explicit operator scope rules where they distinguish authorization from discovery. Add only missing persisted fields for ports/protocols, origin-cert exceptions and operator-approved policy changes.
- Session identity: purpose, task or conversation identity, allowed capability set, policy revision and lifetime. Issue in trusted backend context, bind to execution process/network identity, revoke on end/cancel and policy change. No client-supplied purpose/task escalation.
- Policy checks return structured allow/deny/reason; missing policy or DB failure denies. Exact grant revisions invalidate caches and close disallowed long-lived sessions/connections.
- Provide research and testing policy constructors and a controlled resolver/dial contract. Deny private/link-local/metadata/control-plane access for public research, and known target domains/IPs. Approvals grant only the required operation, never a permanent generic bypass.
- Operator API/UI: view current effective policy, edit explicit grants, approve a certificate exception, and see why a task is blocked. Auditable changes and deterministic migrations.

### C. Single gateway and origin transport

Own traffic/, egress/ extraction and the pinned MITM extension. Reuse B's interfaces.

- One gateway owns session validation, request authorization, HTTP-aware proxy chaining, origin TLS and post-transform evidence.
- Extend the dependency at the origin-dial/round-trip and stream-observation seams; do not replace maintained protocol machinery with another hand parser.
- Carry verified authority and selected IP to dial; authorize redirect requests and each distinct destination; distinguish infrastructure, policy, transport, origin TLS and target HTTP failures.
- Preserve HTTP semantics: Accept, Fetch Metadata, authorization, cookies, duplicate headers, Upgrade, trailers and content encoding. Strip only gateway credentials and correct hop-by-hop headers for each protocol.
- Consistent UA/client hints/TLS profile for synthetic clients; align Chromium override with the chosen identity without claiming full Chrome fingerprint equivalence. Scope exceptions never silently disable certificate verification globally.
- Reusable pooled connections keyed by session/policy/TLS/exit identity; no cross-task cookies/auth or connection reuse after incompatible policy changes.
- One accounting charge per HTTP request; WebSocket/SSE handshakes and stream byte/duration limits are explicit. Upper bounds apply to upstream/downstream idle time, buffered memory and retained bodies.
- Migrate all server-side HTTP clients and proxy-aware tools to the gateway route appropriate to their purpose. No hard-coded :8888 fallback. Preserve direct native LLM/control-plane destinations outside tool reach.
- Retire the redundant masking process and its obsolete commands/settings only after all callers are migrated.

### D. Honest evidence

Own capture persistence changes coordinated with C and schema owner.

- Metadata exists for successful, failed, streamed, cancelled and denied attempts as policy permits. Record the final origin-directed request and distinguish target response from synthetic gateway error.
- Stream capture to bounded stores; never buffer unbounded bodies or WS/SSE events. Record bytes observed/retained, completeness, truncation, error stage, protocol and session/task identity.
- Preserve existing exchange identifiers and pinned evidence. Legacy records have unknown completeness rather than falsely claiming complete.
- Separate research provenance from engagement evidence. Research records contain source URL/time/result or digest; do not silently merge public advisory reads into target testing evidence.
- Exports and API/UI show omissions and gateway failures. Capture-off is an actual write policy for new body capture; already-running sessions obey changes. Required engagement metadata remains explicit rather than pretending capture is disabled everywhere.

### E. Unprivileged execution and packet boundary

Own Linux execution boundary, SDK execution seam, guest deployment and startup integration. Capability probe must precede concrete implementation choice.

- One narrow privileged supervisor creates/tears down network and filesystem isolation, installs session policy and launches a nonprivileged process. Tools cannot invoke arbitrary privileged operations.
- Cover Bash/background jobs, PTY shell, Python/custom commands, manifest runs, MCP stdio children, Obscura and Chromium. Cover read/write tool access too: subprocess isolation alone does not protect in-process file tools.
- Separate task/session workspace; read-only necessary tool/runtime paths; no application data root, keys, DB socket, supervisor socket, host mounts or unrelated task profiles. Minimal process environment and private proc/tmp/run views, no retained capabilities or privilege-gaining executables.
- Default-deny IPv4/IPv6 egress; allow gateway + controlled resolver for HTTP/research; explicit task destinations/protocols for raw network tools. Scope exclusions, CIDR overlaps, DNS aliases and routing changes are enforced on the wire.
- Install tools through an approved bounded operation in isolated staging, then atomically publish approved executable/template artifacts. Dependencies persist across normal redeployments; do not rely on mutable guest-root installs alone.
- VPN-required sessions fail closed when route/tunnel health disappears; no unfiltered interface fallback. Clean up process groups, namespaces and rules on cancellation, crash and restart without affecting another session.
- Standalone/non-Linux runtime capability errors are explicit. Never report isolation enabled unless verified. No silent legacy execution mode.

### F. Research/testing browser cutover

Own browser/, server browser/research bindings, MCP seed migration, browser settings UI and skills.

- Obscura supplies stable research reading/extraction tools through the policy gateway. No second visible general browser surface and no arbitrary evaluation/cookie/profile sharing. Isolate and clean up its processes.
- Keep native Chromium's browser_* controls, live view, screenshots, upload/download, dialog handling and operator takeover. Enforce policy for popup/worker/browser traffic through the packet/gateway boundary, not only CDP's first page.
- Bind task context from conversation records server-side, never from model arguments. Unbound chat rejects testing-browser tools and remains research-capable.
- Remove Playwright MCP seed/migrations/settings/browser_driver API/UI, obsolete visibility rows and npm launcher packages. Retain Chromium installation. Do not delete operator-custom unrelated MCP integrations.
- Source prompts and persisted-default migrations agree on research versus testing. MCP rows, tools and skills cannot restore a duplicate unmanaged browser route by default.

### G. Tool Curator complete ingest workflow

Own curator tooling/UI built on E/F and existing Toolbox persistence.

- Accept installed binary, repository URL, script/docs or manual priming. Inspect repository through approved research/install paths; record source revision and binary version.
- Run bounded discovery commands and subcommand help unprivileged; arbitrary --help code has no controller secrets or uncontrolled network.
- Optional install is an explicit operator-approved operation, not merely a final template-save approval. Probe only local disposable fixtures in the isolated session.
- Derive parameters, defaults, target shape, proxy/identity support, supported rate controls and emit parser from observed output. Preserve evidence of what was tested versus inferred.
- Validate generated TOML, preview actual argv, and test parsing against captured sample output. Do not permit category changes to evade mandatory policy or rate controls; unsupported rate models are explicit.
- Approval publishes the template/tool with provenance and verification state. No user data or existing templates lost; updates and cancellation are safe. Curator cannot self-approve or use generic Bash to bypass installation authority.

### H. Integration, migrations and deployment

Single integration owner for server/server.go, shared DB schema changes, model/run context wiring, source docs and final checks; single UI owner for web api.ts/types.ts/messages.

- Preserve DB/evidence/template/profile/prompt data. Make migrations idempotent and old-record uncertainty visible. Do not auto-authorize old discovered assets or overwrite edited prompts.
- Move runtime proxies/settings to one path; remove dead masking/Playwright paths, no hidden direct or compatibility bypass. Track all CLI, Dockerfile, sandbox, dev, package, export, test and doc callers.
- Add explicit startup capability/health report for isolation, gateway, resolver and optional VPN; fail required operations closed, not fake success.
- Preflight update with no active tasks/conversations/streams and operator approval for service interruption. Never classify a running task as stale on behalf of the operator. Build stage before stop; preserve last good deployment and rollback instructions. No live deployment in implementation agents.

## Dependency order and handoff

1. Parent writes this plan. Sonnet feasibility agents map the MITM transport extension, Linux isolation/callers, and explicit authorization/migration seams. Independent repairs A can begin under disjoint file ownership once scoped.
2. Freeze B/E/C interfaces from evidence before parallel implementation. Integration owner applies common schema contract once. C/D share one transport/evidence owner to avoid incompatible hooks; E and B can proceed independently against the contract.
3. F and G wire only after the execution/policy interfaces exist. One agent owns shared frontend API/types/messages; parallel UI work receives stable endpoints first.
4. Integration owner migrates every caller, removes old paths and updates this plan with actual completion evidence.
5. Verification agent runs checks once after all implementation slices settle; then verified failures return to the owning slice. No overlapping DB suites or mid-flight build/lint/format runs.

## Required acceptance matrix

- Allowed task HTTPS succeeds; unapproved host, excluded subnet, overlapping CIDR, DNS alias into excluded range, IPv6 alternative, DNS rebinding and redirect fail before target receives bytes.
- Research reads public docs but cannot reach targets/internal services, including through page subresources, redirects, external MCP instructions, raw sockets or proxy-env removal.
- Browser testing retains login/session cookies, file upload restricted to task workspace, download, JS dialog, screenshot, live view, popup/worker policy and WSS behavior.
- HTTP/1 + HTTP/2 + plaintext HTTP + WSS + SSE + bodies larger than 5 MiB retain correctly classified metadata and complete/truncated/error indicators with bounded memory; no silent exchange omission.
- Synthetic TLS/header identity is consistent; origin certificate failure is blocked without explicit exception. global_proxy changes exit only, not policy/capture. Repeated headers and API Accept semantics survive.
- Cancel, policy revoke, capture policy change, gateway crash, namespace crash and VPN-required route loss have deterministic behavior; no direct retry or stale unrestricted sessions survive.
- A hostile discovery binary attempts DB/host access, filesystem escape, symlinks, setuid, alternate DNS and background children; all denied while legitimate local fixture discovery works.
- Curator ingests a disposable local sample repo and tool, discovers help/output, generates valid template, captures verification provenance, waits for operator approval, and never installs/publishes before approval.
- Existing DB migrations preserve records and edited prompts; tests prove old assets are not silently promoted into authorization.
- Real PostgreSQL tests do not silently skip; scoped Go regressions, build/vet, web check/tests/static export, Python deployment tests, CJK/doc-link gates and actual browser surfaces pass. Use isolated fixture infrastructure, never engagement targets.
- Kernel-dependent tests must report explicit PASS or BLOCKED with reason, not a green SKIP misrepresented as enforcement proof.

## Deployment and rollback

Source changes and staged builds do not imply deployment. The current live server remains untouched. Any needed image rebuild, privileged capability installation or network change is surfaced before execution. Preserve the existing persistent state and image until isolated end-to-end checks pass. Rollback stops new sessions, drains/cancels only with operator authorization, restores the previous binary/image, and preserves new evidence/policy rows without authorizing them through the legacy path.

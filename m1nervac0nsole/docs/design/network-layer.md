# Network layer (as built)

Reference for the outbound path as it exists in the tree. The design rationale and the acceptance matrix are in [network-boundary-implementation-plan.md](network-boundary-implementation-plan.md); this file describes what is there now, how to operate it, and what it does not cover.

## Shape

One HTTP interception boundary, one origin transport, one policy decision point, and unprivileged tool processes.

```
agent / tool process (uid 1000, own netns)
  -> execbox session relay on 127.0.0.1:8788
  -> recording proxy (traffic/)  [client TLS terminated with the recorder CA]
  -> gateway (gateway/)          [authorize, resolve+pin, uTLS, exit]
  -> operator exit (global proxy) or direct
  -> origin
```

Nothing else may dial an origin for HTTP. A tool that ignores its proxy settings reaches only the session relay address; the root namespace admits only that port and the resolver.

## Components

| Package | Responsibility |
|---|---|
| `netpolicy/` | `Session`, `Destination`, `Decision`, `Rule`, `State`, `Authorizer`, `Store`, `Issuer`, `ProxyURL`. The decision point: policy stage (name/CIDR/protocol/port) and DNS stage (resolved addresses). |
| `gateway/` | `mproxy.OriginTransport`: authorization before dial, address pinning, uTLS Chrome handshake with strict verification, per-session pooling, exit selection, synthetic failures tagged with `X-M1nervac0nsole-Gateway`. |
| `traffic/` | The recording proxy. Terminates client TLS, parses HTTP/1.1 and h2, runs addons, stores exchanges. `OpenWithTransport(dir, addr, originTransport)`; a nil transport is the unguarded path and production never uses it. |
| `execbox/` | Privileged supervisor. Per session: network namespace, veth, iptables admitting only the gateway and resolver, cgroup v2 limits, mount namespace, uid drop, `PREFIX`/`PATH` for installs, atomic publish into the persistent toolbox bin. |
| `third_party/go-mitmproxy/` | Pinned v1.9.2 copy with the `OriginTransport` hook (see its `PATCH`). The only vendored patch in the tree. |
| `egress/` | Masking proxy. Retained for asset-enrichment probes only; pending retirement once the gateway exposes a probe path. |

## Request lifecycle

1. A tool process receives `HTTP_PROXY`/`HTTPS_PROXY` = `http://<session credential>@127.0.0.1:8788`. The credential is minted by `Manager.IssueSession` for that run and revoked when the run's context ends. Chromium ignores credentials in `--proxy-server`, so the testing browser is launched with the bare address: the gateway answers a request that carries no `Proxy-Authorization` with `407` and `Proxy-Authenticate`, and the driver answers the resulting CDP `Fetch.authRequired` with the browser's own session credential. A request that carries an unknown or revoked credential keeps the `403`.
2. The recorder answers `CONNECT` only after the gateway's `Dial` succeeds, so a dead or refused origin is refused at CONNECT rather than faked.
3. `Dial` reads the session from `Proxy-Authorization`, asks `netpolicy` about the authority, resolves it, re-checks every resolved address, pins one, and applies the exit.
4. `Handshake` runs a Chrome uTLS profile with strict verification unless the session holds an explicit certificate exception for that authority.
5. `RoundTrip` re-checks the destination, strips gateway credentials and hop-by-hop headers, preserves duplicate headers, `Accept`, `Cookie` and `Authorization`, and uses `http2.Transport` or `http.Transport` according to the negotiated ALPN.
6. The recorder stores the exchange. A gateway-produced failure is stored with its stage, never as the target's answer.

## Policy model

- An `include` rule in `task_scope_rules` authorizes only with `authorized = true`. An `exclude` rule binds as soon as it is written: a restriction is never a grant. A rule carries effect, pattern, protocol (`any` or exact), ports (empty = any) and approver.
- Exclusions beat includes. An unreadable policy denies. A task with no authorized include denies with a distinct reason.
- Discovered assets never authorize. Discovery expands the graph; only an operator approval expands access.
- `tasks.policy_revision` bumps on any rule, exception or scope change. The authorizer reads the policy state on every decision (there is no verdict cache); the revision is what stops a pooled origin connection issued under an older policy from being reused.
- Editing a rule's effect or pattern drops its approval; a note-only edit keeps it. Every write, through either route set, leaves a `policy_audit` row.
- Purposes: `testing` (task-bound: authorized includes minus every exclusion), `research` (public destinations only; refuses engagement targets, private/loopback/link-local/metadata, and mixed DNS answers), `install` (research's network rule, plus a writable staging prefix).
- `Session.Credential` is opaque and omitted from `Session.String()`, so logging a session cannot leak authority.

## Evidence model

- Every attempt the recorder sees produces a row: success, failure, or policy-refused, with the stage that produced it.
- A streamed exchange (SSE, a body of 5 MiB or more, a WebSocket) is stored as one row. The body is spooled to a content-addressed blob with no per-exchange cap; the only bound is the capture filesystem reserve, and a breach truncates and labels the stored head with `X-M1nervac0nsole-Capture: body not captured in full: partial`. A WebSocket stores a JSONL transcript of both directions as its body, and its stored length is the transcript's length on disk. Its row is labelled partial when a direction ended with a real transport error or no close frame was seen; the proxy's own teardown of the second direction is not evidence of the cause, and 1005/1006 are local reports, never an agreement. A WebSocket inside a CONNECT tunnel reports the tunnel's method and status.
- Every row carries the task id of the `netpolicy` session the gateway authorized the request with, so an exchange resolves to its task without guessing from the host. A request with no session keeps a null id.
- `Proxy-Authorization` is never stored: the session credential would otherwise be captured in plaintext.
- Research provenance is separate from engagement evidence; a public advisory read is not target evidence.
- `evidence/` pins a finding's blob independently of the disposable traffic store.

## Isolation model

- Tool processes run as uid 1000 with no capabilities and `NoNewPrivs`, in their own network, mount and pid namespaces.
- The session sees the task workspace read-write, a private tmpfs at `/tmp` (a requested working directory of `/tmp` means that tmpfs, never the host's `/tmp`), read-only runtime paths, and the persistent toolbox bin on `PATH`.
- The supervisor sweeps a previous crash's namespaces, veths, rules and cgroups before serving.
- Missing kernel capability is a refusal with the missing capability named. There is no unisolated fallback.
- `execbox probe` exits non-zero when the verified report is not OK, so a deployment can gate on it. It runs in its own state, cgroup and toolbox directories, so it is safe beside a serving supervisor.

## Operations

```sh
# Supervisor (guest, root, before the app)
m1nervac0nsole execbox serve -gateway 127.0.0.1:8788 -workspace /state/m1nervac0nsole/tasks,/state/m1nervac0nsole/sessions
m1nervac0nsole execbox probe   # exit 1 when isolation is not verified

# Policy (admin API)
GET    /api/tasks/{id}/policy
POST   /api/tasks/{id}/policy/rules
POST   /api/tasks/{id}/policy/rules/{rid}/authorize
POST   /api/tasks/{id}/policy/rules/{rid}/revoke
GET    /api/tasks/{id}/policy/cert-exceptions
POST   /api/tasks/{id}/policy/cert-exceptions
DELETE /api/tasks/{id}/policy/cert-exceptions/{eid}
```

A task with no authorized rule is blocked by design. Approve at least one destination before expecting target traffic: in the console, the task's scope-rule card lists every rule with Approve / Revoke (`GET /api/tasks/{id}/scope/rules` carries `authorized`, `protocol` and `ports`).

## Browser roles

- **Testing**: native Chromium over CDP (`browser_*`), task-bound, with live view, upload/download, dialogs and operator takeover. An unbound chat has none.
- **Research**: Obscura (`mcp__obscura__*`), `--stealth`, read-only tool allow-list, launched through the gateway with the recorder CA in `SSL_CERT_FILE`. It refuses engagement targets and private addresses, including after a redirect.
- Playwright MCP and the `browser_driver` setting are gone; a migration deletes the old row.

## Known limits

- The backend process still runs as root in the guest; only tool children drop privileges.
- In-process tools (`Read`, `Write`, `Edit`, `MultiEdit`, `LS`, `Glob`, `Grep`, `tcp_probe`, `WebFetch`, custom `http`, `create_skill`, `update_skill_file`, `browser_upload`, `ask_operator` staging) run outside the subprocess boundary. `Grep` falls back to its in-process implementation because its call site carries no context. `tcp_probe` and HTTP asset enrichment dial from the backend but ask the same `netpolicy` authorizer first; DNS enrichment does not contact the target and is not gated.
- A custom `script` tool receives its body and parameters as arguments, so a script larger than the kernel's argument limit cannot run.
- A tool's own verbose output can echo its proxy credential; it is per-run and revoked when the run's context ends.
- A task's Chromium holds its own session, issued at launch and revoked when the browser closes or is evicted.
- Origin certificates are verified strictly; the exception is per session and per authority, and is recorded.
- Raw TCP/UDP/DNS from an approved raw tool is governed by the session packet rules, not by the gateway.

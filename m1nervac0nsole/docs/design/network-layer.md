# Network layer (as built)

Reference for the outbound path as it exists in the tree. The design rationale and the acceptance matrix are in [network-boundary-implementation-plan.md](network-boundary-implementation-plan.md); this file describes what is there now, how to operate it, and what it does not cover.

## Shape

One recorded HTTP boundary and origin transport, plus an optional policy-enforced IPv4 direct lane for testing subprocesses.

```
agent / tool process (uid 1000, own netns)
  -> execbox session relay on 127.0.0.1:8788
  -> recording proxy (traffic/)  [client TLS terminated with the recorder CA]
  -> gateway (gateway/)          [authorize, resolve+pin, uTLS, exit]
  -> operator exit (global proxy) or direct
  -> origin
```

Recorded HTTP always uses the gateway. The backend wraps the installed execbox client for **all testing subprocesses**, including SDK/Bash, custom scripts and manifests. With live `tun0` and no operator global proxy, testing sessions can also receive a scoped direct lane from their namespace through root-namespace FORWARD rules to `tun0`. Research/install remain relay-only. Without a lane, processes reach only the session relay and resolver.

## Components

| Package | Responsibility |
|---|---|
| `netpolicy/` | `Session`, `Destination`, `Decision`, `Rule`, `State`, `Authorizer`, `Store`, `Issuer`, `ProxyURL`. The decision point: policy stage (name/CIDR/protocol/port) and DNS stage (resolved addresses). |
| `gateway/` | `mproxy.OriginTransport`: authorization before dial, address pinning, uTLS Chrome handshake with strict verification, selective identity masking, per-session pooling, exit selection, synthetic failures tagged with `X-M1nervac0nsole-Gateway`. |
| `traffic/` | The recording proxy. Terminates client TLS, parses HTTP/1.1 and h2, runs addons, stores exchanges. `OpenWithTransport(dir, addr, originTransport)`; a nil transport is the unguarded path and production never uses it. |
| `execbox/` | Privileged supervisor. Per session: network namespace, veth, relay/resolver access and optional scoped direct packet rules, cgroup v2 limits, mount namespace, uid drop, `PREFIX`/`PATH` for installs, atomic publish into the persistent toolbox bin. |
| `third_party/go-mitmproxy/` | Pinned v1.9.2 copy with the `OriginTransport` hook (see its `PATCH`). The only vendored patch in the tree. |

## Request lifecycle

1. A tool process receives `HTTP_PROXY`/`HTTPS_PROXY` = `http://<session credential>:<session credential>@127.0.0.1:8788`, and the recorder's public CA — mounted read-only into the session by the supervisor — in `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and `NODE_EXTRA_CA_CERTS`. The credential is repeated as the password because Python's `urllib` and `urllib3` send `Proxy-Authorization` only when both parts are set; the gateway reads the user part alone. The credential is minted by `Manager.IssueSession` for that run and revoked when the run's context ends. Chromium ignores credentials in `--proxy-server`, so the testing browser is launched with the bare address: the gateway answers a request that carries no `Proxy-Authorization` with `407` and `Proxy-Authenticate`, and the driver answers the resulting CDP `Fetch.authRequired` with the browser's own session credential. A request that carries an unknown or revoked credential keeps the `403`.
2. The recorder answers `CONNECT` only after the gateway's `Dial` succeeds, so a dead or refused origin is refused at CONNECT rather than faked.
3. `Dial` reads the session from `Proxy-Authorization`, asks `netpolicy` about the authority, resolves it, re-checks every resolved address, pins one, and applies the exit.
4. `Handshake` runs a Chrome uTLS profile with strict verification unless the session holds an explicit certificate exception for that authority.
5. `RoundTrip` re-checks the destination, strips gateway credentials and hop-by-hop headers, preserves duplicate headers, `Accept`, `Cookie` and `Authorization`, and uses `http2.Transport` or `http.Transport` according to the negotiated ALPN.
6. The recorder stores the exchange. A gateway-produced failure is stored with its stage, never as the target's answer.

### Identity and route selection

- Origin TLS on the recorded path uses Chrome uTLS. Header masking replaces only missing or recognized tool-default User-Agent values; deliberate custom UAs and credentials are preserved. Stealth uses `navigation`: eligible bodyless GET/HEAD requests receive navigation headers without overwriting caller choices. Careful, Standard and Unbound use `ua` masking on recorded traffic. Enrichment uses recorded gateway sessions with navigation masking.
- Profiles provide speed guidance, not enforced rate or thread ceilings. Only tool-run concurrency is bounded by default: 16 global and 16 per target.
- Interactive HTTP retains recorder proxy environment settings, even when its process has a direct lane. Standard/Unbound bulk-HTTP manifests declaring `RateRPS` omit **both** proxy environment and proxy argv only after a lane snapshot is available. Execution refuses if that selected lane disappears; it does not silently fall back to an unscoped route. Raw tools can use scoped direct sockets regardless of their HTTP proxy environment.
- The Nmap manifest offers `scan=sS` (default SYN), `sT` (TCP connect), or `sU` (UDP) and supplies `--privileged -Pn -n`. `--privileged` tells Nmap to use the granted raw capability despite uid 1000; it does not grant root. `-Pn` avoids off-port discovery probes. For equivalent Bash commands, include `--privileged -Pn`; use backend `port_scan`/`tcp_probe` when no lane is available.
- The separate masking-egress proxy, its package, subcommand and environment settings are retired.

### Direct packet enforcement and revocation

The root namespace applies authorized includes, protocol/port constraints, exclusions and infrastructure denies to packets in **both** FORWARD directions, including established flows. Infrastructure denies cover loopback, `10.98.0.0/16`, link-local, guest-local addresses, `host.microsandbox.internal` and resolved configured native-provider/profile endpoints (also unspecified, multicast and broadcast IPv4 destinations). They do not deny entire VPN destination ranges.

Hostname grants learn only filtered DNS A answers through the session resolver. Learned addresses expire with DNS TTL (bounded by the smallest answer TTL across an alias chain), are re-evaluated on policy updates and are not renewed by policy refresh. The session link has no IPv6: AAAA answers do not create a direct path.

The backend polls every second, with one combined one-second deadline for policy read and supervisor apply. Revocation normally takes at most about two seconds plus kernel teardown/scheduling. Policy-read, apply or egress-availability failure cancels the process and tears down its namespace, with no old-policy fallback. The supervisor also kills the session on failed rule application.


## Policy model

- An `include` rule in `task_scope_rules` authorizes only with `authorized = true`. An `exclude` rule binds as soon as it is written: a restriction is never a grant. A rule carries effect, pattern, protocol (`any` or exact), ports (empty = any) and approver.
- Exclusions beat includes. An unreadable policy denies. A task with no authorized include denies with a distinct reason.
- The task goal's target is authorized at creation with a boundary (actor `goal`): an IPv4 address gets its /24, IPv6 its /64, a hostname `*.<registrable domain>` (which also matches the apex). A discovered target outside every authorized include gets a pending (unauthorized) include rule written by `agent`, plus a `scope_pending` system event for the operator; the task keeps running. Discovered targets inside an authorized rule need nothing. A hostname the agent recorded against an IP (asset rows carrying both) is reachable when that IP is authorized: the gateway resolves the name to the recorded address for that task. A hostname rule is never auto-approved, because a hostname grant authorizes the name wherever DNS points it.
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
- Direct traffic bypasses gateway identity masking and HTTP recording. Preserve execution artifacts and pinned pcap evidence; replay safe HTTP through the recorder when inspectable request/response evidence is needed.

## Isolation model

- Tool processes run as uid 1000 with `NoNewPrivs`, in their own network, mount and pid namespaces. Relay-only sessions have no capabilities; direct-lane sessions receive only `CAP_NET_RAW` for raw tools such as SYN/UDP scanners.
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
- In-process filesystem and network tools remain outside the subprocess boundary. Backend `tcp_probe` and `port_scan` authorize and pin destinations before dialling; they are not recorder exchanges. HTTP asset enrichment instead uses recorded gateway sessions with navigation masking. DNS enrichment does not contact the target.
- Relay-only scanners cannot directly reach target ports; a scoped direct-lane session can perform permitted TCP, SYN and UDP scans. Packet policy still decides protocol, ports and addresses.
- A tunnel that does not open with TLS or an HTTP request line, or whose client stays silent for 2 s (a server-speaks-first service), is relayed as raw bytes by the recorder after gateway authorization; its bytes are not HTTP-recorded.
- A custom `script` tool sends its body and parameters on stdin to a fixed bootstrap, not in argv; the executed script is written under the run workspace and reported as an artifact. Oversized bodies or `TOOL_*` values are refused explicitly.
- A tool's own verbose output can echo its proxy credential; it is per-run and revoked when the run's context ends.
- A task's Chromium holds its own session, issued at launch and revoked when the browser closes or is evicted.
- Origin certificates are verified strictly; the exception is per session and per authority, and is recorded.
- Raw TCP/UDP/DNS from an approved raw tool is governed by the session packet rules, not by the gateway.

# deployment

Host-side and guest-side machinery that runs m1nervac0nsole inside a microsandbox VM, captures what it does, and exports the result.

The application itself is documented in `m1nervac0nsole/docs/system-reference.md`. This file covers the machine around it.

## Topology

```
host                                  sandbox
  ./lab  --------------------------->  guest-start.py  (supervisor, root)
  state/        <- mount /state -->      PostgreSQL            127.0.0.1:5432
  guest-dist/   <- /dist:ro ------>      execbox supervisor   /run/m1nervac0nsole/execbox.sock
  secrets/      <- /run/secrets -->      m1nervac0nsole       0.0.0.0:8787
                                         recording proxy      127.0.0.1:8788
                                         tcpdump, strace, openvpn
```

Only `127.0.0.1:8787` is published to the host. Everything else is loopback inside the sandbox.

The host never runs application code. `./lab build` stages the binary, skills and guest scripts into `deployment/guest-dist/`; the sandbox mounts it read-only at `/dist`; the guest copies from it when the supervisor starts. `./lab start` on an already-healthy sandbox rebuilds `/dist` but does not restart the supervisor, so the running binary stays the old one: use `./lab stop && ./lab start` to deploy a change. The image's baked copies are only the fallback for a sandbox created before that mount existed.

## The image

`deployment/sandbox.yaml` names `agentlab/m1nervac0nsole:deepseek-v1` with `pull_policy: never`, so a missing image fails rather than pulls.

`./lab image-build` builds and validates that tag from this repository:

1. reads the tag from `deployment/sandbox.yaml`;
2. runs `m1nervac0nsole/build.sh` for `linux/amd64`, then `docker build -f deployment/Dockerfile -t <tag>-candidate .`;
3. runs every entry in `deployment/image-capabilities.txt` with `command -v` inside the candidate and fails on the first missing one;
4. stops. It never moves the tag, never calls `msb`, and never touches the sandbox or `/state`.

`--replace` moves the tag only after the candidate passes, keeping the old image as `<tag>-prev-<id12>`; roll back with `docker tag <tag>-prev-<id12> <tag>`. A failed build or a failed capability check leaves the configured tag untouched.

Loading a built image into microsandbox is a separate, printed step: `docker save -o IMAGE.tar <tag>` then `MSB_HOME=<repo>/microsandbox .venv/bin/msb load -i IMAGE.tar`. A running sandbox keeps its rootfs, so a newly loaded image applies to sandboxes created afterwards.

**A rebuild is not bit-identical to the historical image.** The base tag, apt indexes and several clones float, and the overlay that produced `deepseek-v1` is not in the tree. `./lab image-build` prints this and reports `reproducible: false`; it rebuilds the tag, it does not reproduce the bytes. `deployment/Dockerfile.toolchain` is the historical toolchain overlay and is not part of this path. `deployment/provenance.json` records the image id and layers; never hand-edit it.

## Mounts

| Host | Guest | Notes |
|---|---|---|
| `state/` | `/state` | Quota in MiB, default 150 GiB, substituted at create time from `AGENTLAB_STATE_QUOTA_GB` (0 = no quota). Fixed at creation; grow with `./lab resize-state <GB>` |
| `deployment/guest-dist/` | `/dist` | Read-only. Binary, skills, guest scripts |
| `secrets/admin-password` | `/run/secrets/agentlab-admin` | Initial admin password |
| `secrets/native-proxy-token` | `/run/secrets/agentlab-native-proxy` | Host provider-proxy token |
| `secrets/openvpn-profile.ovpn` | `/run/secrets/openvpn-profile.ovpn` | Only with `./lab start --vpn <profile>` |

## State layout

```
/state
  postgres/                     PostgreSQL data directory
  captures/<session-id>/        manifest.json, pcap/, strace/, tls/, logs/
  current-capture.json          which session is live
  supervisor.pid
  m1nervac0nsole/               application data root
    tasks/<task>/               task workspaces (writable roots for tools)
    sessions/<session>/         chat session workspaces
  skills/                       synced from /dist/skills at every start; writable
  runtime/
    m1nervac0nsole              the binary
    jwt.key
    status.json
    secrets/m1nervac0nsole-db.dsn
    logs/postgres/postgres.log
    logs/openvpn.log
```

`/state` is the persistent volume. Everything a tool writes outside its task workspace and the session's private `/tmp` is discarded with the session.

## Guest processes

Start order, enforced by `guest-start.py`:

1. Acquire `/state/runtime/supervisor.lock` (a second supervisor exits with code 3).
2. PostgreSQL on `/state/postgres`, loopback TCP plus the `/run/postgresql` socket.
3. The application's database role and database.
4. `tcpdump`, which must report that it is listening.
5. The `execbox` supervisor, which must pass its own session probe.
6. The backend under `strace`.

Stop order on SIGTERM, SIGINT, or backend exit: backend process group, then `execbox` (SIGTERM), then `tcpdump` (SIGINT, so the pcap flushes), then PostgreSQL (`pg_ctl -m fast`).

The backend exit code is the supervisor's exit code (128+signal if killed), 1 on any failure.

## Network routes

Recorded HTTP uses the session recorder → gateway, with Chrome uTLS and selective tool-default UA masking. Stealth uses navigation masking; Careful/Standard/Unbound use UA masking. Enrichment uses recorded gateway navigation sessions. The separate masking-egress process, subcommand and environment settings are retired. Profiles are guidance, not rate/thread ceilings; default tool-run concurrency is 16 globally and per target.

The backend wraps the installed execbox client for **all testing subprocesses**, including SDK/Bash, scripts and manifests. A scoped direct lane is available only with live `tun0` and no operator global proxy; research/install remain relay-only. Interactive HTTP retains recorder proxy env. Standard/Unbound bulk-HTTP manifests declaring `RateRPS` omit both proxy env and argv only after an available lane snapshot; execution refuses if the lane disappears. Raw tools can use scoped direct sockets regardless of HTTP env. Only direct sessions receive `CAP_NET_RAW`, so permitted SYN/UDP scanning is not restricted to backend connect scans.

Root-namespace FORWARD rules enforce authorized scope, exclusions and protocol/port constraints in both directions, including established flows. Infrastructure denies cover loopback, `10.98.0.0/16`, link-local, guest-local addresses, `host.microsandbox.internal` and configured native-provider/profile endpoints, not entire VPN destination ranges. Filtered DNS A grants expire with TTL and are re-evaluated on policy updates. The session link has no IPv6; direct traffic is IPv4-only.

The backend polls every second with a combined one-second policy read/apply deadline. Revocation normally takes at most about two seconds plus kernel teardown/scheduling. Read/apply/egress failure cancels processes without an old-policy fallback; supervisor apply failures kill sessions. Direct traffic has no gateway masking or HTTP recording: retain execution artifacts and pinned pcap, and replay safe HTTP through the recorder when inspectable evidence is needed.

Tool sessions mount the recorder's **public** CA certificate read-only at the absolute path the backend names in `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and `NODE_EXTRA_CA_CERTS`; the research browser is launched with it. The supervisor re-encodes only the certificates (`execbox serve -ca-cert`, empty disables), so the signing key is never exposed. If the recorder has not written its CA yet, the session reports that rather than silently trusting nothing.

These are source-level behavior descriptions, not claims that this redesign has been deployed or verified in a live guest. See [Network layer](../m1nervac0nsole/docs/design/network-layer.md).


## Capture

Three independent records, all inside `/state/captures/<session-id>/`:

- **pcap** — `tcpdump` on `any`, snap length 0, per-packet flush, rotated at 128 MB per segment into a ring. The ring ceiling is `AGENTLAB_CAPTURE_RING_GB` (default 64 GB) worth of segments, capped at 4096 and shrunk to what actually fits on the volume. `wrap_suspected` is set when every slot is in use.
- **strace** — `-ff -ttt -T -yy -s4096 -e trace=process,file,network`. The 4096-byte string limit is deliberate: 256 cut real paths, argv elements and payload fragments mid-value, so a trace could not be read back as evidence.
- **logs** — the backend's own output.

A reserve is kept free on the capture filesystem: 20% of the volume, never less than 1536 MB. Without it the ring filled a 5.8 GB filesystem to 100% and took the whole stack down. `traffic/` mirrors the same rule for its streamed-body spool.

Gateway-origin TLS payloads are ciphertext in the pcap. The gateway writes its origin handshake secrets to `tls/keys.log` inside the capture session (mode 0600), so those flows can be decrypted with the exported keylog. Direct-lane TLS does not use the gateway and is not covered by its keylog. The manifest records that guest root can modify or delete captures and the manifest itself.

## Export

`./lab export` runs `guest-export.py`, which streams a tar to stdout and writes a timestamped directory with a `manifest.json` of SHA-256 hashes.

Layout:

```
raw/application/                 the application data root
raw/captures/                    the capture session
raw/host-events/<segment>.jsonl  host command log, rotated
raw/provider-proxy-traffic/      one file per provider stream segment
raw/llm_records.jsonl            provider wire bodies
raw/reasoning.jsonl              recovered reasoning
logs/postgres.log                database-side failures
manifest.json                    sha256 per artifact, plus prunable[]
```

`/state/runtime` is never copied whole. Historical exports may include `logs/egress.log`; the retired masking-egress CA directory is never exported because it holds private-key material.

A failed export removes its directory; a `SIGKILL`ed one can leave a directory with no manifest, which `verify_export` and `prune` both refuse.

`./lab prune <export-id>` deletes only what a verified export contains. It re-checks every hash, honours a `prunable` allow-list, never touches an active stream (a writer holds it open), and supports `--dry-run`. There is no automatic pruning anywhere: this command is the only deletion path.

## Scripts

| File | Role |
|---|---|
| `guest-start.py` | Guest supervisor: start and stop order, capture, status |
| `guest-export.py` | Streams the export tar; snapshots live SQLite in the writer's kernel |
| `export_traces.py` | Turns an export into training data (`train.jsonl`, `reasoning.jsonl`) |
| `verify_capture.py` | End-to-end capture check; drives the authenticated custom-tool test endpoint, needs host `tshark` |
| `verify_completeness.py` | Pushes nonces through HTTP, SSE, a large body and a WebSocket; reports collected, retained, exported, consumed |
| `build-cliproxy.sh` | Builds the pinned CLIProxyAPI plus `core.patch` |
| `test_extension_capture.mjs` | Harness for the browser extension's capture queue |
| `provenance.json` | Machine-written image and toolchain record; never hand-edit |

## Operation

```sh
./lab start [--vpn PROFILE]   # build guest-dist if stale, create or reuse the sandbox, start the stack
./lab status                  # health, processes, capture state
./lab export                  # timestamped archive with a hash manifest
./lab prune <export-id>       # delete what a verified export contains
./lab exec -- bash -lc '...'  # run a command in the guest
./lab stop                    # stop the stack and the sandbox
```

Never start two VMs against the shared `state/`; `./lab start` refuses while another running sandbox exists. Use `./lab stop` rather than a force-kill.

## Verification

```sh
python3 deployment/verify_capture.py      # capture end to end (live run + tshark)
python3 deployment/verify_completeness.py # four capture shapes, byte-exact through export and re-import
tests/run.sh python                       # host and deployment suites
./deployment/cliproxy/run-tests.sh        # provider proxy
```

`verify_capture.py` runs its producer through `POST /api/tools/custom/test`, so it needs no credential and stages nothing. By default it proves the gateway refuses a research session's loopback request and that the refusal is recorded; `--task-id` uses a task whose rules already authorize the fixture origin, and reports `blocked` rather than `verified` when the request is refused.

`verify_completeness.py` starts its own gateway and recorder on a temporary store, mints its own credential and grants only its fixture ports, so it needs no live guest and changes no policy. It pushes plain HTTP, SSE, a 6 MiB body and a duplex WebSocket through, exports the task, re-imports into an empty store and compares bytes per shape; a third listener outside the granted ports must be refused at the policy stage and never dialled. It also proves the keylog decrypts the origin flow and that the same flow is ciphertext without it.

## Traps

- **A rebuilt image is not the historical image.** `./lab image-build` rebuilds the configured tag from this repository and validates its capabilities; it does not reproduce the 2026-11-11 bytes. See "The image" above.
- **`guest-dist` staleness.** `lab` rebuilds it when a build input is newer. If a change does not reach the VM, check that its package is listed in `BUILD_INPUTS`.
- **The capture reserve has one authority.** `guest-start.py` computes it and passes it to the recorder by environment; the recorder's constants are only the standalone default outside the lab.
- **`run-tests.sh` needs `.upstream-work/` to exist** but does not create it; on a clean checkout it dies in `mktemp`.
- **`internal/privacy` and `internal/runtime` in `deployment/cliproxy/` are host code, not upstream.** `core.patch` carries no hunk for them, so they are edited directly; the upstream packages under `internal/runtime/executor/` are patch-managed.

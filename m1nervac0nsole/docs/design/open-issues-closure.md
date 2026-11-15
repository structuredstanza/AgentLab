# Open-issue closure

Status: implemented and verified. `go build ./...` and `go vet ./...` are clean; `go test -p 1 ./...` is green on two separate disposable PostgreSQL databases, and each package the CI matrix runs (`agent config db enrich evidence guard intercept llmrec server`) is green alone on its own empty database; `./traffic/` is green over 18 consecutive runs; the execbox kernel tests and the real-Chromium popup and child-target tests pass in the guest; 223 host Python tests, the web gates and the provider-proxy suite pass. Live: `verify_capture.py` reports `verified` (the policy refusal is recorded, the credential-free marker correlates, export checksums hold) and `verify_completeness.py` reports `verified` (plain, SSE, 6 MiB and duplex WebSocket byte-identical through export and re-import; the ungranted port is refused and never dialled; the keylog decrypts and does not without it).

## As built

| Area | Contract |
|---|---|
| Task traffic | `ExportTask(taskID, dir)`, `StageDeleteTask(taskID)`, `StageDeleteExchangesForArchive(ids, archiveID, taskID)`. Journal version 2 carries `exchange_ids` and no hosts; recovery branches on version, so a task stage cannot widen to a host. |
| Process evidence | `execbox.WithArtifacts(ctx, ArtifactCall{Dir, ToolUseID, Origin})`; `Process.ArtifactPointer() string` (exported, because the interface is satisfied outside the package); `Result.Artifact`; `frame.StdinAccepted`. A per-process directory holds `meta.json` plus `stdin`/`stdout`/`stderr` or a single `terminal`, 0700/0600. |
| Reserve | `AGENTLAB_CAPTURE_RESERVE_MB`/`_PCT` in `guest-start.py`; `M1NERVAC0NSOLE_CAPTURE_RESERVE_MB`/`_PCT` to the recorder; one store-wide atomic byte counter; a probe error stops capture with a labelled partial. |
| WebSocket | `proxy.WebSocketRecorder{WebSocketFrame, WebSocketClosed}`; a JSONL transcript stored as the response blob with `resp_len` equal to the transcript length on disk; a row is partial when a direction ended with a real transport error or no close frame was seen. The proxy closes the second direction as soon as the first ends, so that teardown (`net.ErrClosed`) decides nothing; 1005 and 1006 are local reports, never an agreement. |
| Browser | Popup recorded before resume, named only by an allowed Document request; child targets intercepted on their own session before they run; unclassified setup failure closes the target. |
| Image | `./lab image-build [--replace]` builds and capability-checks `<tag>-candidate`, never touching the tag, sandbox or `/state` by default. |
| Test locks | `internal/testlock.Run(dsn, run)` holds key 7337741002 on one pinned connection and releases it before exit. |

## Scope and decisions

| Area | Contract |
|---|---|
| Task traffic lifecycle | Select attributed exchanges by task ID, journal exact IDs, and compact only the IDs exported. Preserve NULL-task rows and shared legacy host trees. Explicit host/all deletion remains separate. |
| Authorized verification | Isolated real gateway/recorder fixtures prove byte recovery without borrowed credentials. Live verification uses the existing authenticated custom-tool test endpoint and never changes task policy or starts an engagement. |
| Image build | Build and validate a candidate from the repository recipe. Preserve the current tag by default; explicit replacement keeps a rollback tag. No sandbox recreation or persistent-volume changes. A rebuilt tag is not a claim of historical bit identity. |
| Capture reserve | Pass the guest's reserve policy into the backend. Probe or write failure produces a partial capture without disrupting forwarding. Account for concurrent writers and the actual capture filesystem. |
| WebSocket evidence | Persist both directions, binary payloads, message types, arrival ordering and termination in an exportable transcript. Live-view bounds do not limit stored evidence. Transcript byte length and payload byte totals are separate quantities. |
| Process evidence | Send EOF for one-shot non-PTY execution; preserve output on error. Store per-process submitted input, accepted-byte count and distinct output streams under persistent run workspaces, with relative paths and hashes attached to tool results. Never capture environment secrets. |
| Browser targets | Empty/about:blank is not destination authorization. Intercept actual requests before resuming child targets; verify denied origins receive no request and allowed targets do not hang. |
| Test locks | Share one pinned PostgreSQL advisory-lock helper while retaining each package's setup. Release the lock and connection before exiting. Never silently run unlocked after a reachable database rejects the lock. |

## Implementation ownership

Wave 1 has independent owners for traffic lifecycle, process execution, native browser targets, database-test locking, and image construction. Wave 2 takes ownership of traffic capture/reserve/WebSocket code only after the lifecycle writer has finished. Verifier updates follow the capture contracts. The parent owns shared route/schema files and global documentation; this design requires neither a new server route nor a PostgreSQL migration.

No live-policy override, credential-mint endpoint, automatic pruning, historical ownership inference, or production task deletion is part of verification.

## Acceptance

- Delete/archive/restore one of two tasks sharing a host and blob: the other task, unattributed legacy rows, shared files and pinned evidence remain intact. Rollback and crash replay use exact IDs.
- Capture and recover HTTP, SSE, large bodies, duplex WebSocket and TLS-keylog evidence through real production components; damaged exported evidence must fail verification.
- Default live verification proves an unauthorized request is refused and recorded. An allowed live round trip requires an already-authorized operator task and is never reported as verified when blocked.
- Candidate image passes the declared command/path inventory without replacing the configured image or touching the sandbox.
- Low space, failed accounting, short writes, cancellation and concurrent captures produce honest partial/error metadata while proxy forwarding remains independent.
- Process artifact bytes and hashes survive export; unknown exit status is not success; cancelled and timed-out calls retain available output. Symlinks cannot redirect artifact writes outside the run directory.
- Delayed popup navigation, redirects, workers and iframes cannot contact an excluded origin. Unsupported Chromium interception is an explicit limitation backed by gateway enforcement evidence, not an assumed fallback.
- Database-test helper blocks concurrent suites and releases its lock on both successful and failing test exits.

## Verification discipline

Implementation workers do not run builds, tests or formatters mid-flight. After integration, run focused regressions with a disposable PostgreSQL database and preserve command exit status. Root/browser cases require the appropriate real runtime; skipped prerequisites are not passes. Keep source, deployment and graph evidence distinct. Update affected documentation only with observed results and explicitly record remaining platform limits.

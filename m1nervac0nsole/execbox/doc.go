// Package execbox is the unprivileged execution boundary for tool processes.
//
// One privileged supervisor (cmd/m1nervac0nsole execbox serve) owns every
// namespace, cgroup and firewall change; the SDK, the server and the browser
// driver ask it, over a Unix socket, to start a process inside a session:
//
//   - a private network namespace with a veth pair to the root namespace, where
//     the root namespace admits only the gateway port and the session resolver
//     and rejects everything else (IPv4 and IPv6);
//   - a private mount namespace built from a tmpfs root that contains only the
//     session workspace (read-write), the configured runtime paths
//     (read-only), a private /proc, /dev, /tmp and /run, and no application
//     data root, key, database socket, supervisor socket or other task's
//     workspace;
//   - a private PID, IPC and UTS namespace;
//   - a cgroup v2 subtree with memory and pid limits, used to kill the whole
//     process tree on exit, cancellation, crash and restart;
//   - an unprivileged uid (1000) with an empty capability set, via setpriv
//     --bounding-set=-all --no-new-privs.
//
// Session identity comes from netpolicy.Session carried in the caller's trusted
// context (WithSession), never from the spawned program's arguments or
// environment, and never from the model.
//
// # Installed tools persist
//
// A session's root is a tmpfs, so a binary installed into it is discarded with
// the session. The toolbox directory under /state is the exception: the
// supervisor mounts its bin/ read-only into every session and puts it on PATH,
// and an install-purpose session additionally gets a writable staging prefix
// (PREFIX, HOME and TMPDIR) of its own. When the install script succeeds the
// supervisor publishes the staged artifact into that bin directory - a temp name
// in the same directory and a rename, owner root, mode 0755 - so a tool
// installed once is available to later sessions and later boots, because /state
// survives sandbox recreation. The tool never publishes itself, and a failed or
// unverified install publishes nothing.
//
// # Fail closed
//
// Missing kernel capability is an error, never a fallback: a session that
// cannot be isolated is refused with a *CapabilityError naming the missing
// capability, and no process is started. The supervisor refuses to start when
// its own self-test fails, and the client refuses when the supervisor is not
// reachable. Install wires the process-wide client; without it the SDK keeps
// its standalone behaviour of spawning directly, which is not an isolation
// boundary and is why the deployed entry point must install one.
//
// # What stays in-process
//
// Subprocess isolation does not cover tools that run inside the backend
// process. These remain outside this boundary (network-boundary plan, resolved
// decision 2) and must move behind the supervisor, or the backend itself must
// be confined, before they count as isolated:
//
//   - Read, Write, Edit, MultiEdit, LS, Glob, Grep (the in-process file tools,
//     including Grep's pure-Go fallback path);
//   - tcp_probe;
//   - WebFetch;
//   - the custom "http" tool;
//   - create_skill and update_skill_file;
//   - browser_upload;
//   - ask_operator staging.
//
// They read and write with the backend's own privileges, so a task workspace
// that the backend can reach is reachable through them even when every
// subprocess is confined. Reported by Capability report at startup so this is
// visible rather than assumed.
package execbox

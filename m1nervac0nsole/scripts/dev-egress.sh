#!/usr/bin/env bash
# Process helpers for dev.sh, kept separate so scripts/test-dev-egress.sh can drive
# them against fake binaries. Source this file; it does nothing on its own.
#
# Contract:
#   - Every process we start is a direct child that leads its own process group
#     (job control), and its pid is recorded. Cleanup signals ONLY those groups
#     and removes ONLY the temp directory we created. It never uses `kill 0`, so
#     the caller's own process group is never touched.
#   - Readiness of a child is proven by a marker line in a log file this launch
#     truncated, AND the child still being alive. A CA file on disk, a listener
#     someone else holds, or a stale log proves nothing.

DEV_OWNED_PIDS=()
DEV_TMP=""
DEV_LAST_PID=""

# Each background job gets its own process group (pgid == pid).
dev_enable_job_control() { set -m; }

# dev_launch <logfile|-> cmd args...   ("-" inherits stdout/stderr)
dev_launch() {
	local log=$1
	shift
	if [ "$log" = "-" ]; then
		"$@" &
	else
		"$@" >"$log" 2>&1 &
	fi
	DEV_LAST_PID=$!
	DEV_OWNED_PIDS+=("$DEV_LAST_PID")
}

dev_group_alive() { kill -0 -- "-$1" 2>/dev/null; }

# dev_cleanup: terminate the groups we own, then remove our temp dir. Idempotent.
dev_cleanup() {
	trap - EXIT INT TERM
	local pid i alive
	for pid in ${DEV_OWNED_PIDS[@]+"${DEV_OWNED_PIDS[@]}"}; do
		kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
	done
	for i in $(seq 1 50); do
		alive=0
		for pid in ${DEV_OWNED_PIDS[@]+"${DEV_OWNED_PIDS[@]}"}; do
			if dev_group_alive "$pid"; then alive=1; fi
		done
		[ "$alive" -eq 0 ] && break
		sleep 0.1
	done
	for pid in ${DEV_OWNED_PIDS[@]+"${DEV_OWNED_PIDS[@]}"}; do
		if dev_group_alive "$pid"; then
			kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
		fi
		wait "$pid" 2>/dev/null || true
	done
	DEV_OWNED_PIDS=()
	if [ -n "$DEV_TMP" ] && [ -d "$DEV_TMP" ]; then
		rm -rf -- "$DEV_TMP"
	fi
	DEV_TMP=""
}

# dev_wait_marker <pid> <logfile> <marker> <timeout_seconds>
# Succeeds only when the marker is in the log and the child is alive.
dev_wait_marker() {
	local pid=$1 log=$2 marker=$3 timeout=$4 i
	for i in $(seq 1 $((timeout * 10))); do
		if ! kill -0 "$pid" 2>/dev/null; then
			return 1
		fi
		if grep -qF -- "$marker" "$log" 2>/dev/null && kill -0 "$pid" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

# dev_start_egress <binary> <addr> <dir> <logfile> [timeout_seconds]
# Starts `<binary> egress-proxy` as an owned child and waits for ITS "egress
# proxy on <addr>;" line (printed only after it has bound the port). On success
# exports M1NERVAC0NSOLE_EGRESS_PROXY / M1NERVAC0NSOLE_EGRESS_CA; on any failure exports nothing
# and returns non-zero. <dir> (the CA and identity) is created by the proxy and
# never deleted here.
dev_start_egress() {
	local bin=$1 addr=$2 dir=$3 log=$4 timeout=${5:-30}
	# Match the guest's 100 requests/min per-target ceiling.
	dev_launch "$log" "$bin" egress-proxy -addr "$addr" -dir "$dir" -rpm 100
	local pid=$DEV_LAST_PID
	if ! dev_wait_marker "$pid" "$log" "egress proxy on $addr;" "$timeout"; then
		echo "[dev] egress proxy did not start on $addr (port in use, crashed, or too slow); not starting the backend. Its log:" >&2
		tail -n 20 "$log" >&2 2>/dev/null || true
		return 1
	fi
	if [ ! -f "$dir/ca.pem" ]; then
		echo "[dev] egress proxy is up but wrote no CA at $dir/ca.pem; not starting the backend" >&2
		return 1
	fi
	export M1NERVAC0NSOLE_EGRESS_PROXY="http://$addr"
	export M1NERVAC0NSOLE_EGRESS_CA="$dir/ca.pem"
}

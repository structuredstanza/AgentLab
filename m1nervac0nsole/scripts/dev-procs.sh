#!/usr/bin/env bash
# Process helpers for dev.sh. Source this file; it does nothing on its own.
#
# Contract:
#   - Every process we start is a direct child that leads its own process group
#     (job control), and its pid is recorded. Cleanup signals ONLY those groups
#     and removes ONLY the temp directory we created. It never uses `kill 0`, so
#     the caller's own process group is never touched.

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

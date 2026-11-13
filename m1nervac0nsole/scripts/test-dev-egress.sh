#!/usr/bin/env bash
# Behavioral check for scripts/dev-egress.sh (what dev.sh relies on). It drives the real
# functions against FAKE egress binaries in a temp directory: no app state, no real proxy,
# no port is bound. Exits non-zero on the first violated expectation.
#
#   scripts/test-dev-egress.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=dev-egress.sh
. "$here/dev-egress.sh"
dev_enable_job_control

work=$(mktemp -d "${TMPDIR:-/tmp}/m1nervac0nsole-dev-egress-test.XXXXXX")
sentinel_pid=""
final_cleanup() {
	[ -n "$sentinel_pid" ] && kill "$sentinel_pid" 2>/dev/null
	dev_cleanup
	rm -rf -- "$work"
}
trap final_cleanup EXIT

fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok:   $*"; }
alive() { kill -0 "$1" 2>/dev/null; }

mkdir -p "$work/bin"
ADDR=127.0.0.1:18888

# A proxy that binds, writes its CA, prints the ready line, and keeps a grandchild in its group.
cat >"$work/bin/ok" <<'EOF'
#!/usr/bin/env bash
dir=$5; addr=$3
mkdir -p "$dir"; : >"$dir/ca.pem"
sleep 0.3
echo "egress proxy on $addr; presenting \"x\"; no request ceiling"
sleep 300 &
echo $! >"$FAKE_CHILD_PID_FILE"
wait
EOF
# A proxy that cannot bind: exits straight away, no ready line.
cat >"$work/bin/conflict" <<'EOF'
#!/usr/bin/env bash
echo "egress: listen $3: bind: address already in use" >&2
exit 1
EOF
# A foreign listener / wedged proxy: alive, silent, and a stale CA is already on disk.
cat >"$work/bin/silent" <<'EOF'
#!/usr/bin/env bash
sleep 300
EOF
chmod +x "$work/bin/"*
export FAKE_CHILD_PID_FILE="$work/child.pid"

# An unrelated process that must survive our cleanup.
sleep 300 &
sentinel_pid=$!
# It is a job of THIS shell, but not one we own: it was not started via dev_launch.

userdir="$work/userdata/egress"
mkdir -p "$userdir"
echo "user-ca-keep" >"$userdir/ca.pem"

# 1. A healthy proxy: ready, env exported, then cleanup is exact.
unset M1NERVAC0NSOLE_EGRESS_PROXY M1NERVAC0NSOLE_EGRESS_CA
DEV_TMP="$work/devtmp1"; mkdir -p "$DEV_TMP"
if dev_start_egress "$work/bin/ok" "$ADDR" "$work/okdir" "$DEV_TMP/egress.log" 10; then
	pid=$DEV_LAST_PID
	[ "${M1NERVAC0NSOLE_EGRESS_PROXY:-}" = "http://$ADDR" ] && pass "env exported on success" || fail "M1NERVAC0NSOLE_EGRESS_PROXY not exported: '${M1NERVAC0NSOLE_EGRESS_PROXY:-}'"
	[ "${M1NERVAC0NSOLE_EGRESS_CA:-}" = "$work/okdir/ca.pem" ] && pass "CA env exported" || fail "M1NERVAC0NSOLE_EGRESS_CA wrong: '${M1NERVAC0NSOLE_EGRESS_CA:-}'"
	grandchild=$(cat "$FAKE_CHILD_PID_FILE" 2>/dev/null || true)
	dev_cleanup
	alive "$pid" && fail "owned proxy still alive after cleanup" || pass "owned proxy stopped"
	[ -n "$grandchild" ] && alive "$grandchild" && fail "grandchild in the owned group survived cleanup" || pass "owned group (incl. grandchild) stopped"
	alive "$sentinel_pid" && pass "unrelated process survived cleanup" || fail "cleanup killed a process we do not own"
	[ -d "$work/devtmp1" ] && fail "temp dir not removed" || pass "temp dir removed"
else
	fail "healthy proxy was not recognised as ready"
	dev_cleanup
fi

# 2. A port conflict: must fail fast, export nothing.
unset M1NERVAC0NSOLE_EGRESS_PROXY M1NERVAC0NSOLE_EGRESS_CA
DEV_TMP="$work/devtmp2"; mkdir -p "$DEV_TMP"
start=$(date +%s)
if dev_start_egress "$work/bin/conflict" "$ADDR" "$work/conflictdir" "$DEV_TMP/egress.log" 20 2>/dev/null; then
	fail "a proxy that failed to bind was treated as ready"
else
	pass "bind failure reported"
fi
[ $(($(date +%s) - start)) -lt 10 ] && pass "bind failure detected promptly (not by timeout)" || fail "bind failure took the full timeout"
[ -z "${M1NERVAC0NSOLE_EGRESS_PROXY:-}${M1NERVAC0NSOLE_EGRESS_CA:-}" ] && pass "nothing exported after failure" || fail "env exported despite failure"
dev_cleanup

# 3. Stale CA + stale log marker + a silent live process: file presence must not count as ready.
unset M1NERVAC0NSOLE_EGRESS_PROXY M1NERVAC0NSOLE_EGRESS_CA
DEV_TMP="$work/devtmp3"; mkdir -p "$DEV_TMP"
log="$DEV_TMP/egress.log"
echo "egress proxy on $ADDR; presenting \"stale\"" >"$log"
mkdir -p "$work/stale"; : >"$work/stale/ca.pem"
if dev_start_egress "$work/bin/silent" "$ADDR" "$work/stale" "$log" 2 2>/dev/null; then
	fail "a stale CA / stale log marker was accepted as readiness"
else
	pass "stale CA and stale log marker rejected"
fi
[ -z "${M1NERVAC0NSOLE_EGRESS_PROXY:-}${M1NERVAC0NSOLE_EGRESS_CA:-}" ] && pass "nothing exported for the silent process" || fail "env exported for a process that never became ready"
spid=$DEV_LAST_PID
dev_cleanup
alive "$spid" && fail "silent process left running after cleanup" || pass "silent process cleaned up"

# 4. The user's own data was never touched by any of the above.
[ "$(cat "$userdir/ca.pem")" = "user-ca-keep" ] && pass "user CA untouched" || fail "user CA modified"
alive "$sentinel_pid" && pass "sentinel still alive at end" || fail "sentinel died"

# dev_cleanup resets the EXIT trap, so run the final cleanup explicitly.
final_cleanup
if [ "$fails" -ne 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all dev-egress checks passed"

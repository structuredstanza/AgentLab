#!/usr/bin/env bash
# Run every test suite in one command. Pass an area to run just that one:
#   tests/run.sh            all
#   tests/run.sh go         m1nervac0nsole Go tests
#   tests/run.sh proxy      provider-proxy tests
#   tests/run.sh python     deployment/lab tests
#   tests/run.sh web        Next.js UI tests
#   tests/run.sh dev        dev-launcher process contract
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AREA="${1:-all}"
STATUS=0

case "$AREA" in
all | go | proxy | python | web | dev) ;;
*)
	printf 'usage: %s [all|go|proxy|python|web|dev]\n' "${BASH_SOURCE[0]}" >&2
	exit 2
	;;
esac

run() {
	local name="$1"
	shift
	printf '\n=== %s ===\n' "$name"
	if "$@"; then
		printf 'PASS  %s\n' "$name"
	else
		printf 'FAIL  %s\n' "$name"
		STATUS=1
	fi
}

# The db and server suites need Postgres. Two server tests fail rather than skip
# without it, so an unset DSN is called out here instead of leaving a bare FAIL.
if [ -z "${M1NERVAC0NSOLE_PG_DSN:-}" ]; then
	printf 'note: M1NERVAC0NSOLE_PG_DSN is unset. db/ and server/ need Postgres; expect failures there.\n'
fi

case "$AREA" in
all | go)
	run "go (m1nervac0nsole)" bash -c \
		'cd "$0/m1nervac0nsole" && go vet ./... && go test -p 1 ./... -count=1 -timeout 2400s' "$ROOT"
	;;
esac

case "$AREA" in
all | proxy)
	run "proxy (cliproxy host)" "$ROOT/deployment/cliproxy/run-tests.sh" -count=1
	;;
esac

case "$AREA" in
all | python)
	run "python (lab, guest, export)" python3 -m unittest discover -s "$ROOT/tests/python" -p 'test_*.py'
	;;
esac

case "$AREA" in
all | web)
	run "web (next)" bash -c 'cd "$0/m1nervac0nsole/web" && npx vitest run' "$ROOT"
	;;
esac

# Proves the dev launcher's process contract: the masking proxy must report its
# own readiness, cleanup must signal only the groups it started (never the
# launching shell), and a failure must export nothing.
case "$AREA" in
all | dev)
	run "dev launcher contract" "$ROOT/m1nervac0nsole/scripts/test-dev-egress.sh"
	;;
esac

printf '\n'
if [ "$STATUS" -eq 0 ]; then
	printf 'all suites passed\n'
else
	printf 'at least one suite failed\n'
fi
exit "$STATUS"

#!/bin/sh
# ARTEX daemon start script (Linux / macOS / Docker ENTRYPOINT)
#
# Usage:
#   ./start.sh                       Run in the foreground (stop with Ctrl-C)
#   nohup ./start.sh >artex.log 2>&1 &   Run in the background as a resident process
#   ./start.sh -addr :9000           Any extra arguments are passed through to artex as-is
#
# This script runs artex, and when the process exits, it checks the exit code:
#
#   0      User stopped normally     → exit the loop
#   Other  Abnormal exit             → restart after backoff (1→2→4… up to 60 seconds)
set -u

cd "$(dirname "$0")" || exit 1

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] executable not found: $BIN" >&2; exit 1; }

MAX_DELAY=60

child=0
stopping=0

# Forward the stop signal to the artex main process.
#
# This is essential under Docker. docker stop sends SIGTERM only to PID 1 (that is, this script)
# and does not send it to child processes. If it is not forwarded, artex never receives the signal, cannot shut down gracefully,
# and after 10 seconds is force-killed with SIGKILL, cutting off whatever work was in progress.
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# A signal interrupts wait and makes it return a value greater than 128. At this point the child process is still in the middle of a graceful shutdown, so,
	# wait must be called once more to obtain the real exit code.
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[artex] stopped"
		exit 0
	fi

	case "$code" in
		0)
			echo "[artex] exited normally"
			exit 0
			;;
		*)
			echo "[artex] abnormal exit (code=$code), restarting in ${delay}s" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done

#!/bin/sh
# ARTEX daemon start script (Linux / macOS / Docker ENTRYPOINT)
#
# Usage:
#   ./start.sh                       Run in the foreground (stop with Ctrl-C)
#   nohup ./start.sh >artex.log 2>&1 &   Run in the background as a resident process
#   ./start.sh -addr :9000           Any extra arguments are passed through to artex as-is
#
# This script does one thing. It runs artex, and when the process exits, it checks the exit code to decide whether to start it again.
#
#   0      User stopped normally     → exit the loop
#   75     Program requests a restart → restart immediately (triggered on screen by clicking "One-click update" or "Rollback")
#   Other  Abnormal exit             → restart after backoff (1→2→4… up to 60 seconds)
#
# Downloading, SHA256 checksum verification, and binary replacement are intentionally not done here. That logic would have to be written twice, once in sh and once in bat,
# This is exactly the part that must never go wrong. Once a non-executable binary has been swapped in, this script will faithfully
# keep launching it again and again, and the user has no option but to log into the machine and recover it by hand. That is why verification and replacement are all kept in Go (the selfupdate package),
# so that artex handles them itself at startup, and the script stays simple.
set -u

cd "$(dirname "$0")" || exit 1

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] executable not found: $BIN" >&2; exit 1; }

RESTART_CODE=75
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
		"$RESTART_CODE")
			# The update/rollback is ready. Running it again makes artex complete the version swap at startup (see selfupdate.Bootstrap).
			echo "[artex] restart requested (applying new version)…"
			delay=1
			;;
		*)
			echo "[artex] abnormal exit (code=$code), restarting in ${delay}s" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done

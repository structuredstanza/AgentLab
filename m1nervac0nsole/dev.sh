#!/usr/bin/env bash
# Development mode: runs the backend (127.0.0.1:8787) and the traffic recording proxy (:8788)
# together with the frontend next dev server (:5173).
# The frontend /api is reverse-proxied to the backend. Press Ctrl-C to shut everything down together.
#
# Process safety: every process started here is a direct child in its own process group, and on exit
# ONLY those groups (plus the temp build directory) are signalled; the group that launched this script
# is never touched.
#
# For the single-binary (frontend embedded) approach, see the "Single binary" section of the README. This script is not used for it.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/dev-procs.sh
. scripts/dev-procs.sh

dev_enable_job_control
trap 'dev_cleanup; exit 130' INT TERM
trap dev_cleanup EXIT

DEV_TMP=$(mktemp -d "${TMPDIR:-/tmp}/m1nervac0nsole-dev.XXXXXX")

# Build once, up front and without a deadline, so no later step races a compile. The binary lives under
# the temp dir, which config.BaseDir() treats as throwaway, so data/ and config.json still resolve
# against this directory.
go build -o "$DEV_TMP/m1nervac0nsole" ./cmd/m1nervac0nsole

# Backend (frontend not embedded). The number of concurrent work agents is configured in "System Settings".
dev_launch - "$DEV_TMP/m1nervac0nsole" -addr 127.0.0.1:8787 -proxy 127.0.0.1:8788

# Frontend hot reload (Next dev server on the documented :5173; /api is reverse-proxied to :8787).
dev_launch - bash -c 'cd web && exec npm run dev -- -p 5173'

echo "[dev] backend :8787 / recording proxy :8788 / frontend http://localhost:5173  (Ctrl-C to stop)"
# Stop everything as soon as any child exits, instead of leaving a half-running stack.
wait -n || true

#!/usr/bin/env bash
# Development mode: runs the backend (127.0.0.1:8787), the traffic recording proxy (:8788) and the
# masking egress proxy (:8888) together with the frontend next dev server (:5173).
# The frontend /api is reverse-proxied to the backend. Press Ctrl-C to shut everything down together.
#
# Process safety: every process started here is a direct child in its own process group, and on exit
# ONLY those groups (plus the temp build directory) are signalled; the group that launched this script
# is never touched. The egress proxy must prove readiness itself (its own fresh log line), otherwise
# nothing else is started.
#
# For the single-binary (frontend embedded) approach, see the "Single binary" section of the README. This script is not used for it.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/dev-egress.sh
. scripts/dev-egress.sh

dev_enable_job_control
trap 'dev_cleanup; exit 130' INT TERM
trap dev_cleanup EXIT

DEV_TMP=$(mktemp -d "${TMPDIR:-/tmp}/artex-dev.XXXXXX")

# Build once, up front and without a deadline, so no later step races a compile. The binary lives under
# the temp dir, which config.BaseDir() treats as throwaway, so data/ and config.json still resolve
# against this directory.
go build -o "$DEV_TMP/artex" ./cmd/artex

# Masking egress proxy. The backend's own outbound requests (asset-enrichment probes) exit through it, and
# any manifest tool that honours ARTEX_EGRESS_PROXY does too. Its CA and identity live under data/egress
# (persisted, never deleted here); the backend trusts that CA explicitly and fails enrichment probes closed
# when the proxy is absent. Nothing below runs unless this exact process reports it is listening.
dev_start_egress "$DEV_TMP/artex" 127.0.0.1:8888 "$PWD/data/egress" "$DEV_TMP/egress.log" 30 || exit 1

# Backend (frontend not embedded). The number of concurrent work agents is configured in "System Settings".
dev_launch - "$DEV_TMP/artex" -addr 127.0.0.1:8787 -proxy 127.0.0.1:8788

# Frontend hot reload (Vite/Next dev server; /api is reverse-proxied to :8787).
dev_launch - bash -c 'cd web && exec npm run dev'

echo "[dev] backend :8787 / recording proxy :8788 / egress proxy :8888 / frontend http://localhost:5173  (Ctrl-C to stop)"
# Stop everything as soon as any child exits, instead of leaving a half-running stack.
wait -n || true

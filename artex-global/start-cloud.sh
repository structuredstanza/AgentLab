#!/usr/bin/env bash
set -euo pipefail

# Render assigns a PORT environment variable arbitrarily, so specify the arguments so the app starts on that port
# Default execution and preserve skill/data paths
: "${PORT:?PORT environment variable must be set}"
echo "[*] Starting ARTEX Server on port :$PORT"
exec ./artex -addr ":$PORT"

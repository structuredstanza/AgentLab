#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG=v8.0.47
MODULE=github.com/router-for-me/CLIProxyAPI/v8
HOST="$ROOT/deployment/cliproxy"
PATCH="$HOST/core.patch"
REVISION="90c447d3a8727d115aa7552ec93ce023736ed492"
WORK="$(mktemp -d "$ROOT/.upstream-work/test.XXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" \
    https://github.com/router-for-me/CLIProxyAPI.git "$WORK/core"
git -C "$WORK/core" apply "$PATCH"
cp "$HOST/go.mod" "$WORK/host.mod"
[ -f "$HOST/go.sum" ] && cp "$HOST/go.sum" "$WORK/host.sum"
GOWORK=off go -C "$HOST" mod edit -modfile "$WORK/host.mod" -replace "$MODULE=$WORK/core"
GOWORK=off go -C "$HOST" test -mod=mod -modfile "$WORK/host.mod" "$@" ./internal/...

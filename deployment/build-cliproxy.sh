#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REVISION=90c447d3a8727d115aa7552ec93ce023736ed492
TAG=v8.0.47
MODULE=github.com/router-for-me/CLIProxyAPI/v8
HOST="$ROOT/deployment/cliproxy"
PATCH="$HOST/core.patch"
OUTPUT="$ROOT/dist/provider-proxy"

[ -f "$HOST/go.mod" ] || { printf 'Missing native host module\n' >&2; exit 1; }
[ -f "$PATCH" ] || { printf 'Missing reviewed core patch\n' >&2; exit 1; }
mkdir -p "$ROOT/.upstream-work" "$ROOT/dist"
WORK="$(mktemp -d "$ROOT/.upstream-work/native-build.XXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" \
    https://github.com/router-for-me/CLIProxyAPI.git "$WORK/core"
[ "$(git -C "$WORK/core" rev-parse HEAD)" = "$REVISION" ] || {
    printf 'Pinned upstream tag no longer matches the reviewed revision\n' >&2
    exit 1
}
git -C "$WORK/core" apply --check "$PATCH"
git -C "$WORK/core" apply "$PATCH"

cp "$HOST/go.mod" "$WORK/host.mod"
if [ -f "$HOST/go.sum" ]; then cp "$HOST/go.sum" "$WORK/host.sum"; fi
GOWORK=off go -C "$HOST" mod edit -modfile "$WORK/host.mod" \
    -replace "$MODULE=$WORK/core"
GOWORK=off go -C "$HOST" build -mod=readonly -modfile "$WORK/host.mod" \
    -trimpath -ldflags '-s -w' -o "$WORK/provider-proxy" ./cmd/provider-proxy
install -m 0755 "$WORK/provider-proxy" "$OUTPUT"
install -m 0644 "$WORK/core/LICENSE" "$OUTPUT.LICENSE"
printf 'Built %s from %s\n' "$OUTPUT" "$REVISION"
sha256sum "$PATCH" "$OUTPUT" "$OUTPUT.LICENSE"

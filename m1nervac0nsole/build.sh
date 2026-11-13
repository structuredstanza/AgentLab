#!/usr/bin/env bash
# m1nervac0nsole cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   M1NERVAC0NSOLE_TARGET_OS=linux             One target OS in single-target mode.
#   M1NERVAC0NSOLE_TARGET_ARCH=amd64           One target arch in single-target mode.
#   M1NERVAC0NSOLE_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   M1NERVAC0NSOLE_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   M1NERVAC0NSOLE_OUTPUT=/path/to/m1nervac0nsole       Explicit binary path in single-target mode.
#   M1NERVAC0NSOLE_OUTPUT_DIR=dist             Directory for default binary paths.
#   M1NERVAC0NSOLE_PACKAGE=1                   Create a zip archive for each target.
#   M1NERVAC0NSOLE_PACKAGE_DIR=dist            Directory for release archives.
#   M1NERVAC0NSOLE_COMPRESS=off                UPX mode: off, auto, or required.
#   M1NERVAC0NSOLE_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   M1NERVAC0NSOLE_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   M1NERVAC0NSOLE_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   M1NERVAC0NSOLE_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./build.sh                         Build for the current system and architecture
  ./build.sh --target linux/amd64   Build one specified target
  ./build.sh --release               Build and package all supported targets

Options:
  --release              Build amd64/arm64 targets for Linux, macOS, and Windows, and create zip archives
  --target OS/ARCH       Specify a single target. Example: windows/amd64
  --upx                  Force binary compression with UPX (may affect compatibility on some Linux environments)
  --no-compress          Do not use UPX; shrink only with the Go linker, then zip
  --help                 Show help

Override the target list with M1NERVAC0NSOLE_TARGETS. Example:
  M1NERVAC0NSOLE_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
M1NERVAC0NSOLE_RELEASE="${M1NERVAC0NSOLE_RELEASE:-0}"
M1NERVAC0NSOLE_COMPRESS="${M1NERVAC0NSOLE_COMPRESS:-off}"
M1NERVAC0NSOLE_PACKAGE="${M1NERVAC0NSOLE_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      M1NERVAC0NSOLE_RELEASE=1
      M1NERVAC0NSOLE_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires an OS/ARCH argument"
      target_arg="$2"
      case "$target_arg" in
        */*)
          M1NERVAC0NSOLE_TARGET_OS="${target_arg%%/*}"
          M1NERVAC0NSOLE_TARGET_ARCH="${target_arg##*/}"
          M1NERVAC0NSOLE_TARGETS="$target_arg"
          ;;
        *) die "Target must be in OS/ARCH format. Example: linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      M1NERVAC0NSOLE_COMPRESS=0
      shift
      ;;
    --upx)
      M1NERVAC0NSOLE_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "Unknown argument: $1 (see --help for usage)" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "Go not found (this project requires Go 1.26 or later)"

M1NERVAC0NSOLE_GOSUMDB="${M1NERVAC0NSOLE_GOSUMDB:-sum.golang.org}"
if [ -z "${M1NERVAC0NSOLE_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    M1NERVAC0NSOLE_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    M1NERVAC0NSOLE_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
M1NERVAC0NSOLE_BUILD_VERSION="${M1NERVAC0NSOLE_BUILD_VERSION#v}"
M1NERVAC0NSOLE_OUTPUT_DIR="${M1NERVAC0NSOLE_OUTPUT_DIR:-dist}"
M1NERVAC0NSOLE_PACKAGE_DIR="${M1NERVAC0NSOLE_PACKAGE_DIR:-$M1NERVAC0NSOLE_OUTPUT_DIR}"
M1NERVAC0NSOLE_UPX_ARGS="${M1NERVAC0NSOLE_UPX_ARGS:---best --lzma}"

if [ "${M1NERVAC0NSOLE_RELEASE}" = "1" ]; then
  M1NERVAC0NSOLE_TARGETS="${M1NERVAC0NSOLE_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  M1NERVAC0NSOLE_TARGET_OS="${M1NERVAC0NSOLE_TARGET_OS:-$(GOSUMDB="$M1NERVAC0NSOLE_GOSUMDB" go env GOOS)}"
  M1NERVAC0NSOLE_TARGET_ARCH="${M1NERVAC0NSOLE_TARGET_ARCH:-$(GOSUMDB="$M1NERVAC0NSOLE_GOSUMDB" go env GOARCH)}"
  M1NERVAC0NSOLE_TARGETS="${M1NERVAC0NSOLE_TARGETS:-${M1NERVAC0NSOLE_TARGET_OS}/${M1NERVAC0NSOLE_TARGET_ARCH}}"
fi

if [ "${M1NERVAC0NSOLE_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "M1NERVAC0NSOLE_SKIP_FRONTEND=1 but server/webui/dist does not exist"
else
  command -v npm >/dev/null 2>&1 || die "npm not found (the static frontend build requires Node.js/npm)"
  command -v rsync >/dev/null 2>&1 || die "rsync not found"
  info "Building static frontend assets"
  if [ "${M1NERVAC0NSOLE_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "Syncing frontend assets to server/webui/dist"
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$M1NERVAC0NSOLE_COMPRESS" in
    0|off|false|none)
      info "Skipping UPX: $binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "M1NERVAC0NSOLE_COMPRESS must be one of: off, auto, required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$M1NERVAC0NSOLE_COMPRESS" = "required" ]; then
      die "M1NERVAC0NSOLE_COMPRESS=required but upx was not found"
    fi
    warn "upx not found; keeping the linker-compressed result as is: $binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$M1NERVAC0NSOLE_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$M1NERVAC0NSOLE_COMPRESS" = "required" ]; then
      die "UPX compression failed: $binary"
    fi
    warn "UPX does not support this target format; keeping the uncompressed binary: $binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX compression complete: $binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="m1nervac0nsole-${M1NERVAC0NSOLE_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${M1NERVAC0NSOLE_PACKAGE_DIR}/${package_name}"
  archive="${M1NERVAC0NSOLE_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "zip is required for packaging"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # The supervisor startup script is the official entry point: relaunches m1nervac0nsole after abnormal exit
  # and forwards process termination signals. Ship only the one matching the target system.
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$M1NERVAC0NSOLE_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release archive: $archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "Invalid target: $target (must be in OS/ARCH format)" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "Unsupported system: $goos (supported: linux, darwin, windows)" ;;
  esac

  binary_name="m1nervac0nsole"
  [ "$goos" = "windows" ] && binary_name="m1nervac0nsole.exe"
  if [ -n "${M1NERVAC0NSOLE_OUTPUT:-}" ] && [ "$M1NERVAC0NSOLE_RELEASE" != "1" ]; then
    output="$M1NERVAC0NSOLE_OUTPUT"
  else
    output="${M1NERVAC0NSOLE_OUTPUT_DIR}/m1nervac0nsole-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "Compiling ${goos}/${goarch}, version ${M1NERVAC0NSOLE_BUILD_VERSION}"
  GOSUMDB="$M1NERVAC0NSOLE_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${M1NERVAC0NSOLE_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/m1nervac0nsole

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$M1NERVAC0NSOLE_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  if [ "$goos" = "linux" ] && ! [ "$output" -ef "${M1NERVAC0NSOLE_OUTPUT_DIR}/${goarch}/${binary_name}" ]; then
    mkdir -p "${M1NERVAC0NSOLE_OUTPUT_DIR}/${goarch}"
    cp -f "$output" "${M1NERVAC0NSOLE_OUTPUT_DIR}/${goarch}/${binary_name}"
  fi
  ok "Compilation complete: $output"
}

write_checksums() {
  [ "$M1NERVAC0NSOLE_PACKAGE" = "1" ] || return 0
  checksum_file="$M1NERVAC0NSOLE_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$M1NERVAC0NSOLE_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$M1NERVAC0NSOLE_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "Neither sha256sum nor shasum was found; skipping SHA256SUMS"
    return 0
  fi
  ok "Checksum file: $checksum_file"
}

mkdir -p "$M1NERVAC0NSOLE_OUTPUT_DIR"
if [ "$M1NERVAC0NSOLE_PACKAGE" = "1" ]; then mkdir -p "$M1NERVAC0NSOLE_PACKAGE_DIR"; fi

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$M1NERVAC0NSOLE_TARGETS"
IFS="$old_ifs"
[ "${#targets[@]}" -gt 0 ] || die "M1NERVAC0NSOLE_TARGETS must not be empty"
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$M1NERVAC0NSOLE_PACKAGE" = "1" ]; then
  write_checksums
  info "Release packages created: $M1NERVAC0NSOLE_PACKAGE_DIR"
fi

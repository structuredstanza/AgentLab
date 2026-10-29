#!/usr/bin/env bash
# ARTEX update script: ① Docker update (pull new image and recreate)  ② Local build update (rebuild binary)
# Pairs with install.sh. install handles the initial installation, and update handles upgrading to a new version.
# There is no need to run DB migrations manually. artex re-runs schema.sql idempotently on every startup (ADD COLUMN/CREATE
# INDEX IF NOT EXISTS included) "Restarting is the migration." Data (pgdata volume, ./data, ./skills) is not affected.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# ── Optional: sync the repository to the latest code (compose, scripts, and locally compiled sources are all updated from this) ───────
sync_repo(){
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "Not a git working copy; skipping git pull"; return; }
  [ "$(ask 'Pull the latest code (git pull --ff-only)? (y/n)' y)" = y ] || return
  if ! git pull --ff-only; then
    warn "git pull could not fast-forward (local changes exist or the branch has diverged). Resolve it manually and try again. This time the current code will be used as is"
  fi
}

# ── ① Docker update ───────────────────────────────
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "docker / docker compose not found. Install and deploy first with ./install.sh"
  [ -f .env ] || die ".env not found. Complete the first deployment with ./install.sh first"

  # Optional: upgrade to the specified version tag (if left empty, follows ARTEX_TAG in .env; the default is latest)
  local tag; tag="$(ask 'Target image tag (press Enter to use .env / latest)' '')"
  if [ -n "$tag" ]; then
    if grep -q '^ARTEX_TAG=' .env; then
      sed -i.bak "s|^ARTEX_TAG=.*|ARTEX_TAG=${tag}|" .env && rm -f .env.bak
    else
      printf '\nARTEX_TAG=%s\n' "$tag" >> .env
    fi
    ok "Set ARTEX_TAG to ${tag}"
  fi

  # Only artex is affected. postgres is pinned to 16-alpine, so there is no need to upgrade it (pulling it would waste bandwidth,
  # and a major version change would also carry compatibility risk). Because artex declares depends_on postgres, running up with the service name
  # will automatically start pg if it is not running, and if it is already running it is left as is and not recreated.
  info "Pulling the new image (artex only)…"
  if ! docker compose pull artex; then
    warn "Could not pull the image ghcr.io/jiwoochris/artex-global (check that the specified tag is a published release tag and that the network is reachable)"
    die "Image update failed. You can also update with \"2) Local update (recompile with go)\""
  fi
  info "Recreating and starting (artex automatically migrates the schema on restart)…"
  docker compose up -d artex
  ok "Update complete → http://localhost:8787"
  info "View logs: docker compose logs -f artex"
  info "Clean up old images (optional): docker image prune -f"
}

# ── ② Local compile update ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "Go not found (>=1.26): https://go.dev/dl/"
  [ -f config.json ] || warn "config.json not found. For the first deployment, use ./install.sh"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "Rebuilding the frontend static output…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "Recompiling a single binary with the frontend embedded…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "npm not found. Compiling the backend only, without the embedded frontend (run the frontend separately with npm run dev)"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "Compilation complete → ./artex"
  warn "To apply the changes, restart the running artex process (the schema is migrated automatically on restart)"
}

echo "=============================="
echo "  ARTEX update"
echo "  1) Docker update (pull the new image and recreate)"
echo "  2) Local update (recompile with go)"
echo "=============================="
case "$(ask 'Choice' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "Invalid choice" ;;
esac

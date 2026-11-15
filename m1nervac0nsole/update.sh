#!/usr/bin/env bash
# m1nervac0nsole update script: ① Docker update (pull new image and recreate)  ② Local build update (rebuild binary)
# Pairs with install.sh. install handles the initial installation, and update handles upgrading to a new version.
# There is no need to run DB migrations manually. m1nervac0nsole re-runs schema.sql idempotently on every startup (ADD COLUMN/CREATE
# INDEX IF NOT EXISTS included) "Restarting is the migration." Data (pgdata volume, ./data, ./skills) is not affected.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# ── ① Docker rebuild update ───────────────────────
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "docker / docker compose not found. Install and deploy first with ./install.sh"
  [ -f .env ] || die ".env not found. Complete the first deployment with ./install.sh first"

  info "Building this custom fork locally; no stock image or repository is pulled."
  ./build.sh
  if ! docker compose build m1nervac0nsole; then
    die "Docker build failed. You can also update with \"2) Local update (recompile with go)\""
  fi
  info "Recreating and starting (m1nervac0nsole automatically migrates the schema on restart)…"
  docker compose up -d m1nervac0nsole
  ok "Update complete → http://localhost:8787"
  info "View logs: docker compose logs -f m1nervac0nsole"
  info "Clean up old dangling images (optional): docker image prune -f"
}

# ── ② Local compile update ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "Go not found (>=1.26): https://go.dev/dl/"
  [ -f config.json ] || warn "config.json not found. For the first deployment, use ./install.sh"
  ok "Go: $(go version)"

  # build.sh owns the frontend export, the embed copy and the version stamp
  if command -v npm >/dev/null 2>&1; then
    info "Rebuilding the binary and the embedded frontend…"
    M1NERVAC0NSOLE_OUTPUT="$PWD/m1nervac0nsole" ./build.sh
  else
    warn "npm not found. Compiling the backend only, without the embedded frontend (run the frontend separately with npm run dev)"
    CGO_ENABLED=0 go build -o m1nervac0nsole ./cmd/m1nervac0nsole
  fi
  ok "Compilation complete → ./m1nervac0nsole"
  warn "To apply the changes, restart the running m1nervac0nsole process (the schema is migrated automatically on restart)"
}

echo "=============================="
echo "  m1nervac0nsole update (custom AgentLab fork)"
echo "  1) Docker update (rebuild local image and restart)"
echo "  2) Local update (recompile binary with go)"
echo "=============================="
case "$(ask 'Choice' 1)" in
  1) update_docker ;;
  2) update_local ;;
  *) die "Invalid choice" ;;
esac

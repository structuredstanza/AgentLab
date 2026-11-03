#!/usr/bin/env bash
# Back up AgentLab PostgreSQL and, optionally, its private host-mounted state.
#
# Usage:
#   scripts/backup.sh [--with-data] [--keep N] [--output-dir DIR]
#
#   --with-data    archive ../state/ (private captures, artifacts, runtime state)
#   --keep N       number of db dumps to keep (default 14; data archives rotate
#                  to the same count)
#   --output-dir   where to write (default backups/, relative to the repo root)
#
# PostgreSQL dump uses the host DSN file/environment or the local Docker service.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { sed -n '2,15p' "$0" | sed 's/^# \?//'; }

KEEP=14
OUTPUT_DIR="backups"
WITH_DATA=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP="${2:?}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?}"; shift 2 ;;
    --with-data) WITH_DATA=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$KEEP" in (*[!0-9]*|'') echo "--keep must be a positive integer" >&2; exit 2 ;; esac

# Compose reads .env for credentials; source it for the dump command too.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi
PGUSER_NAME="${POSTGRES_USER:-artex}"
PGDATABASE_NAME="${POSTGRES_DB:-artex}"

umask 077
mkdir -p "$OUTPUT_DIR"
chmod 0700 "$OUTPUT_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
DB_OUT="$OUTPUT_DIR/artex-db-$TS.sql.gz"
if [ -e "$DB_OUT" ]; then
  echo "refusing to overwrite $DB_OUT" >&2
  exit 1
fi

# Discover database source: AgentLab DSN file, environment DSN, or docker-compose postgres service
DSN=""
for candidate in "${ARTEX_PG_DSN:-}" "${DATABASE_URL:-}" "/state/runtime/secrets/artex-db.dsn" "../state/runtime/secrets/artex-db.dsn"; do
  if [ -n "$candidate" ]; then
    if [ -f "$candidate" ]; then
      DSN="$(cat "$candidate")"
      break
    elif [ "${candidate#postgres}" != "$candidate" ]; then
      DSN="$candidate"
      break
    fi
  fi
done

dump_success=0
if [ -n "$DSN" ] && command -v pg_dump >/dev/null 2>&1; then
  if pg_dump "$DSN" | gzip > "$DB_OUT"; then
    dump_success=1
  fi
fi

if [ "$dump_success" -eq 0 ]; then
  if command -v docker >/dev/null 2>&1 && docker compose ps --services 2>/dev/null | grep -q '^postgres$'; then
    if docker compose exec -T postgres pg_dump -U "$PGUSER_NAME" "$PGDATABASE_NAME" | gzip > "$DB_OUT"; then
      dump_success=1
    fi
  fi
fi

if [ "$dump_success" -eq 0 ]; then
  rm -f "$DB_OUT"
  echo "pg_dump failed: no reachable PostgreSQL database found (checked /state/runtime/secrets/artex-db.dsn, ARTEX_PG_DSN, and docker compose)" >&2
  exit 1
fi

chmod 0600 "$DB_OUT"
gzip -t "$DB_OUT"
echo "wrote $DB_OUT ($(du -h "$DB_OUT" | cut -f1))"
if [ "$WITH_DATA" -eq 1 ]; then
  STATE_DIR="${AGENTLAB_STATE_DIR:-../state}"
  DATA_OUT="$OUTPUT_DIR/agentlab-state-$TS.tar.gz"
  if [ ! -d "$STATE_DIR" ]; then
    echo "AgentLab state directory not found: $STATE_DIR (set AGENTLAB_STATE_DIR)" >&2
    exit 1
  fi
  if ! tar -czf "$DATA_OUT" -C "$STATE_DIR" . 2>"$OUTPUT_DIR/.tar.err"; then
    rm -f "$DATA_OUT"
    echo "AgentLab state archive failed:" >&2
    head -5 "$OUTPUT_DIR/.tar.err" >&2
    rm -f "$OUTPUT_DIR/.tar.err"
    exit 1
  fi
  chmod 0600 "$DATA_OUT"
  rm -f "$OUTPUT_DIR/.tar.err"
  echo "wrote $DATA_OUT ($(du -h "$DATA_OUT" | cut -f1))"
fi

prune() {
  ls -1t "$OUTPUT_DIR"/$1 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
    echo "pruning $old"
    rm -f "$old"
  done
}
prune 'artex-db-*.sql.gz'
[ "$WITH_DATA" -eq 1 ] && prune 'agentlab-state-*.tar.gz'
echo "backup complete ($KEEP newest kept)"

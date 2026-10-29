#!/usr/bin/env bash
# =============================================================================
# ARTEX administrator password reset script
#
# The login username is fixed to ARTEX. The password is stored as a bcrypt hash in the settings table of the database
# Stored under the auth.password_hash key. This script connects to the database and then generates a bcrypt hash inside the DB using pgcrypto.
# Rewrites it with that key. Fully compatible with the backend login verification (golang.org/x/crypto/bcrypt).
#
# Two deployment modes:
#   local (default) -- connects directly to the database with psql from the host. Connection settings are taken in this priority order:
#                    Command-line argument > --dsn/$ARTEX_PG_DSN > database.* in config.json
#   docker        -- runs psql inside the postgres container via `docker compose exec` (or `docker exec`).
#                    The compose setup does not expose 5432 to the host by default, so psql is run inside the container.
#
# Usage examples:
#   ./reset-password.sh                          # Local: automatically reads config.json/environment and prompts interactively for the new password
#   ./reset-password.sh -p 'NewPass!'            # Local; specify the new password directly
#   ./reset-password.sh --dsn postgres://u:p@h:5432/artex
#   ./reset-password.sh -H 127.0.0.1 -P 5433 -U autopentest -W pass -d artex
#   ./reset-password.sh -m docker                # Docker deployment (reads POSTGRES_* from .env)
#   ./reset-password.sh -m docker -c pg-container-name --exec docker
#
# Security: The new password is passed via an environment variable and psql \getenv (it does not appear in the process argv), and is automatically escaped via :'var'
# Automatically escaped (prevents SQL injection). The database password is passed via PGPASSWORD, so likewise it does not go into argv.
# =============================================================================
set -euo pipefail

PASS_KEY="auth.password_hash"
BCRYPT_COST=10

MODE=""            # local | docker (leave empty for automatic detection)
DSN=""
HOST="" PORT="" USER="" DBPASS="" DBNAME="" SSLMODE=""
CONFIG=""
CONTAINER=""       # postgres service/container name in docker mode (default: postgres)
EXEC_KIND=""       # compose | docker (which exec to use in docker mode. Auto if left empty)
NEWPASS=""
ASSUME_YES=0

die() { echo "Error: $*" >&2; exit 1; }
info() { echo "· $*" >&2; }

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ---- Argument parsing -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)        MODE="${2:-}"; shift 2 ;;
    --dsn)            DSN="${2:-}"; shift 2 ;;
    -H|--host)        HOST="${2:-}"; shift 2 ;;
    -P|--port)        PORT="${2:-}"; shift 2 ;;
    -U|--user)        USER="${2:-}"; shift 2 ;;
    -W|--db-password) DBPASS="${2:-}"; shift 2 ;;
    -d|--dbname)      DBNAME="${2:-}"; shift 2 ;;
    --sslmode)        SSLMODE="${2:-}"; shift 2 ;;
    --config)         CONFIG="${2:-}"; shift 2 ;;
    -c|--container)   CONTAINER="${2:-}"; shift 2 ;;
    --exec)           EXEC_KIND="${2:-}"; shift 2 ;;
    -p|--new-password) NEWPASS="${2:-}"; shift 2 ;;
    -y|--yes)         ASSUME_YES=1; shift ;;
    -h|--help)        usage ;;
    *) die "Unknown argument: $1 (see -h for usage)" ;;
  esac
done

# ---- Read database.* from config.json (only when in local mode and connection info was not specified explicitly) -----
# We prefer parsing with python3 (more robust). If python3 is not available, fall back to grep (since config.json has cleanly separated fields).
read_config_json() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$path" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1])).get("database", {})
except Exception:
    sys.exit(1)
# You can pass the dsn directly or supply the fields separately
if d.get("dsn"):
    print("DSN\t" + d["dsn"]); sys.exit(0)
for k in ("host","port","user","password","dbname","sslmode"):
    if d.get(k) is not None:
        print(k.upper() + "\t" + str(d[k]))
PY
  else
    # Simple last-resort fallback: grep for each key (value is a string or number)
    local k
    for k in host port user password dbname sslmode; do
      local v
      v=$(grep -oE "\"$k\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)" "$path" 2>/dev/null \
            | head -1 | sed -E "s/.*:[[:space:]]*//; s/^\"//; s/\"$//") || true
      [[ -n "$v" ]] && echo -e "${k^^}\t$v"
    done
  fi
}

apply_config_fields() {
  local line key val
  while IFS=$'\t' read -r key val; do
    [[ -z "$key" ]] && continue
    case "$key" in
      DSN)      [[ -z "$DSN" ]] && DSN="$val" ;;
      HOST)     [[ -z "$HOST" ]] && HOST="$val" ;;
      PORT)     [[ -z "$PORT" ]] && PORT="$val" ;;
      USER)     [[ -z "$USER" ]] && USER="$val" ;;
      PASSWORD) [[ -z "$DBPASS" ]] && DBPASS="$val" ;;
      DBNAME)   [[ -z "$DBNAME" ]] && DBNAME="$val" ;;
      SSLMODE)  [[ -z "$SSLMODE" ]] && SSLMODE="$val" ;;
    esac
  done
}

# ---- Automatic mode detection ---------------------------------------------------------
if [[ -z "$MODE" ]]; then
  if [[ -n "$DSN$HOST$USER$DBNAME" || -n "${ARTEX_PG_DSN:-}" || -f "${CONFIG:-config.json}" ]]; then
    MODE="local"
  elif command -v docker >/dev/null 2>&1 && [[ -f docker-compose.yml ]]; then
    MODE="docker"
  else
    MODE="local"
  fi
fi
info "Deployment mode: $MODE"

# ---- Collect new password -----------------------------------------------------------
if [[ -z "$NEWPASS" ]]; then
  read -r -s -p "Enter new password (username is fixed to ARTEX):" NEWPASS; echo >&2
  [[ -n "$NEWPASS" ]] || die "Password cannot be empty"
  read -r -s -p "Re-enter to confirm:" NEWPASS2; echo >&2
  [[ "$NEWPASS" == "$NEWPASS2" ]] || die "The two entries do not match"
fi
[[ -n "$NEWPASS" ]] || die "Password cannot be empty"

# Passes the password to psql via an environment variable (read with \getenv, so it does not appear in argv/ps)
export ARTEX_RESET_NEWPASS="$NEWPASS"

# Generates the bcrypt hash inside the DB and upserts it. The password is automatically escaped as :'newpw'. CREATE EXTENSION is idempotent, and
# if the database role lacks permission to create extensions, an error occurs here (see the run failure branch below for guidance).
SQL=$(cat <<SQL
\\set ON_ERROR_STOP on
\\getenv newpw ARTEX_RESET_NEWPASS
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO settings(key, value)
VALUES ('$PASS_KEY', crypt(:'newpw', gen_salt('bf', $BCRYPT_COST)))
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
SQL
)

# ---- Run -----------------------------------------------------------------
if [[ "$MODE" == "local" ]]; then
  # Connection info precedence: command line > --dsn/$ARTEX_PG_DSN > config.json
  if [[ -z "$DSN" && -z "$HOST$USER$DBNAME" ]]; then
    [[ -n "${ARTEX_PG_DSN:-}" ]] && DSN="$ARTEX_PG_DSN"
  fi
  if [[ -z "$DSN" && -z "$HOST$USER$DBNAME" ]]; then
    cfg="${CONFIG:-config.json}"
    if [[ -f "$cfg" ]]; then
      info "Reading the database settings from $cfg"
      apply_config_fields < <(read_config_json "$cfg")
    fi
  fi

command -v psql >/dev/null 2>&1 || die "psql was not found on this machine (install postgresql-client or use -m docker)"

  declare -a PSQL_ARGS=()
  if [[ -n "$DSN" ]]; then
    PSQL_ARGS=("$DSN")
    target="$DSN"
  else
    [[ -n "$USER"   ]] || die "Database user (-U) is missing, or no valid config.json/DSN was provided"
    [[ -n "$DBNAME" ]] || die "Database name (-d) is missing, or no valid config.json/DSN was provided"
    HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-5432}"; SSLMODE="${SSLMODE:-disable}"
    PSQL_ARGS=(-h "$HOST" -p "$PORT" -U "$USER" -d "$DBNAME")
    [[ -n "$SSLMODE" ]] && export PGSSLMODE="$SSLMODE"
    [[ -n "$DBPASS" ]] && export PGPASSWORD="$DBPASS"
    target="$USER@$HOST:$PORT/$DBNAME"
  fi

  info "Target database: $target"
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Reset the ARTEX password in this database? [y/N]" ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "Cancelled"
  fi

  if ! printf '%s\n' "$SQL" | psql "${PSQL_ARGS[@]}" -v ON_ERROR_STOP=1 -q >/dev/null; then
    die "Write failed. If you see a pgcrypto permission or missing-extension error, use a role that can create extensions, or run CREATE EXTENSION pgcrypto manually first."
  fi

else
  # ---- docker ----
command -v docker >/dev/null 2>&1 || die "docker not found"
  CONTAINER="${CONTAINER:-postgres}"

  # Exec method selection: prefer docker compose exec (service name), otherwise docker exec (container name)
  if [[ -z "$EXEC_KIND" ]]; then
    if docker compose version >/dev/null 2>&1 && [[ -f docker-compose.yml ]]; then
      EXEC_KIND="compose"
    else
      EXEC_KIND="docker"
    fi
  fi

  # psql credentials inside the container: command line first, then POSTGRES_* in .env, and finally compose defaults (artex)
  if [[ -f .env ]]; then
    # shellcheck disable=SC1091
    set -a; . ./.env; set +a
  fi
  DUSER="${USER:-${POSTGRES_USER:-artex}}"
  DNAME="${DBNAME:-${POSTGRES_DB:-artex}}"
  [[ -n "$DBPASS" ]] && export PGPASSWORD="$DBPASS"
  [[ -z "${PGPASSWORD:-}" && -n "${POSTGRES_PASSWORD:-}" ]] && export PGPASSWORD="$POSTGRES_PASSWORD"

  info "Target: psql -U $DUSER -d $DNAME inside container $CONTAINER (exec=$EXEC_KIND)"
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Reset the ARTEX password in this container database? [y/N]" ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "Cancelled"
  fi

  # -e only gives the name and not the value → it inherits from the current environment, so the password does not appear in the docker command argv.
  declare -a EXEC_CMD
  if [[ "$EXEC_KIND" == "compose" ]]; then
    EXEC_CMD=(docker compose exec -T -e ARTEX_RESET_NEWPASS -e PGPASSWORD "$CONTAINER"
              psql -U "$DUSER" -d "$DNAME" -v ON_ERROR_STOP=1 -q)
  else
    EXEC_CMD=(docker exec -i -e ARTEX_RESET_NEWPASS -e PGPASSWORD "$CONTAINER"
              psql -U "$DUSER" -d "$DNAME" -v ON_ERROR_STOP=1 -q)
  fi

  if ! printf '%s\n' "$SQL" | "${EXEC_CMD[@]}" >/dev/null; then
    die "Write failed. Check the container name (-c), the database account (POSTGRES_* in .env), and the role's pgcrypto permissions."
  fi
fi

unset ARTEX_RESET_NEWPASS
echo "✓ ARTEX admin password has been reset. Log in with username ARTEX and the new password (no service restart needed)."
echo "  Existing login sessions (tokens) are invalidated within a few seconds. If this is recovery after the account was taken over or leaked, also review custom tools, MCP, LLM, and notification settings."

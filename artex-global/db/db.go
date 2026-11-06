// Package db is the PostgreSQL data source for ARTEX (replacing the old graph single-file SQLite).
// It opens the connection, applies the schema, and seeds the built-in agent and variable catalogs.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns is the upper bound of the connection pool (see `Open`). It is kept well below PostgreSQL's default max_connections (100),
// yet well above the application's own nested connection depth (the bootstrapper's schema advisory lock,
// while holding one connection, seedBuiltins acquires another), so it does not self-deadlock.
// does not get dropped.
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env ARTEX_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql does not limit the number of connections by default, so when the pool has no idle connection it always
	// opens a new one, pushing toward PostgreSQL's max_connections (default 100), and only then gets rejected.
	// Under heavy load, queries then receive the error `FATAL: sorry, too many clients
	// already` instead of "no value to read," and this error takes the same shape as the "read failure" in the authentication path below.
	// With a cap set, overflow waits for an idle connection (slows down instead of erroring), reset-password.sh·psql
	// If you run with a lower max_connections, lower this value as well.
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // Default interactive shell switch when creating a line; ON CONFLICT does not overwrite the user's later manual toggles
	runSeconds            *int // Wall-clock cap in seconds for a single run when building a row: nil = use the seed default (1200), 0 = no time limit
}

type promptVar struct{ name, desc, example, source string }

// intp returns a pointer to v, used to explicitly set optional builtinAgent fields (such as runSeconds).
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). Built-in tools are not stored in the DB; here we only seed the agent + variable catalog.
// Note: the default for the interactive shell of planner/worker/mainagent/auto is set uniformly to true by the interactive_shell_default_v1
// Uniformly set the block to true (respecting subsequent toggles); the interactiveShell here only applies to new agents that should be enabled by default when the row is created.
var builtinAgents = []builtinAgent{
	{"goals", "Goal breakdown", "goals", "Breaks the penetration-test objective into independent, verifiable sub-goals.", []promptVar{
		{"EngagementDescription", "Task description (target/background)", "Test the example.com site", "exploration"},
		// Now is a global runtime variable (see server.globalPromptVars), no longer defined in each agent's catalog
		// Duplicate definition; otherwise withGlobalVars appending would collide with the global entry.
	}, false, nil},
	{"planner", "Planning", "planner", "Reads the situation and determines goals; adds exploration intents only when there is a genuinely uncovered new direction (one planning loop per task).", []promptVar{
		{"Goal", "Overall task goal", "Gain administrator privileges on example.com", "exploration"},
		{"AssetSummary", "Asset count / type distribution summary (optional)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "Main", "main", "Human interface: observes progress and turns the human's intent into a hint or high-priority intent.", []promptVar{
		{"Goal", "Current task goal", "Gain administrator privileges on example.com", "exploration"},
		{"AssetSummary", "Opening situation summary (optional)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "Confirmed findings summary (optional)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "Execute", "worker", "Claims one intent, executes it, writes discovered facts/findings back to the knowledge graph, then stops.", []promptVar{
		{"ProxyAddr", "Recorded proxy address (drives the dual-copy if branch)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "Worker self-identifier (optional)", "worker-1", "runtime"},
	}, false, nil},
	// Auto: built-in "platform operations" agent. Does not participate in the penetration orchestration loop; driven via the chat page, operates the platform with tools.
	{"auto", "Auto", "assistant", "Platform operations assistant: uses tools to manage tasks (create/view/pause/add hints) and assets, and can create/modify skills, custom tools, and MCP.", nil, false, nil},
	// Penetration testing: built-in "standalone pentest" agent. Driven from the chat page, a single agent walks the full penetration chain from reconnaissance to wrap-up, planning, executing, and verifying on its own. Interactive shell is enabled by default.
	{"pentest", "Penetration testing", "assistant", "Standalone pentest agent: one agent walks the full chain from recon → attack-surface discovery → deep exploitation → verification → wrap-up, planning, executing, and adversarially verifying on its own.", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// After 'Now' was promoted from each agent directory to a global runtime variable, old databases still have a leftover 'Now' entry in goals
	// It would collide with the global item (duplicate key in the frontend variable list); clean it up as well.
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (user
	// enables it themselves when needed), no proxy by default. The traffic-capture toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.migrateBuiltinSeedLabelsEN(); err != nil {
		return fmt.Errorf("relabel builtin seeds: %w", err)
	}
	if err := d.migrateCriticalPathRuleV6(); err != nil {
		return fmt.Errorf("rewrite critical-path rule: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[Built-in] Government site (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[Built-in] Government site (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[Built-in] Education site (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[Built-in] Education site (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES (true, $1, $2, $3, true)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
//
// recon-orchestration goes to the same agents that hold run_tool (auto, pentest,
// worker, planner). It is the skill that explains how to choose and drive a
// manifest tool, so binding the tool without the skill left the agents to
// rediscover the ranking by hand — or skip it and reach for Bash.
var builtinSkillVisibility = map[string][]string{
	"api-recon":           {"auto", "pentest", "worker"},
	"recon-orchestration": {"auto", "pentest", "worker", "planner"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
//
// This only holds because toggle-off writes enabled=false rather than deleting the
// row (see ToggleSkillVisibility / SetAgentSkillVisibility): a deleted row leaves
// no record of the user's choice, and this seed would insert it straight back.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v1"); v == "done" {
		return nil
	}
	type rule struct {
		name     string
		target   string // tool_name | tool_input
		typ      string // string | regex
		pattern  string
		action   string
		message  string
		priority int
	}
	rules := []rule{
		// ── System destructive commands (priority 100) ──────────────────────────────────
		{
			name:     "[Built-in] Recursive forced delete rm -rf",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
			action:   "deny",
			message:  "Recursive forced deletion (rm -rf / rm --recursive) is forbidden; it can permanently damage the system or target environment",
			priority: 100,
		},
		{
			name:     "[Built-in] Delete critical system directories",
			target:   "tool_input",
			typ:      "regex",
			pattern:  criticalPathDeletePattern,
			action:   "deny",
			message:  "Deleting critical system paths is forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Disk format mkfs",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bmkfs\b`,
			action:   "deny",
			message:  "Formatting a disk (mkfs) is forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Overwrite disk device with dd",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "Overwriting a disk device with dd is forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Fork bomb",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `:\(\)\s*\{[^}]*:\|:`,
			action:   "deny",
			message:  "Running a fork bomb is forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Shutdown / reboot",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
			action:   "deny",
			message:  "Shutdown or reboot commands are forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Kill all processes",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
			action:   "deny",
			message:  "kill -9 -1 or killall -9 (killing all processes) is forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Disk erase shred / wipe",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "Erasing a disk device with shred/wipe is forbidden",
			priority: 100,
		},
		{
			name:     "[Built-in] Clear firewall rules",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
			action:   "deny",
			message:  "Clearing firewall rules (iptables -F / nft flush) is forbidden",
			priority: 100,
		},
		// ── Database destructive operations (priority 90) ─────────────────────────────────
		{
			name:     "[Built-in] SQL DROP DATABASE / TABLE / SCHEMA",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
			action:   "deny",
			message:  "DROP operations are forbidden; they can irreversibly destroy database objects",
			priority: 90,
		},
		{
			name:     "[Built-in] SQL TRUNCATE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
			action:   "deny",
			message:  "TRUNCATE is forbidden; it may clear all rows in a data table",
			priority: 90,
		},
		{
			name:     "[Built-in] MongoDB drop / dropDatabase",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
			action:   "deny",
			message:  "MongoDB drop operations are forbidden",
			priority: 90,
		},
		{
			name:     "[Built-in] Redis FLUSHALL / FLUSHDB",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
			action:   "deny",
			message:  "Redis FLUSHALL / FLUSHDB is forbidden; it may clear all cached data",
			priority: 90,
		},
		// ── HTTP destructive requests (priority 80) ──────────────────────────────────
		// Three common ways for an Agent to send a DELETE request:
		//   1. curl -X DELETE / --request DELETE (executed directly via the Bash tool or written into a script)
		//   2. Python HTTP client .delete() method
		//   3. In JS/general scripts, method: 'DELETE' / method="DELETE"
		{
			name:     "[Built-in] curl / wget sending DELETE requests",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
			action:   "deny",
			message:  "Sending HTTP DELETE requests via curl/wget is forbidden; it may delete target system data",
			priority: 80,
		},
		{
			name:     "[Built-in] Python HTTP client DELETE (requests/httpx/aiohttp)",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
			action:   "deny",
			message:  "Sending HTTP DELETE requests with a Python HTTP client is forbidden",
			priority: 80,
		},
		{
			name:     "[Built-in] HTTP DELETE method declared in script (JS/generic)",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
			action:   "deny",
			message:  "Declaring and sending HTTP DELETE requests in a script is forbidden",
			priority: 80,
		},
		{
			name:     "[Built-in] Bulk clear / purge endpoint paths",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
			action:   "deny",
			message:  "Calling bulk clear or destroy endpoints (/clear /wipe /flush /purge etc.) is forbidden",
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v1", "done")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are plain [built-in] rules — the user can
// disable or delete them. The exfil rule ships DISABLED by default (its
// curl/wget/nc pipe pattern mis-fires on legitimate CTF/pentest reverse-shell and
// data-transfer pipes); enable it manually when exfil gating is actually wanted.
func (d *DB) seedDefaultInterceptRulesV2() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v2"); v == "done" {
		return nil
	}
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		enabled  bool
		priority int
	}{
		{
			name:     "[Built-in] Destructive system commands",
			pattern:  `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
			action:   "deny",
			message:  "Destructive command rejected (rm -rf / / mkfs / dd / fork bomb / shutdown or reboot / overwriting a disk device)",
			enabled:  true,
			priority: 100,
		},
		{
			name:     "[Built-in] Data exfiltration pipe",
			pattern:  `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
			action:   "deny",
			message:  "Suspected data-exfiltration pipe rejected (command output being sent out via curl/wget/nc)",
			enabled:  false,
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, $3, 'tool_input', 'regex', $4, $5, $6, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.enabled, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v2", "done")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method* (curl -X DELETE, requests.delete(, method:'DELETE'),
// and v1's path rule covers only /clear /wipe /flush /purge /truncate /drop /destroy
// /factory-reset /reset-all — so a plain `curl 'http://t/api/user/delete?id=1'` (a
// delete endpoint reached with GET/POST, which is how most web apps expose deletion)
// slipped through every built-in rule. Own flag so it also lands on DBs that already
// ran v1/v2, where editing the v1 seed would have no effect.
//
// The pattern deliberately requires a separator after the verb so /delivery,
// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
// /delete-user do. destroy is re-covered here because v1's rule does not allow a
// suffix (/destroyAll was missed).
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const deleteEndpointPathPattern = `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`

// criticalPathDeletePattern denies `rm` aimed at system directories.
//
// Two shipped versions were wrong, both found in a live engagement:
//
// v3/v4 used a bare `/` alternative, so any absolute path within 60 characters of
// `rm` read as rm's target — and plain deletes of user files were denied too.
//
// v5 narrowed the gap to `[^;&|\n]` and made root a whole token, but the rule is
// matched against the JSON-encoded tool input, where a line break is the two
// characters `\` and `n`, not a newline. The gap walked straight across `\n` and
// still denied `rm -f $CJ\ncurl … -o /dev/null`.
//
// The gap is now an alternation: any character except `; & |` and backslash, or a
// backslash followed by anything but n/r. That stops at a JSON line break while
// still allowing escaped quotes, and the optional `\?` before the separator keeps
// `rm -f \"/etc/hosts\"` covered.
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const criticalPathDeletePattern = `\brm\b(?:[^;&|\\]|\\[^nr]){0,80}\\?["'\s](?:/(?:\s|$|["'])|/(?:etc|bin|sbin|usr|boot|lib|sys|proc|dev|root|var)(?:/|\s|$|["']))`

// criticalPathDeletePatternV5 is what the v5 migration installed; a database may
// still hold it. oldCriticalPathDeletePattern is the original v3/v4 pattern.
const criticalPathDeletePatternV5 = `\brm\b[^;&|\n]{0,80}["'\s](?:/(?:\s|$|["'])|/(?:etc|bin|sbin|usr|boot|lib|sys|proc|dev|root|var)(?:/|\s|$|["']))`

const oldCriticalPathDeletePattern = `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`

// migrateCriticalPathRuleV6 rewrites the seeded critical-path rule on databases
// that still hold either shipped version. Only a row holding one of those byte
// strings verbatim is touched, so a rule the operator edited is left alone.
func (d *DB) migrateCriticalPathRuleV6() error {
	const flag = "intercept_critical_path_rule_v6"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`UPDATE intercept_rules SET pattern=$2 WHERE name=$1 AND pattern IN ($3,$4)`,
		"[Built-in] Delete critical system directories", criticalPathDeletePattern,
		criticalPathDeletePatternV5, oldCriticalPathDeletePattern,
	); err != nil {
		return fmt.Errorf("rewrite critical-path rule: %w", err)
	}
	return d.SetSetting(flag, "done")
}

func (d *DB) seedDefaultInterceptRulesV3() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v3"); v == "done" {
		return nil
	}
	const name = "[Built-in] Delete-type endpoint paths"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 80, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		name,
		deleteEndpointPathPattern,
		"Calling delete-type endpoints (/delete /remove /unlink /erase etc.) is forbidden regardless of HTTP method. Many applications trigger deletion with GET/POST, and it still really deletes target data",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return d.SetSetting("intercept_default_rules_v3", "done")
}

// migrateBuiltinSeedLabelsEN relabels the built-in intercept/asset rules that v1-v3
// seeded in Chinese. Only rows whose name/message/note still equal the exact shipped
// original are updated, so user-edited or user-created rules are never touched.
// Gated by its own flag so it runs once per DB.
func (d *DB) migrateBuiltinSeedLabelsEN() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_en_v4"); v == "done" {
		return nil
	}
	type relabel struct{ oldName, oldMsg, newName, newMsg string }
	rules := []relabel{
		{"[\u5185\u7f6e] \u9012\u5f52\u5f3a\u5236\u5220\u9664 rm -rf", "\u7981\u6b62\u6267\u884c\u9012\u5f52\u5f3a\u5236\u5220\u9664\uff08rm -rf / rm --recursive\uff09\uff0c\u53ef\u80fd\u6c38\u4e45\u635f\u574f\u7cfb\u7edf\u6216\u9776\u673a\u73af\u5883", "[Built-in] Recursive forced delete rm -rf", "Recursive forced deletion (rm -rf / rm --recursive) is forbidden; it can permanently damage the system or target environment"},
		{"[\u5185\u7f6e] \u5220\u9664\u7cfb\u7edf\u5173\u952e\u76ee\u5f55", "\u7981\u6b62\u5220\u9664\u7cfb\u7edf\u5173\u952e\u8def\u5f84", "[Built-in] Delete critical system directories", "Deleting critical system paths is forbidden"},
		{"[\u5185\u7f6e] \u78c1\u76d8\u683c\u5f0f\u5316 mkfs", "\u7981\u6b62\u683c\u5f0f\u5316\u78c1\u76d8\uff08mkfs\uff09", "[Built-in] Disk format mkfs", "Formatting a disk (mkfs) is forbidden"},
		{"[\u5185\u7f6e] \u8986\u5199\u78c1\u76d8\u8bbe\u5907 dd", "\u7981\u6b62\u4f7f\u7528 dd \u8986\u5199\u78c1\u76d8\u8bbe\u5907", "[Built-in] Overwrite disk device with dd", "Overwriting a disk device with dd is forbidden"},
		{"[\u5185\u7f6e] Fork \u70b8\u5f39", "\u7981\u6b62\u6267\u884c Fork \u70b8\u5f39", "[Built-in] Fork bomb", "Running a fork bomb is forbidden"},
		{"[\u5185\u7f6e] \u5173\u673a / \u91cd\u542f", "\u7981\u6b62\u6267\u884c\u5173\u673a\u6216\u91cd\u542f\u547d\u4ee4", "[Built-in] Shutdown / reboot", "Shutdown or reboot commands are forbidden"},
		{"[\u5185\u7f6e] \u6740\u6b7b\u5168\u90e8\u8fdb\u7a0b", "\u7981\u6b62 kill -9 -1 \u6216 killall -9\uff08\u6740\u6b7b\u6240\u6709\u8fdb\u7a0b\uff09", "[Built-in] Kill all processes", "kill -9 -1 or killall -9 (killing all processes) is forbidden"},
		{"[\u5185\u7f6e] \u78c1\u76d8\u64e6\u9664 shred / wipe", "\u7981\u6b62\u5bf9\u78c1\u76d8\u8bbe\u5907\u6267\u884c shred/wipe \u64e6\u9664", "[Built-in] Disk erase shred / wipe", "Erasing a disk device with shred/wipe is forbidden"},
		{"[\u5185\u7f6e] \u6e05\u7a7a\u9632\u706b\u5899\u89c4\u5219", "\u7981\u6b62\u6e05\u7a7a\u9632\u706b\u5899\u89c4\u5219\uff08iptables -F / nft flush\uff09", "[Built-in] Clear firewall rules", "Clearing firewall rules (iptables -F / nft flush) is forbidden"},
		{"[\u5185\u7f6e] SQL DROP DATABASE / TABLE / SCHEMA", "\u7981\u6b62\u6267\u884c DROP \u64cd\u4f5c\uff0c\u53ef\u80fd\u4e0d\u53ef\u9006\u5730\u9500\u6bc1\u6570\u636e\u5e93\u5bf9\u8c61", "[Built-in] SQL DROP DATABASE / TABLE / SCHEMA", "DROP operations are forbidden; they can irreversibly destroy database objects"},
		{"[\u5185\u7f6e] SQL TRUNCATE", "\u7981\u6b62\u6267\u884c TRUNCATE\uff0c\u53ef\u80fd\u6e05\u7a7a\u6570\u636e\u8868\u6240\u6709\u6570\u636e", "[Built-in] SQL TRUNCATE", "TRUNCATE is forbidden; it may clear all rows in a data table"},
		{"[\u5185\u7f6e] MongoDB drop / dropDatabase", "\u7981\u6b62\u6267\u884c MongoDB drop \u64cd\u4f5c", "[Built-in] MongoDB drop / dropDatabase", "MongoDB drop operations are forbidden"},
		{"[\u5185\u7f6e] Redis FLUSHALL / FLUSHDB", "\u7981\u6b62\u6267\u884c Redis FLUSHALL / FLUSHDB\uff0c\u53ef\u80fd\u6e05\u7a7a\u5168\u90e8\u7f13\u5b58\u6570\u636e", "[Built-in] Redis FLUSHALL / FLUSHDB", "Redis FLUSHALL / FLUSHDB is forbidden; it may clear all cached data"},
		{"[\u5185\u7f6e] curl / wget \u53d1\u9001 DELETE \u8bf7\u6c42", "\u7981\u6b62\u901a\u8fc7 curl/wget \u53d1\u9001 HTTP DELETE \u8bf7\u6c42\uff0c\u53ef\u80fd\u5220\u9664\u76ee\u6807\u7cfb\u7edf\u6570\u636e", "[Built-in] curl / wget sending DELETE requests", "Sending HTTP DELETE requests via curl/wget is forbidden; it may delete target system data"},
		{"[\u5185\u7f6e] Python HTTP \u5ba2\u6237\u7aef DELETE\uff08requests/httpx/aiohttp\uff09", "\u7981\u6b62\u4f7f\u7528 Python HTTP \u5ba2\u6237\u7aef\u53d1\u9001 DELETE \u8bf7\u6c42", "[Built-in] Python HTTP client DELETE (requests/httpx/aiohttp)", "Sending HTTP DELETE requests with a Python HTTP client is forbidden"},
		{"[\u5185\u7f6e] \u811a\u672c\u4e2d\u58f0\u660e HTTP DELETE \u65b9\u6cd5\uff08JS/\u901a\u7528\uff09", "\u7981\u6b62\u5728\u811a\u672c\u4e2d\u58f0\u660e\u5e76\u53d1\u9001 HTTP DELETE \u8bf7\u6c42", "[Built-in] HTTP DELETE method declared in script (JS/generic)", "Declaring and sending HTTP DELETE requests in a script is forbidden"},
		{"[\u5185\u7f6e] \u6279\u91cf\u6e05\u7a7a / \u6e05\u9664\u63a5\u53e3\u8def\u5f84", "\u7981\u6b62\u8c03\u7528\u6279\u91cf\u6e05\u7a7a\u6216\u9500\u6bc1\u7c7b\u63a5\u53e3\uff08/clear /wipe /flush /purge \u7b49\uff09", "[Built-in] Bulk clear / purge endpoint paths", "Calling bulk clear or destroy endpoints (/clear /wipe /flush /purge etc.) is forbidden"},
		{"[\u5185\u7f6e] \u7834\u574f\u6027\u7cfb\u7edf\u547d\u4ee4", "\u7834\u574f\u6027\u547d\u4ee4\u88ab\u62d2\u7edd\uff08rm -rf / / mkfs / dd / fork bomb / \u5173\u673a\u91cd\u542f / \u8986\u5199\u78c1\u76d8\u8bbe\u5907\uff09", "[Built-in] Destructive system commands", "Destructive command rejected (rm -rf / / mkfs / dd / fork bomb / shutdown or reboot / overwriting a disk device)"},
		{"[\u5185\u7f6e] \u6570\u636e\u5916\u6cc4\u7ba1\u9053", "\u7591\u4f3c\u6570\u636e\u5916\u6cc4\u7ba1\u9053\u88ab\u62d2\u7edd\uff08\u547d\u4ee4\u8f93\u51fa\u7ecf curl/wget/nc \u5916\u4f20\uff09", "[Built-in] Data exfiltration pipe", "Suspected data-exfiltration pipe rejected (command output being sent out via curl/wget/nc)"},
		{"[\u5185\u7f6e] \u5220\u9664\u7c7b\u63a5\u53e3\u8def\u5f84", "\u7981\u6b62\u8c03\u7528\u5220\u9664\u7c7b\u63a5\u53e3\uff08/delete /remove /unlink /erase \u7b49\uff09\uff0c\u4e0d\u8bba\u4f7f\u7528\u54ea\u79cd HTTP \u65b9\u6cd5——\u591a\u6570\u5e94\u7528\u7684\u5220\u9664\u63a5\u53e3\u7528 GET/POST \u5c31\u80fd\u89e6\u53d1\uff0c\u540c\u6837\u4f1a\u771f\u5b9e\u5220\u9664\u76ee\u6807\u6570\u636e", "[Built-in] Delete-type endpoint paths", "Calling delete-type endpoints (/delete /remove /unlink /erase etc.) is forbidden regardless of HTTP method. Many applications trigger deletion with GET/POST, and it still really deletes target data"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`UPDATE intercept_rules SET name=$3, message=$4 WHERE name=$1 AND message=$2`,
			r.oldName, r.oldMsg, r.newName, r.newMsg); err != nil {
			return fmt.Errorf("relabel rule %q: %w", r.oldName, err)
		}
	}
	notes := [][2]string{
		{"[\u5185\u7f6e] \u653f\u5e9c\u7f51\u7ad9 (.gov)", "[Built-in] Government site (.gov)"},
		{"[\u5185\u7f6e] \u653f\u5e9c\u7f51\u7ad9 (.gov.cn)", "[Built-in] Government site (.gov.cn)"},
		{"[\u5185\u7f6e] \u6559\u80b2\u7f51\u7ad9 (.edu)", "[Built-in] Education site (.edu)"},
		{"[\u5185\u7f6e] \u6559\u80b2\u7f51\u7ad9 (.edu.cn)", "[Built-in] Education site (.edu.cn)"},
	}
	for _, n := range notes {
		if _, err := d.Exec(`UPDATE asset_intercept_rules SET note=$2 WHERE builtin=true AND note=$1`, n[0], n[1]); err != nil {
			return fmt.Errorf("relabel asset rule %q: %w", n[0], err)
		}
	}
	return d.SetSetting("intercept_default_rules_en_v4", "done")
}

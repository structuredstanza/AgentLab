package db

import (
	"database/sql"
	"errors"
	"testing"
)

// The browser MCP ships enabled, and an install that seeded it disabled is
// migrated once. The one-shot settings flag is what makes a later user
// toggle-off stick: without it the migration would resurrect the row on every
// restart.
func TestBrowserMCPSeedEnablesOnceAndRespectsToggleOff(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	const key = "browser_mcp_enabled_v1"
	const seedArgs = `["@playwright/mcp","--headless"]`
	const backup = "browser-test-backup"

	// Save the shared row + flag and move the row aside under a temporary name,
	// so the seed sees no 'browser' row while the real one keeps its id (and any
	// agent_visibility rows pointing at it).
	var (
		hadRow  bool
		enabled bool
		args    string
		env     string
	)
	err = d.QueryRow(`SELECT enabled, args, env FROM mcp_servers WHERE name='browser'`).Scan(&enabled, &args, &env)
	switch {
	case err == nil:
		hadRow = true
	case errors.Is(err, sql.ErrNoRows):
	default:
		t.Fatal(err)
	}
	oldFlag, hadFlag, err := d.GetSetting(key)
	if err != nil {
		t.Fatal(err)
	}
	if hadRow {
		if _, err := d.Exec(`DELETE FROM mcp_servers WHERE name=$1`, backup); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE mcp_servers SET name=$1 WHERE name='browser'`, backup); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM mcp_servers WHERE name='browser'`)
		if hadRow {
			_, _ = d.Exec(`UPDATE mcp_servers SET name='browser', enabled=$1, args=$2, env=$3 WHERE name=$4`, enabled, args, env, backup)
		}
		if hadFlag {
			_ = d.SetSetting(key, oldFlag)
		} else {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key)
		}
	})

	rowEnabled := func() bool {
		t.Helper()
		var got bool
		if err := d.QueryRow(`SELECT enabled FROM mcp_servers WHERE name='browser'`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// A fresh install on a build that already ran the migration (flag set, row
	// absent): the INSERT itself must ship the row enabled.
	if err := d.SetSetting(key, "true"); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if !rowEnabled() {
		t.Fatal("a fresh install seeded the browser MCP disabled")
	}

	// The user disables it. A restart must not resurrect it.
	if _, err := d.Exec(`UPDATE mcp_servers SET enabled=false WHERE name='browser'`); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if rowEnabled() {
		t.Fatal("a user toggle-off was resurrected by the next startup")
	}

	// An older install: the row was seeded disabled and the migration never ran.
	// The first startup after the upgrade flips it, once.
	if _, err := d.Exec(`UPDATE mcp_servers SET enabled=false, args=$1, env='{}' WHERE name='browser'`, seedArgs); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if !rowEnabled() {
		t.Fatal("the migrated browser MCP row is still disabled")
	}
	if v, _, _ := d.GetSetting(key); v != "true" {
		t.Fatalf("the one-shot flag was not set (got %q)", v)
	}

	// A toggle-off after the migration survives the next restart.
	if _, err := d.Exec(`UPDATE mcp_servers SET enabled=false WHERE name='browser'`); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if rowEnabled() {
		t.Fatal("a post-migration toggle-off was resurrected by the next startup")
	}
}

// The browser skill ships visible to the agents that execute work, and stays
// invisible to the human-interface agent. The MCP itself is bound directly (see
// the test below); the skill is the how-to.
func TestBrowserSkillShipsVisibleToExecutingAgents(t *testing.T) {
	for _, key := range []string{"auto", "pentest", "worker", "planner"} {
		if !containsStr(builtinSkillVisibility["browser"], key) {
			t.Errorf("browser skill is not declared for %q (got %v)", key, builtinSkillVisibility["browser"])
		}
	}

	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	if _, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE skill_name='browser'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM agent_skill_visibility WHERE skill_name='browser'`)
	})
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"auto", "pentest", "worker", "planner"} {
		ag, err := d.GetAgentByKey(key)
		if err != nil || ag == nil {
			t.Fatalf("agent %q missing: %v", key, err)
		}
		got, err := d.AgentSkillNames(ag.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !containsStr(got, "browser") {
			t.Errorf("%s cannot see the browser skill (has %v)", key, got)
		}
	}
	if ag, err := d.GetAgentByKey("mainagent"); err == nil && ag != nil {
		got, _ := d.AgentSkillNames(ag.ID)
		if containsStr(got, "browser") {
			t.Errorf("mainagent should not get the browser skill, has %v", got)
		}
	}
}

// The browser MCP is bound to the executing agents directly, so its tools are in
// the global block from session start. A skill-gated server was listed in the
// prompt but never unlocked in two measured runs.
func TestBrowserMCPIsVisibleToExecutingAgents(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE name='browser')`)
	})
	if _, err := d.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE name='browser')`); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBrowserMCPVisibility(); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"auto", "pentest", "worker", "planner"} {
		ag, err := d.GetAgentByKey(key)
		if err != nil || ag == nil {
			t.Fatalf("agent %q missing: %v", key, err)
		}
		ids, err := d.AgentVisible(ag.ID, "mcp")
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) == 0 {
			t.Errorf("%s cannot see the browser MCP (visible %v)", key, ids)
		}
	}

	// A user toggle-off survives a restart: the seed is insert-if-absent.
	if _, err := d.Exec(`UPDATE agent_visibility SET enabled=false WHERE resource_kind='mcp'`); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBrowserMCPVisibility(); err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err := d.QueryRow(`SELECT count(*) FROM agent_visibility WHERE resource_kind='mcp' AND enabled=true`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("%d bindings were resurrected after a toggle-off", enabled)
	}
}

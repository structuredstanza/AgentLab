package db

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// The Playwright MCP is retired: the native Chromium driver is the only testing
// browser. An upgraded install loses the seeded row and the visibility rows that
// pointed at it, once - a row the operator creates again by hand is theirs, and
// the next startup leaves it alone.
func TestPlaywrightMCPIsRemovedOnce(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	const flag = "browser_mcp_removed_v1"
	oldFlag, hadFlag, err := d.GetSetting(flag)
	if err != nil {
		t.Fatal(err)
	}
	// Park any real row so the test owns the name, and put it back afterwards.
	var (
		hadRow  bool
		enabled bool
		command string
		args    string
		env     string
	)
	err = d.QueryRow(`SELECT enabled, command, args::text, env::text FROM mcp_servers WHERE name='browser'`).
		Scan(&enabled, &command, &args, &env)
	switch {
	case err == nil:
		hadRow = true
	case errors.Is(err, sql.ErrNoRows):
	default:
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM mcp_servers WHERE name='browser'`)
		if hadRow {
			_, _ = d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser','stdio',$1,$2::jsonb,$3::jsonb,$4)
ON CONFLICT (name) DO UPDATE SET command=EXCLUDED.command, args=EXCLUDED.args, env=EXCLUDED.env, enabled=EXCLUDED.enabled`,
				command, args, env, enabled)
		}
		if hadFlag {
			_ = d.SetSetting(flag, oldFlag)
		} else {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, flag)
		}
	})

	// seedRow puts back what an older build shipped: the row plus one binding.
	seedRow := func() int64 {
		t.Helper()
		if _, err := d.Exec(`DELETE FROM mcp_servers WHERE name='browser'`); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser','stdio','playwright-mcp','["--headless"]'::jsonb,'{}'::jsonb,true)`); err != nil {
			t.Fatal(err)
		}
		var id int64
		if err := d.QueryRow(`SELECT id FROM mcp_servers WHERE name='browser'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`
INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled)
SELECT a.id, 'mcp', m.id, '', true FROM agents a, mcp_servers m
WHERE a.key='worker' AND m.name='browser'
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		return id
	}

	rowID := seedRow()
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM mcp_servers WHERE name='browser'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("the retired Playwright MCP row survived the migration")
	}
	if err := d.QueryRow(`SELECT count(*) FROM agent_visibility WHERE resource_kind='mcp' AND resource_id=$1`, rowID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("%d visibility rows still point at the deleted server", rows)
	}
	if v, _, _ := d.GetSetting(flag); v != "true" {
		t.Fatalf("the one-shot flag was not set (got %q)", v)
	}

	// One-shot: a row the operator adds again is not deleted on the next start.
	seedRow()
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM mcp_servers WHERE name='browser'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatal("a browser MCP row created after the migration was deleted again")
	}
}

// Obscura is the research browser: enabled, stealth, and bound to the agents
// that read public material - including the chat agents, which carry no task and
// therefore cannot use the testing browser at all.
func TestObscuraMCPIsStealthAndResearchBound(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	const flag = "obscura_mcp_stealth_v1"
	oldFlag, hadFlag, err := d.GetSetting(flag)
	if err != nil {
		t.Fatal(err)
	}
	var (
		hadRow  bool
		enabled bool
		args    string
	)
	err = d.QueryRow(`SELECT enabled, args::text FROM mcp_servers WHERE name='obscura'`).Scan(&enabled, &args)
	switch {
	case err == nil:
		hadRow = true
	case errors.Is(err, sql.ErrNoRows):
	default:
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM mcp_servers WHERE name='obscura'`)
		if hadRow {
			_, _ = d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('obscura','stdio','obscura',$1::jsonb,'{}'::jsonb,$2)
ON CONFLICT (name) DO UPDATE SET args=EXCLUDED.args, enabled=EXCLUDED.enabled`, args, enabled)
		}
		if hadFlag {
			_ = d.SetSetting(flag, oldFlag)
		} else {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, flag)
		}
	})

	argsOf := func() string {
		t.Helper()
		var got string
		if err := d.QueryRow(`SELECT args::text FROM mcp_servers WHERE name='obscura'`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	seedFresh := func() {
		t.Helper()
		if _, err := d.Exec(`DELETE FROM mcp_servers WHERE name='obscura'`); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
			t.Fatal(err)
		}
		if err := d.seedBuiltins(); err != nil {
			t.Fatal(err)
		}
	}

	// A fresh install seeds the stealth build, enabled.
	seedFresh()
	if got := argsOf(); got != `["mcp", "--stealth"]` {
		t.Fatalf("seeded obscura args = %s, want the stealth build", got)
	}
	var on bool
	if err := d.QueryRow(`SELECT enabled FROM mcp_servers WHERE name='obscura'`).Scan(&on); err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("the research browser was seeded disabled")
	}

	// An install from before the stealth seed gets it once.
	if _, err := d.Exec(`UPDATE mcp_servers SET args='["mcp"]'::jsonb WHERE name='obscura'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if got := argsOf(); !strings.Contains(got, `"--stealth"`) {
		t.Fatalf("the migrated obscura row is not stealth: %s", got)
	}

	// A row the operator edited is left alone.
	if _, err := d.Exec(`UPDATE mcp_servers SET args='["mcp","--stealth","--font-dir","/fonts"]'::jsonb WHERE name='obscura'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltins(); err != nil {
		t.Fatal(err)
	}
	if got := argsOf(); !strings.Contains(got, "/fonts") {
		t.Fatalf("the migration overwrote an edited row: %s", got)
	}

	// Visibility: the research agents see it, the report writer does not.
	if _, err := d.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE name='obscura')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE name='obscura')`)
	})
	if err := d.seedObscuraMCPVisibility(); err != nil {
		t.Fatal(err)
	}
	for _, key := range obscuraMCPAgents {
		ag, err := d.GetAgentByKey(key)
		if err != nil || ag == nil {
			t.Fatalf("agent %q missing: %v", key, err)
		}
		ids, err := d.AgentVisible(ag.ID, "mcp")
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) == 0 {
			t.Errorf("%s cannot see the research browser (visible %v)", key, ids)
		}
	}
	for _, key := range []string{"drafter", "reporter"} {
		ag, err := d.GetAgentByKey(key)
		if err != nil || ag == nil {
			continue
		}
		ids, _ := d.AgentVisible(ag.ID, "mcp")
		if len(ids) != 0 {
			t.Errorf("%s should not see the research browser (visible %v)", key, ids)
		}
	}

	// A user toggle-off survives a restart: the seed is insert-if-absent.
	if _, err := d.Exec(`
UPDATE agent_visibility SET enabled=false
WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE name='obscura')`); err != nil {
		t.Fatal(err)
	}
	if err := d.seedObscuraMCPVisibility(); err != nil {
		t.Fatal(err)
	}
	var resurrected int
	if err := d.QueryRow(`
SELECT count(*) FROM agent_visibility
WHERE resource_kind='mcp' AND enabled=true
  AND resource_id IN (SELECT id FROM mcp_servers WHERE name='obscura')`).Scan(&resurrected); err != nil {
		t.Fatal(err)
	}
	if resurrected != 0 {
		t.Fatalf("%d bindings were resurrected after a toggle-off", resurrected)
	}
}

// The browser skill ships visible to the agents that execute work, and stays
// invisible to the human-interface agent. The native driver's tools are host
// tools bound directly to the executing agents; the skill is the how-to.
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

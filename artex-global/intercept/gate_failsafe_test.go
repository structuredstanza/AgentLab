package intercept

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
)

// The approval gate must not silently allow everything when its rule source is
// unreachable: Match reports "no decision" on a load error, and the guard treats
// that as allow.
func TestMatchFailsOpenWhenRulesCannotBeLoaded(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	if _, err := d.Exec(`DELETE FROM intercept_rules`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO intercept_rules (name, match_target, match_type, pattern, action, message, priority, enabled)
VALUES ('deny-rm','tool_input','string','rm -rf','deny','blocked',1,true)`); err != nil {
		t.Fatal(err)
	}

	ic := New(d)
	ic.Invalidate()
	if dec, ok := ic.Match("Bash", []byte(`{"command":"rm -rf /tmp/x"}`)); !ok || dec.Action != "deny" {
		t.Fatalf("with the DB up, Match should deny: ok=%v dec=%+v", ok, dec)
	}

	// the rule source goes away (connection lost, DB restart, network blip)
	ic.Invalidate()
	_ = d.Close()

	dec, ok := ic.Match("Bash", []byte(`{"command":"rm -rf /tmp/x"}`))
	t.Logf("with the DB down: ok=%v action=%q", ok, dec.Action)
	if !ok || dec.Action != "deny" {
		t.Fatalf("the deny rule was bypassed when the rule source was unreachable (ok=%v action=%q)", ok, dec.Action)
	}
}

// A gate that has never loaded any rules and cannot reach the database must
// refuse rather than run every tool unchecked.
func TestMatchDeniesWhenNoRuleSetWasEverLoaded(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	_ = d.Close() // unreachable rule source, and no cache to fall back on

	ic := New(d)
	dec, ok := ic.Match("Bash", []byte(`{"command":"rm -rf /tmp/x"}`))
	if !ok || dec.Action != "deny" {
		t.Fatalf("a gate with no rules and no database allowed the call: ok=%v action=%q", ok, dec.Action)
	}
	t.Logf("denied with: %s", dec.Message)
}

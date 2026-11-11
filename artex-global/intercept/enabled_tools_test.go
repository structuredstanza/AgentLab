package intercept

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
)

// The curator's one write must enter the rule system out of the box. What it
// stores is durable and an operator may promote it into a scope every task
// reads, so an instance that never configured intercept_enabled_tools still has
// to see the proposal before it lands. Its read tools must stay out: gating a
// search would make the curator unusable without protecting anything.
func TestMemoryProposeIsInterceptedByDefault(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	ic := New(d)
	prior, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetEnabledTools(prior) })
	// Fall back to the hard-coded defaults, whatever this database was left at.
	if err := d.SetSetting("intercept_enabled_tools", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key='intercept_enabled_tools'`); err != nil {
		t.Fatal(err)
	}
	ic.Invalidate()

	if !ic.IsToolEnabled("memory_propose") {
		t.Error("memory_propose is not intercepted by default: a curator proposal would be stored unseen")
	}
	for _, read := range []string{"memory_search", "memory_read", "reflection_search", "task_digest"} {
		if ic.IsToolEnabled(read) {
			t.Errorf("%s is intercepted by default: read-only curator tools must not prompt the operator", read)
		}
	}
}

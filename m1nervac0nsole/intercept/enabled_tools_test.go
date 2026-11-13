package intercept

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// The curator's one write belongs in the default intercept scope, so an
// instance that never configured intercept_enabled_tools shows it in the scope
// dialog and routes it through the rule/judge path. Membership is not the
// approval itself (see TestMemoryProposeAlwaysAsksBeforeWriting); its read tools
// must stay out, because gating a search protects nothing and makes the curator
// unusable.
func TestMemoryProposeIsInterceptedByDefault(t *testing.T) {
	dsn := os.Getenv("M1NERVAC0NSOLE_PG_DSN")
	if dsn == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
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

package guard

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/intercept"
)

// One blocked call must appear in the audit exactly once, as a block, carrying
// the command that was about to run. Before the fix it appeared twice: an
// "allow" row with the command and a "block" row with none, so the trail said
// the destructive command had been permitted.
func TestBlockedCallIsAuditedOnceWithItsCommand(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { d.Close() })

	ic := intercept.New(d)
	ic.Invalidate()
	g := NewWithInterceptor(ic)

	const cmd = "rm -rf /tmp/zz-audit-regression"
	input, _ := json.Marshal(map[string]string{"command": cmd})
	blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
	if !blocked {
		t.Skip("this database has no matching deny rule")
	}

	entries := g.Audit()
	if len(entries) != 1 {
		t.Fatalf("%d audit entries for one blocked call, want 1: %+v", len(entries), entries)
	}
	if entries[0].Action != "block" {
		t.Errorf("action = %q, want block", entries[0].Action)
	}
	if entries[0].Command != cmd {
		t.Errorf("command = %q, want the command that was blocked", entries[0].Command)
	}
}

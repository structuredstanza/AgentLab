package guard

import (
	"context"
	"encoding/json"
	"testing"
)

// End to end through the hook registry: a Bash call naming an excluded host is
// refused, and the audit row records why. This is the shape the server wires.
func TestScopeEnforcementIsAudited(t *testing.T) {
	g := New().WithScope(fakeScope{excluded: map[string]string{
		"out-of-scope.test": "task scope excludes it",
	}})
	input, _ := json.Marshal(map[string]string{"command": "ffuf -u https://out-of-scope.test/FUZZ -w w.txt"})
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
	if !blocked {
		t.Fatal("expected a block")
	}
	if msg == "" {
		t.Fatal("block must carry a reason")
	}
	audit := g.Audit()
	if len(audit) == 0 {
		t.Fatal("a refused call must be audited")
	}
	last := audit[len(audit)-1]
	if last.Action != "block" || last.Command == "" {
		t.Fatalf("audit row = %+v, want action=block with the command recorded", last)
	}
}

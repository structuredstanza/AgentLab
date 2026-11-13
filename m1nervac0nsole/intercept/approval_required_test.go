package intercept_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/guard"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/intercept"
)

const memoryProposeInput = `{"task_id":1,"kind":"note","title":"t","body":"b"}`

// A curator proposal must raise the operator approval card before it is stored.
// Being listed in intercept_enabled_tools only puts a tool into the rule/judge
// path; with no matching rule the call is allowed, which is how a proposal was
// stored with no approval. A saved scope that omits memory_propose, an allow
// rule, and an empty rule table must all still ask.
func TestMemoryProposeAlwaysAsksBeforeWriting(t *testing.T) {
	dsn := os.Getenv("M1NERVAC0NSOLE_PG_DSN")
	if dsn == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	ic := intercept.New(d)
	prior, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetEnabledTools(prior) })
	// A scope saved before the curator existed, so memory_propose is not in it.
	if err := ic.SetEnabledTools([]string{"Bash"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM intercept_pending WHERE tool_name='memory_propose'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_name='memory_propose'`) })

	if !ic.IsToolEnabled("memory_propose") {
		t.Fatal("a saved scope without memory_propose turned its approval off")
	}
	if dec, ok := ic.Match("memory_propose", []byte(memoryProposeInput)); !ok || dec.Action != "ask" {
		t.Fatalf("memory_propose produced no approval: ok=%v action=%q", ok, dec.Action)
	}

	// The guard turns the ask into the normal pending record and blocks the call
	// until a person decides, so a denial leaves the tool unexecuted.
	g := guard.NewWithInterceptor(ic)
	for _, tc := range []struct {
		name    string
		approve bool
		blocked bool
	}{
		{"denied", false, true},
		{"approved", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			blocked := make(chan bool, 1)
			go func() {
				b, _, _ := g.Hooks().PreToolUse(ctx, "memory_propose", []byte(memoryProposeInput))
				blocked <- b
			}()
			var id int64
			until := time.Now().Add(5 * time.Second)
			for id == 0 && time.Now().Before(until) {
				rows, err := d.ListPendingIntercepts()
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if row.ToolName == "memory_propose" {
						id = row.ID
					}
				}
				if id == 0 {
					time.Sleep(2 * time.Millisecond)
				}
			}
			if id == 0 {
				t.Fatal("no approval card was raised for the curator's write")
			}
			if err := ic.Decide(id, tc.approve); err != nil {
				t.Fatal(err)
			}
			if got := <-blocked; got != tc.blocked {
				t.Fatalf("blocked=%v want %v", got, tc.blocked)
			}
		})
	}
}

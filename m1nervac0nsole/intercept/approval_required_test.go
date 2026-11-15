package intercept_test

import (
	"context"
	"os"
	"strings"
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
	// The tool curator's proposals and its install ask too, and the card names the
	// tool being approved instead of the memory wording.
	for _, tool := range []string{"toolbox_propose_template", "toolbox_propose_tool", "toolbox_install"} {
		dec, ok := ic.Match(tool, []byte(`{}`))
		if !ok || dec.Action != "ask" {
			t.Fatalf("%s produced no approval: ok=%v action=%q", tool, ok, dec.Action)
		}
		if !strings.Contains(dec.Message, tool) || strings.Contains(dec.RuleName, "memory") {
			t.Errorf("%s approval does not name the tool: rule=%q message=%q", tool, dec.RuleName, dec.Message)
		}
	}

	// The guard turns the ask into the normal pending record and blocks the call
	// until a person decides, so a denial leaves the tool unexecuted. The install
	// is a separate card: approving the template must not run its script, and the
	// script does not run until this card is allowed.
	g := guard.NewWithInterceptor(ic)
	for _, tc := range []struct {
		name    string
		tool    string
		input   string
		approve bool
		blocked bool
	}{
		{"memory denied", "memory_propose", memoryProposeInput, false, true},
		{"memory approved", "memory_propose", memoryProposeInput, true, false},
		{"install denied", "toolbox_install", `{"id":"nikto"}`, false, true},
		{"install approved", "toolbox_install", `{"id":"nikto"}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := guardedCall(t, d, ic, g, tc.tool, tc.input, tc.approve); got != tc.blocked {
				t.Fatalf("blocked=%v want %v", got, tc.blocked)
			}
		})
	}
}

// The platform writers change what every later run loads, so an auto-agent call
// must raise the operator card. The saved scope here omits them, which used to
// be enough to let them run unseen.
func TestPlatformWritersAlwaysAskBeforeWriting(t *testing.T) {
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
	if err := ic.SetEnabledTools([]string{"Bash"}); err != nil {
		t.Fatal(err)
	}
	writers := []string{"update_skill_file", "create_custom_tool", "update_custom_tool"}
	clear := func() {
		for _, tool := range writers {
			_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_name=$1`, tool)
		}
	}
	clear()
	t.Cleanup(clear)

	for _, tool := range writers {
		if !ic.IsToolEnabled(tool) {
			t.Errorf("a saved scope without %s turned its approval off", tool)
		}
		dec, ok := ic.Match(tool, []byte(`{}`))
		if !ok || dec.Action != "ask" {
			t.Fatalf("%s produced no approval: ok=%v action=%q", tool, ok, dec.Action)
		}
		if !strings.Contains(dec.Message, tool) {
			t.Errorf("%s approval does not name the tool: %q", tool, dec.Message)
		}
	}

	g := guard.NewWithInterceptor(ic)
	for _, tool := range writers {
		t.Run(tool+" denied", func(t *testing.T) {
			if !guardedCall(t, d, ic, g, tool, `{}`, false) {
				t.Fatal("a denied platform write was not blocked")
			}
		})
		t.Run(tool+" approved", func(t *testing.T) {
			if guardedCall(t, d, ic, g, tool, `{}`, true) {
				t.Fatal("an approved platform write was still blocked")
			}
		})
	}
}

// guardedCall runs one tool call through the guard's pre-tool hook, decides the
// approval card it raises, and reports whether the call was blocked.
func guardedCall(t *testing.T, d *db.DB, ic *intercept.Interceptor, g *guard.Guard, tool, input string, approve bool) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	blocked := make(chan bool, 1)
	go func() {
		b, _, _ := g.Hooks().PreToolUse(ctx, tool, []byte(input))
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
			if row.ToolName == tool {
				id = row.ID
			}
		}
		if id == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	if id == 0 {
		t.Fatal("no approval card was raised")
	}
	if err := ic.Decide(id, approve); err != nil {
		t.Fatal(err)
	}
	return <-blocked
}

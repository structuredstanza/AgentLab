package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

// run_tool's description promises it "refuses an out-of-scope target". Nothing
// implemented that: the guard's text scan reads the raw tool-call arguments,
// which is a different question from whether the named host is excluded. This
// asserts the handler itself refuses, before the tool starts.
func TestRunToolRefusesExcludedTarget(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	task, err := pg.CreateTask("scope gate", "verify run_tool refuses excluded hosts", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	apex := fmt.Sprintf("blocked-%d.invalid", task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "root_domain", apex, "operator excluded it", "manual", "exclude"); err != nil {
		t.Fatalf("record exclusion: %v", err)
	}

	s := &Server{m: &Manager{pg: pg, assets: pg.Assets()}}
	tool := s.toolRunManifest()

	call := func(target string) string {
		ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
		raw, _ := json.Marshal(map[string]any{"tool": "nmap", "target": target})
		res, err := tool.Call(ctx, raw, &actool.ToolContext{})
		if err != nil {
			t.Fatalf("call returned error: %v", err)
		}
		return resultText(res)
	}

	// A covered host is refused, and the message names the boundary.
	got := call("api." + apex)
	if !strings.Contains(got, "out of scope") {
		t.Errorf("an excluded host was not refused; result was %q", got)
	}
	if !strings.Contains(got, apex) {
		t.Errorf("the refusal does not name the excluded host; result was %q", got)
	}

	// A host outside the boundary is not refused for scope reasons. It may still
	// fail for an unrelated cause (nmap absent in the test environment), so only
	// the scope refusal is asserted absent.
	if got := call("allowed-" + apex); strings.Contains(got, "out of scope") {
		t.Errorf("a host outside the boundary was refused: %q", got)
	}
}

// resultText flattens a tool result to its text for assertions.
func resultText(res actool.Result) string {
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/limits"
)

// list_tools is where an agent looks before running anything, so the engagement's
// rate guidance has to appear there. It is emitted per call rather than stored in
// the tool description, because descriptions are persisted and UI-editable: a
// rebuilt binary would otherwise keep serving the text it seeded on first run.
func TestListToolsStatesTheRateGuidance(t *testing.T) {
	s := &Server{}
	result, err := s.toolListManifests().Call(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := ""
	for _, block := range result.Content {
		out += block.Text
	}
	if !strings.Contains(out, "Standard: tool defaults") {
		t.Fatalf("list_tools output carries no standard guidance:\n%s", out)
	}
	if !strings.Contains(out, "Operator instructions (guidance, not enforced limits)") {
		t.Fatalf("guidance misrepresents the operator's instructions:\n%s", out)
	}
}

func TestListToolsReadsCurrentTaskProfile(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("speed guidance", "verify operator profile", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	s := &Server{m: &Manager{pg: pg, assets: pg.Assets()}}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	for _, profile := range []string{"stealth", "careful", "standard", "unbound"} {
		if _, err := pg.UpdateTask(task.ID, db.TaskPatch{SpeedProfile: &profile}); err != nil {
			t.Fatal(err)
		}
		result, err := s.toolListManifests().Call(ctx, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(result.Flatten(), limits.GuidanceFor(profile)) {
			t.Fatalf("list_tools omitted current %s instructions: %s", profile, result.Flatten())
		}
	}
}

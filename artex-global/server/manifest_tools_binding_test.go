package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/agent"
	"github.com/structuredstanza/AgentLab/artex-global/db"
	actool "github.com/structuredstanza/norma/tool"
)

// stubTool builds a CoreTool with a chosen name, so the resolver can match it
// against a catalog row without constructing the real handler.
func stubTool(name string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: name + " (test stub)",
		Schema:      map[string]any{"type": "object"},
	})
}

// A worker must be able to call run_tool.
//
// run_tool was seeded with a single "auto" binding, and ToolResolve drops any
// catalog tool whose agents list omits the running agent. So a worker's only
// execution path was Bash — while run_tool's own description and the
// recon-orchestration skill told it to prefer run_tool over Bash. The model was
// being instructed to use a tool absent from its schema, which is why it fell
// back to hand-built Bash command lines.
func TestManifestToolsReachWorkerAndPlanner(t *testing.T) {
	// 1. The binding the seeder writes.
	for _, key := range []string{"run_tool", "list_tools"} {
		b := manifestToolAgents(key)
		if b == nil {
			t.Fatalf("%s has no explicit binding; it would fall back to auto-only", key)
		}
		var got []string
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s binding unreadable: %v", key, err)
		}
		for _, want := range []string{"auto", "worker", "planner"} {
			if !contains(got, want) {
				t.Errorf("%s not bound to %q (got %v)", key, want, got)
			}
		}
	}
	// Every other platform tool keeps the auto-only default.
	if b := manifestToolAgents("create_skill"); b != nil {
		t.Errorf("create_skill should keep the auto-only default, got %s", b)
	}

	// 2. The binding survives the per-agent filter.
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	wireTools(pg, nil)
	t.Cleanup(func() { agent.ToolResolve = nil })
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")

	for _, key := range []string{"run_tool", "list_tools"} {
		if err := pg.SeedTool(key, key+" description", json.RawMessage(`{"type":"object"}`), manifestToolAgents(key)); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}

	ts := agent.NewToolSet(nil, "")
	ctx := context.Background()

	workerBase := append(ts.WorkerTools(), actool.DefaultTools()...)
	plannerBase := append(ts.PlannerTools(), actool.DefaultTools()...)
	for _, key := range []string{"run_tool", "list_tools"} {
		workerBase = append(workerBase, stubTool(key))
		plannerBase = append(plannerBase, stubTool(key))
	}

	worker := names(agent.ToolResolve(ctx, "worker", workerBase))
	for _, key := range []string{"run_tool", "list_tools"} {
		if _, ok := worker[key]; !ok {
			t.Errorf("worker cannot call %s — it would fall back to Bash for every declared tool", key)
		}
	}

	planner := names(agent.ToolResolve(ctx, "planner", plannerBase))
	for _, key := range []string{"run_tool", "list_tools"} {
		if _, ok := planner[key]; !ok {
			t.Errorf("planner cannot see %s — an intent cannot name a manifest id", key)
		}
	}
}

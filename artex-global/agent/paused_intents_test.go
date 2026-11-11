package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/norma/llm"
)

// pausedExploration seeds one intent parked on the operator and returns the
// store, so both the overview and the planner round see the same shape.
func pausedExploration(t *testing.T) *db.ExplorationStore {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	expID, err := d.CreateExploration("paused intent visibility", "keep a paused intent visible")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	ts := d.Exploration(expID)
	if _, err := ts.AddNode(db.KindIntent, map[string]any{"summary": "ask the operator for the VPN credential"}, 5, "paused", "planner", nil); err != nil {
		t.Fatal(err)
	}
	return ts
}

// A paused intent waits on a human, so it is in play. The open/running/finished
// lists cannot show it; without paused_intents the planner reads a live
// engagement as a stalled frontier and dispatches more work against the block.
func TestGraphOverviewShowsPausedIntents(t *testing.T) {
	ts := pausedExploration(t)
	overview := NewToolSet(ts, "planner").graphOverviewData()

	list, ok := overview["paused_intents"].([]map[string]any)
	if !ok || len(list) != 1 {
		t.Fatalf("paused_intents = %#v, want the one paused intent", overview["paused_intents"])
	}
	if list[0]["state"] != "paused" || list[0]["summary"] != "ask the operator for the VPN credential" {
		t.Fatalf("paused entry lost its shape: %#v", list[0])
	}
	if id, _ := list[0]["id"].(int64); id <= 0 {
		t.Fatalf("paused entry has no id: %#v", list[0])
	}
	if running, _ := overview["running_intents"].([]map[string]any); len(running) != 0 {
		t.Fatalf("paused intent leaked into running_intents: %#v", running)
	}
}

// The planner round used to append a count-only sentence for paused intents.
// The overview now carries them, so the input names them as data and no longer
// grows a duplicate lead sentence.
func TestPlannerInputNamesPausedIntentsWithoutLeadSentence(t *testing.T) {
	ts := pausedExploration(t)
	provider := &recordingProvider{script: func(_ int, yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "done"}, nil)
		yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}}
	planner := NewPlanner(provider, "test-model", t.TempDir(), nil, 0, 2)
	if _, _, err := planner.Plan(context.Background(), 987654321, nil, ts, "paused wiring", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(provider.reqs) == 0 || len(provider.reqs[0].Messages) == 0 {
		t.Fatal("planner round captured no prompt")
	}
	input := provider.reqs[0].Messages[len(provider.reqs[0].Messages)-1].Text()
	if !strings.Contains(input, `"paused_intents"`) {
		t.Errorf("planner input does not carry the paused intent: %q", input)
	}
	if strings.Contains(input, "are paused waiting on the operator") {
		t.Errorf("planner input still appends the redundant paused sentence: %q", input)
	}
}

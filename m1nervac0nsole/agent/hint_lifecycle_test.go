package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// hintTestStore creates a throwaway exploration so hint lifecycle tests never
// touch a real task's graph.
func hintTestStore(t *testing.T) *db.ExplorationStore {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	expID, err := d.CreateExploration(fmt.Sprintf("hint lifecycle %d", time.Now().UnixNano()), "retire superseded hints")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	return d.Exploration(expID)
}

// addHints calls the add_hint tool in batch mode and returns the created ids.
func addHints(t *testing.T, tools *ToolSet, payload string) []int64 {
	t.Helper()
	res, err := tools.addHint().Call(context.Background(), json.RawMessage(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("add_hint: %s", res.Flatten())
	}
	var out struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("add_hint result %q: %v", res.Flatten(), err)
	}
	return out.IDs
}

// overviewHintIDs calls graph_overview and returns the ids it feeds the planner.
func overviewHintIDs(t *testing.T, tools *ToolSet) []int64 {
	t.Helper()
	res, err := tools.graphOverview().Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("graph_overview: %s", res.Flatten())
	}
	var out struct {
		Hints []struct {
			ID int64 `json:"id"`
		} `json:"hints"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("graph_overview result %q: %v", res.Flatten(), err)
	}
	ids := make([]int64, 0, len(out.Hints))
	for _, h := range out.Hints {
		ids = append(ids, h.ID)
	}
	return ids
}

// A hint that supersedes an older one must retire it: the old text stops being
// fed to the planner (which otherwise keeps obeying the rule that was replaced).
func TestAddHintSupersedesConsumesAndHidesHint(t *testing.T) {
	ts := hintTestStore(t)
	tools := NewToolSet(ts, "planner")

	oldIDs := addHints(t, tools, `{"hints":[{"text":"use /ask for privilege escalation"}]}`)
	if len(oldIDs) != 1 || oldIDs[0] <= 0 {
		t.Fatalf("add_hint ids = %v", oldIDs)
	}
	newIDs := addHints(t, tools, fmt.Sprintf(`{"hints":[{"text":"never use /ask for privilege escalation","supersedes":[%d]}]}`, oldIDs[0]))
	if len(newIDs) != 1 || newIDs[0] <= 0 {
		t.Fatalf("add_hint ids = %v", newIDs)
	}

	old, err := ts.GetNode(oldIDs[0])
	if err != nil || old == nil {
		t.Fatalf("read superseded hint: node=%v err=%v", old, err)
	}
	if old.State != "consumed" {
		t.Fatalf("superseded hint state = %q, want consumed", old.State)
	}

	if got := overviewHintIDs(t, tools); len(got) != 1 || got[0] != newIDs[0] {
		t.Fatalf("overview hints = %v, want only hint %d", got, newIDs[0])
	}
}

// An invalid supersedes id is a per-item error and must not leave a half-created
// hint behind.
func TestAddHintRejectsUnknownSupersedesWithoutCreating(t *testing.T) {
	ts := hintTestStore(t)
	tools := NewToolSet(ts, "planner")

	res, err := tools.addHint().Call(context.Background(), json.RawMessage(`{"text":"orphan","supersedes":[424242]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("expected an error for an unknown supersedes id, got %q", res.Flatten())
	}
	hints, err := ts.ListByKind(db.KindHint, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 0 {
		t.Fatalf("hints created = %d, want 0 after a rejected supersedes id", len(hints))
	}
}

// A bounded overview must not lose an active hint behind newer consumed ones:
// the state filter belongs in the query, not after the page is cut.
func TestGraphOverviewKeepsActiveHintsBehindConsumedOnes(t *testing.T) {
	ts := hintTestStore(t)
	tools := NewToolSet(ts, "planner")
	activeID, err := ts.AddNode(db.KindHint, map[string]any{"text": "standing guidance"}, 0, "active", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 60 {
		if _, err := ts.AddNode(db.KindHint, map[string]any{"text": fmt.Sprintf("retired %d", i)}, 0, "consumed", "human", nil); err != nil {
			t.Fatal(err)
		}
	}
	got := overviewHintIDs(t, tools)
	if len(got) != 1 || got[0] != activeID {
		t.Fatalf("overview hints = %v, want the active hint %d", got, activeID)
	}
}

// The completion gate must refuse to close a task while an intent is paused: the
// planner has to resume it or kill_work it (with a reason) first. The refusal
// must not persist the goal change, so the planner can retry after clearing it.
func TestProveGoalRefusesCompletionWhileIntentPaused(t *testing.T) {
	ts := hintTestStore(t)
	tools := NewToolSet(ts, "planner")
	goalID, err := ts.AddGoal(map[string]any{"text": "finish the audit"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	evidenceID, err := ts.AddNode(db.KindFact, map[string]any{"summary": "audit complete"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	pausedID, err := ts.AddNode(db.KindIntent, map[string]any{"summary": "waiting on the operator"}, 5, "paused", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	input := json.RawMessage(fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d}`, goalID, evidenceID))
	res, err := tools.proveGoal().Call(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tools.GoalMet {
		t.Fatal("task auto-completed while an intent was still paused")
	}
	if !strings.Contains(res.Flatten(), strconv.FormatInt(pausedID, 10)) {
		t.Fatalf("refusal does not name the blocking intent %d: %s", pausedID, res.Flatten())
	}
	goal, err := ts.GetNode(goalID)
	if err != nil || goal == nil {
		t.Fatalf("read goal after refusal: node=%v err=%v", goal, err)
	}
	if goal.State != "open" {
		t.Fatalf("refused prove_goal persisted goal state %q, want open", goal.State)
	}

	if err := ts.SetNodeState(pausedID, "stopped"); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.proveGoal().Call(context.Background(), input, nil); err != nil {
		t.Fatal(err)
	}
	if !tools.GoalMet {
		t.Fatal("task did not complete after the paused intent was cleared")
	}
}

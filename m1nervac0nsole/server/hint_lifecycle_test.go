package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/norma/llm"
)

// newHintTestServer builds a DB-backed server with one task for the hint and
// work-control lifecycle tests.
func newHintTestServer(t *testing.T) (*Manager, *Server, *Task) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m, engine: NewEngine(m), ctx: context.Background()}
	s.engine.SetIntentCancel(func(ctx context.Context, t *Task, intentID int64, reason string) error {
		_, err := s.applyIntentControl(ctx, t, intentID, "cancel", reason, "")
		return err
	})
	task, err := m.CreateTask("hint lifecycle", "exercise the hint and work lifecycle", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	return m, s, task
}

// kill_work must be able to retract an intent that is not running: it falls
// through to the operator cancel path and records the reason for the audit.
func TestKillWorkCancelsIntentWithoutRunningWork(t *testing.T) {
	_, s, task := newHintTestServer(t)
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "queued direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	const reason = "a new hint forbids this approach"
	if err := s.engine.KillWork(context.Background(), taskID, intentID, reason); err != nil {
		t.Fatal(err)
	}
	node, err := task.Store.GetNode(intentID)
	if err != nil || node == nil {
		t.Fatalf("read cancelled intent: node=%v err=%v", node, err)
	}
	if node.State != db.StateIntentDeleted {
		t.Fatalf("intent state = %q, want %q", node.State, db.StateIntentDeleted)
	}
	if node.DeleteReason != reason {
		t.Fatalf("delete reason = %q, want %q", node.DeleteReason, reason)
	}

	if err := s.engine.KillWork(context.Background(), taskID, 987654321, "unknown"); err == nil {
		t.Fatal("kill_work on an unknown intent must still error")
	}
}

// A running intent is marked stopped rather than deleted, so the reason has no
// delete_reason column to land in: it must reach the intent's activity trail.
func TestKillWorkRecordsReasonOnRunningWork(t *testing.T) {
	_, s, task := newHintTestServer(t)
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "running direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	s.engine.registerWork(intentID, func(error) { cancelled = true })

	const reason = "the direction drifted off scope"
	if err := s.engine.KillWork(context.Background(), taskID, intentID, reason); err != nil {
		t.Fatal(err)
	}
	if !cancelled {
		t.Fatal("kill_work did not cancel the running work")
	}
	acts, _, err := task.Store.ActivityPage(db.ActivitySessionFilter{NodeID: &intentID}, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range acts {
		if strings.Contains(a.Summary, reason) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("kill reason %q is not on the intent's activity trail: %+v", reason, acts)
	}
}

// A worker can claim the intent after the cancel path read its state and before
// it deleted the node. The path then skips ControlWork; KillWork's post-delete
// re-check must cancel the run that appeared.
func TestKillWorkCancelsWorkClaimedDuringCancelPath(t *testing.T) {
	_, s, task := newHintTestServer(t)
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "queued direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	s.engine.SetIntentCancel(func(_ context.Context, _ *Task, iid int64, _ string) error {
		// Simulate the claim landing between the cancel path's state snapshot
		// and its delete: the path saw "not running" and skipped ControlWork.
		s.engine.registerWork(iid, func(error) { cancelled = true })
		return nil
	})
	if err := s.engine.KillWork(context.Background(), taskID, intentID, "retracted"); err != nil {
		t.Fatal(err)
	}
	if !cancelled {
		t.Fatal("a work claimed during the cancel path was left running on a deleted intent")
	}
}

// The churn trigger must reach the planner's next round exactly once per asset,
// and only once the asset has churnExhaustedThreshold exhausted intents. This
// drives the engine's terminal-intent path, so removing the notifyChurn wiring
// in runIntent fails it.
func TestChurnTriggerReachesPlannerOncePerAsset(t *testing.T) {
	m, s, task := newHintTestServer(t)
	nano := time.Now().UnixNano()
	ip := fmt.Sprintf("10.%d.%d.%d", byte(nano>>16), byte(nano>>8), byte(nano))
	assetID, err := m.assets.UpsertIP(db.UpsertIPReq{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })

	// MaxTurns=1 makes the first model call a tool turn and the settlement call
	// the closing text turn, so each run ends exhausted without a live model.
	calls := 0
	prov := retestProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		if calls%2 == 1 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
				Type: llm.BlockToolUse, ID: "churn-call", Name: "list_findings", Input: json.RawMessage(`{}`),
			}}}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("wrapped up")}}, "end_turn", llm.Usage{}, nil
	}}
	worker := agent.NewWorker(prov, "churn-test", m.dir, nil, 10000, 1)
	worker.SetNonStreaming(func() bool { return true })

	exhausted := func(summary string) int64 {
		iid, err := task.Store.AddIntent(map[string]any{"summary": summary, "asset_ids": []int64{assetID}}, 1, []int64{assetID}, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := task.Store.SetNodeState(iid, "exhausted"); err != nil {
			t.Fatal(err)
		}
		return iid
	}
	exhausted("variant 1")
	exhausted("variant 2")

	runExhausted := func(summary string) {
		t.Helper()
		iid, err := task.Store.AddIntent(map[string]any{"summary": summary, "asset_ids": []int64{assetID}}, 1, []int64{assetID}, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := task.Store.SetNodeState(iid, "running"); err != nil {
			t.Fatal(err)
		}
		node, err := task.Store.GetNode(iid)
		if err != nil || node == nil {
			t.Fatalf("read intent %d: node=%v err=%v", iid, node, err)
		}
		if ok := s.engine.runIntent(context.Background(), task, "churn-test", worker, node, "", ""); !ok {
			t.Fatal("runIntent did not settle the claimed intent")
		}
		if node, err := task.Store.GetNode(iid); err != nil || node == nil || node.State != "exhausted" {
			t.Fatalf("intent %d state = %v (err %v), want exhausted", iid, node, err)
		}
	}
	runExhausted("variant 3")

	var churn []agent.TriggerEvent
	for _, ev := range task.drainTriggers() {
		if ev.Kind == "churn" {
			churn = append(churn, ev)
		}
	}
	if len(churn) != 1 || churn[0].AssetID != assetID || churn[0].Count != churnExhaustedThreshold {
		t.Fatalf("churn triggers = %+v, want exactly one for asset %d at count %d", churn, assetID, churnExhaustedThreshold)
	}

	// A fourth exhausted intent must not re-fire the one-shot trigger.
	runExhausted("variant 4")
	for _, ev := range task.drainTriggers() {
		if ev.Kind == "churn" {
			t.Fatalf("churn re-fired for asset %d: %+v", assetID, ev)
		}
	}
}

// setHintState closes or reopens one hint of the task named in the path.
func TestSetHintStateHandler(t *testing.T) {
	_, s, task := newHintTestServer(t)
	other, err := s.m.CreateTask("other task", "unrelated scope", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(other.ID, DeleteTaskOptions{}) })
	hintID, err := task.Store.AddNode(db.KindHint, map[string]any{"text": "retire me"}, 0, "active", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	foreignID, err := other.Store.AddNode(db.KindHint, map[string]any{"text": "other task's hint"}, 0, "active", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	call := func(taskID, hid, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/hints/"+hid+"/state", strings.NewReader(body))
		req.SetPathValue("id", taskID)
		req.SetPathValue("hid", hid)
		rec := httptest.NewRecorder()
		s.setHintState(rec, req)
		return rec
	}

	rec := call(task.ID, strconv.FormatInt(hintID, 10), `{"state":"consumed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid transition status=%d body=%s", rec.Code, rec.Body.String())
	}
	if node, err := task.Store.GetNode(hintID); err != nil || node == nil || node.State != "consumed" {
		t.Fatalf("hint state after transition = %v (err %v), want consumed", node, err)
	}

	if rec := call(task.ID, strconv.FormatInt(hintID, 10), `{"state":"bogus"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad state status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call(task.ID, "987654321", `{"state":"consumed"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown hint status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call(task.ID, strconv.FormatInt(foreignID, 10), `{"state":"consumed"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("another task's hint status=%d body=%s", rec.Code, rec.Body.String())
	}
	if node, err := other.Store.GetNode(foreignID); err != nil || node == nil || node.State != "active" {
		t.Fatalf("another task's hint was changed: %v (err %v)", node, err)
	}
}

// Active hints are retired when the task finishes successfully. A failed or
// timed-out task can be revived, so its standing guidance must survive.
func TestActiveHintsConsumedOnlyOnDone(t *testing.T) {
	m, _, task := newHintTestServer(t)
	hintID, err := task.Store.AddNode(db.KindHint, map[string]any{"text": "keep this guidance"}, 0, "active", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskStatus(task.ID, "failed"); err != nil {
		t.Fatal(err)
	}
	if node, err := task.Store.GetNode(hintID); err != nil || node == nil || node.State != "active" {
		t.Fatalf("hint after a failed status = %v (err %v), want active", node, err)
	}
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if node, err := task.Store.GetNode(hintID); err != nil || node == nil || node.State != "consumed" {
		t.Fatalf("hint after done = %v (err %v), want consumed", node, err)
	}

	// The guarded terminal path (planner/goalless completion) follows the same
	// rule for both a failed and a done status.
	for _, tc := range []struct {
		status string
		want   string
	}{
		{"failed", "active"},
		{"done", "consumed"},
	} {
		guarded, err := m.CreateTask("guarded "+tc.status, "finish", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = m.DeleteTask(guarded.ID, DeleteTaskOptions{}) })
		gHint, err := guarded.Store.AddNode(db.KindHint, map[string]any{"text": "guarded guidance"}, 0, "active", "human", nil)
		if err != nil {
			t.Fatal(err)
		}
		won, err := m.SetTaskStatusGuarded(guarded.ID, tc.status)
		if err != nil || !won {
			t.Fatalf("guarded %s: won=%v err=%v", tc.status, won, err)
		}
		if node, err := guarded.Store.GetNode(gHint); err != nil || node == nil || node.State != tc.want {
			t.Fatalf("hint after guarded %s = %v (err %v), want %s", tc.status, node, err, tc.want)
		}
	}
}

// A quiet planning round discards its triggers, but the churn trigger's
// one-shot claim is already spent, so it must survive until a real round.
func TestQuietDrainKeepsChurnTrigger(t *testing.T) {
	task := &Task{notify: make(chan struct{}, 1)}
	if !task.markChurnFired(7) {
		t.Fatal("first churn claim for an asset was refused")
	}
	task.NotifyChurn(7, 3)
	task.NotifyDone(11)
	task.discardTriggersExceptChurn()
	evs := task.drainTriggers()
	if len(evs) != 1 || evs[0].Kind != "churn" || evs[0].AssetID != 7 || evs[0].Count != 3 {
		t.Fatalf("triggers after a quiet drain = %+v, want the churn trigger alone", evs)
	}
}

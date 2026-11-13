package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Pausing an intent is a live signal, not a quiet stop: the planner must be woken
// immediately (with this intent id) and the intent's end-of-batch reflections must
// still be derived, or the next round sees a drained frontier and dispatches more
// work against the same block.
func TestPauseIntentWakesPlannerAndDerivesReflections(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("pause signal", "the target went dark", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	intentID, err := task.Store.AddIntent(map[string]any{"summary": "check whether the target is up"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := transitionIntentState(task.Store, intentID, "open", "running"); err != nil {
		t.Fatal(err)
	}
	// Eight tool calls with no fact and no finding: the derive has a signal to record.
	for range 8 {
		node := intentID
		if _, err := task.Store.AppendActivity(db.Activity{
			NodeID: &node, Kind: "tool_use", Tool: "Bash", Summary: "curl -sS https://absent.example",
		}); err != nil {
			t.Fatal(err)
		}
	}

	e := NewEngine(m)
	if err := e.pauseIntent(task, intentID); err != nil {
		t.Fatal(err)
	}

	node, err := task.Store.GetNode(intentID)
	if err != nil || node == nil {
		t.Fatalf("reload intent: node=%v err=%v", node, err)
	}
	if node.State != "paused" {
		t.Fatalf("intent state = %q, want paused", node.State)
	}
	select {
	case <-task.notify:
	default:
		t.Fatal("pausing did not wake the planner")
	}
	triggers := task.drainTriggers()
	if len(triggers) != 1 || triggers[0].Kind != "done" || triggers[0].IntentID != intentID {
		t.Fatalf("planner triggers = %+v, want one done trigger for intent %d", triggers, intentID)
	}
	key := "intent:" + strconv.FormatInt(intentID, 10) + ":no-yield"
	reflections, err := m.PG().ListReflections(context.Background(), taskID, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reflections {
		if r.DedupeKey == key {
			return
		}
	}
	t.Fatalf("reflection %q missing after pause (%d reflections recorded)", key, len(reflections))
}

// report_blocked must park the whole task, not just one intent: needs_operator
// with the reason, loops stopped, the reason visible to the UI, and a resume that
// lifts the block so planning can continue.
func TestReportBlockedParksTaskAndResumeClearsIt(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task, err := m.CreateTask("blocked engagement", "confirm the target is reachable", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid := mustTaskID(t, task.ID)
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	if err := m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}

	const (
		reason = "the target moved to an unknown address and every probe times out"
		action = "curl -sS -m 5 https://target.example/ and paste the status line"
	)
	execCtx := s.engine.execContextFor(context.Background(), task.ID)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: tid, ExplorationID: task.ExpID})
	input, err := json.Marshal(map[string]string{"reason": reason, "operator_action": action})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.toolReportBlocked().Call(ctx, input, nil); err != nil {
		t.Fatal(err)
	}

	stored, err := m.PG().GetTask(tid)
	if err != nil || stored == nil {
		t.Fatalf("reload task: task=%v err=%v", stored, err)
	}
	if stored.Status != db.StatusNeedsOperator {
		t.Fatalf("task status = %q, want %q", stored.Status, db.StatusNeedsOperator)
	}
	if stored.BlockedReason != reason {
		t.Fatalf("blocked_reason = %q, want %q", stored.BlockedReason, reason)
	}
	if !s.engine.IsPaused(task.ID) {
		t.Fatal("report_blocked did not stop the task loops")
	}
	if code, _, _, ok := agent.AbortReason(execCtx); !ok || code != "blocked_on_operator" {
		t.Fatalf("cancellation code=%q ok=%v, want blocked_on_operator", code, ok)
	}
	if got := s.resolvedTaskStatus(task); got != db.StatusNeedsOperator {
		t.Fatalf("resolved status = %q, want %q (the block must outrank the pause)", got, db.StatusNeedsOperator)
	}
	// The operator handoff must also reach the activity feed.
	feed, _, err := task.Store.ActivityList(nil, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	announced := false
	for _, a := range feed {
		if a.Worker == "planner" && strings.Contains(a.Summary, reason) && strings.Contains(a.Summary, action) {
			announced = true
			break
		}
	}
	if !announced {
		t.Fatalf("no activity row announced the block (%d rows)", len(feed))
	}

	// The task API carries both names the frontend renders.
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/tasks/"+task.ID, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("get task: %d (%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != db.StatusNeedsOperator {
		t.Fatalf("task JSON status = %v, want %q", out["status"], db.StatusNeedsOperator)
	}
	if out["blocked_reason"] != reason {
		t.Fatalf("task JSON blocked_reason = %v, want %q", out["blocked_reason"], reason)
	}

	if _, err := s.applyTaskControl(task, "resume"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	stored, err = m.PG().GetTask(tid)
	if err != nil || stored == nil {
		t.Fatalf("reload resumed task: task=%v err=%v", stored, err)
	}
	if stored.Status != "running" {
		t.Fatalf("status after resume = %q, want running", stored.Status)
	}
	if stored.BlockedReason != "" {
		t.Fatalf("blocked_reason after resume = %q, want empty", stored.BlockedReason)
	}
	if s.engine.IsPaused(task.ID) {
		t.Fatal("resume left the task paused")
	}
}

// Quiet-mode must not swallow the pause wake: with the goal set unchanged and only
// a paused intent, the round is not redundant (the graph changed and a human is
// being asked), so it must run. With real work in flight it stays skipped.
func TestQuietModeDoesNotSwallowPauseWake(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	e := NewEngine(m)
	task, err := m.CreateTask("quiet pause", "the target went dark", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "ask the operator whether the host moved"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := transitionIntentState(task.Store, intentID, "open", "running"); err != nil {
		t.Fatal(err)
	}
	if err := transitionIntentState(task.Store, intentID, "running", "paused"); err != nil {
		t.Fatal(err)
	}
	fp, err := task.Store.OpenGoalFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	e.goalFP.Store(task.ID, fp)
	if e.quietSkipEdge(task) {
		t.Fatal("quiet mode skipped the round even though an intent is waiting on the operator")
	}
	if err := transitionIntentState(task.Store, intentID, "paused", "running"); err != nil {
		t.Fatal(err)
	}
	if !e.quietSkipEdge(task) {
		t.Fatal("quiet mode should skip an edge round while work is in flight and the goal set is unchanged")
	}
}

// The opening planner round is kicked only when nothing is in play: a seeded
// intent already claimed by a worker (open->running) must not trigger a redundant
// round, and a paused intent waiting on a human is not a stalled frontier either.
func TestFirstRoundOnlyKicksWithoutActiveIntent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	e := NewEngine(m)

	seeded, err := m.CreateTask("seeded", "one intent already claimed", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(seeded.ID, DeleteTaskOptions{}) })
	intentID, err := seeded.Store.AddIntent(map[string]any{"summary": "the seeded direction"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := transitionIntentState(seeded.Store, intentID, "open", "running"); err != nil {
		t.Fatal(err)
	}
	e.kickFirstRound(seeded)
	select {
	case <-seeded.notify:
		t.Fatal("a seeded, already-claimed task kicked a redundant first planning round")
	default:
	}

	if err := seeded.Store.SetIntentState(intentID, "paused"); err != nil {
		t.Fatal(err)
	}
	e.kickFirstRound(seeded)
	select {
	case <-seeded.notify:
		t.Fatal("a task waiting on the operator kicked a planning round")
	default:
	}

	fresh, err := m.CreateTask("fresh", "nothing queued", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(fresh.ID, DeleteTaskOptions{}) })
	e.kickFirstRound(fresh)
	select {
	case <-fresh.notify:
	default:
		t.Fatal("a task with nothing in play did not kick the first planning round")
	}
}

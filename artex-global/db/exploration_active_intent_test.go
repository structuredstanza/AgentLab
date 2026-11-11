package db

import (
	"testing"
)

// A paused intent is waiting on a human (ask_operator), not a drained frontier.
// HasActiveIntent must keep reporting it: otherwise the planner reads a live
// engagement as stalled, kicks a redundant first round, and dispatches more work
// against the very block it is waiting on.
func TestHasActiveIntentCountsPaused(t *testing.T) {
	d := memoryTestDB(t)
	tk := memoryTask(t, d)
	es := d.Exploration(tk.ExplorationID)

	if active, err := es.HasActiveIntent(); err != nil || active {
		t.Fatalf("empty exploration: active=%v err=%v, want false", active, err)
	}
	intentID, err := es.AddIntent(map[string]any{"summary": "waiting on the operator"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentState(intentID, "paused"); err != nil {
		t.Fatal(err)
	}
	if active, err := es.HasActiveIntent(); err != nil || !active {
		t.Fatalf("paused-only exploration: active=%v err=%v, want true", active, err)
	}
	// Quiet-mode asks a different question: is work actually in flight? A paused
	// intent is in play but not in flight, so a pause wake must not be swallowed.
	if moving, err := es.HasOpenOrRunningIntent(); err != nil || moving {
		t.Fatalf("paused-only exploration: in-flight=%v err=%v, want false", moving, err)
	}
	if n, err := es.CountPausedIntents(); err != nil || n != 1 {
		t.Fatalf("paused count=%d err=%v, want 1", n, err)
	}
	if err := es.SetIntentState(intentID, "stopped"); err != nil {
		t.Fatal(err)
	}
	if active, err := es.HasActiveIntent(); err != nil || active {
		t.Fatalf("stopped intent: active=%v err=%v, want false", active, err)
	}
}

// needs_operator parks a task with its reason and is not terminal, so the
// normal status path can lift it again.
func TestNeedsOperatorStatusIsRecoverable(t *testing.T) {
	d := memoryTestDB(t)
	tk := memoryTask(t, d)

	if IsTerminal(StatusNeedsOperator) {
		t.Fatal("needs_operator must not be terminal: resuming it returns the task to running")
	}
	if err := d.SetNeedsOperator(tk.ID, "the target moved and every probe times out"); err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetTask(tk.ID)
	if err != nil || stored == nil {
		t.Fatalf("reload: task=%v err=%v", stored, err)
	}
	if stored.Status != StatusNeedsOperator || stored.BlockedReason == "" {
		t.Fatalf("status=%q reason=%q, want %q with a reason", stored.Status, stored.BlockedReason, StatusNeedsOperator)
	}
	reasons, err := d.TaskBlockedReasons()
	if err != nil {
		t.Fatal(err)
	}
	if reasons[tk.ID] != stored.BlockedReason {
		t.Fatalf("blocked reason map = %q, want %q", reasons[tk.ID], stored.BlockedReason)
	}
	if err := d.SetStatus(tk.ID, "running"); err != nil {
		t.Fatal(err)
	}
	stored, err = d.GetTask(tk.ID)
	if err != nil || stored == nil {
		t.Fatalf("reload resumed: task=%v err=%v", stored, err)
	}
	if stored.Status != "running" || stored.BlockedReason != "" {
		t.Fatalf("after resume: status=%q reason=%q, want running with no reason", stored.Status, stored.BlockedReason)
	}
	if stored.CompletedAt != nil {
		t.Fatalf("resume left completed_at stamped: %v", stored.CompletedAt)
	}
}

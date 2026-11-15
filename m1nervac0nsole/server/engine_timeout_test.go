package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// timeoutTestEngine builds an engine with no planner and no worker, so a settle
// sequence that does start parks in the final-round wait instead of calling an LLM.
func timeoutTestEngine(m *Manager) *Engine {
	e := NewEngine(m)
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return nil, nil })
	return e
}

// runCoordinator drives the deadline coordinator for the task until the test ends
// and waits for it before the task row is removed.
func runCoordinator(t *testing.T, e *Engine, task *Task) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.deadlineCoordinator(ctx, task)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func timeoutTestTask(t *testing.T, m *Manager, name string, timeoutSeconds int) (*Task, int64) {
	t.Helper()
	task, err := m.CreateTask(name, "verify the task-level timeout clock", nil, timeoutSeconds, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, id) })
	return task, id
}

// Finding 8: a pause freezes the timeout clock, and resume credits the paused
// interval onto deadline_at - the value the coordinator must run on.
func TestPausedTaskDoesNotTimeOutAndResumeUsesCreditedDeadline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, id := timeoutTestTask(t, m, "pause across deadline", 1)
	if _, err := m.StampTaskFirstRun(task.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyTaskPause(task.ID); err != nil {
		t.Fatal(err)
	}
	engine := timeoutTestEngine(m)
	engine.Pause(task.ID, agent.AbortPausedByUser)
	// Let the stamped deadline pass while the task is paused.
	time.Sleep(1500 * time.Millisecond)
	// A long pause: resuming must credit it, moving the deadline into the future.
	if _, err := m.pg.Exec(`UPDATE tasks SET paused_at = now() - interval '1 hour' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}

	runCoordinator(t, engine, task)
	time.Sleep(3 * deadlinePollInterval / 2)
	if engine.isSettling(task.ID) {
		t.Fatal("a paused task entered the timeout wrap-up")
	}
	if got := m.TaskStatus(task.ID); isTerminalStatus(got) {
		t.Fatalf("a paused task was timed out: status=%q", got)
	}

	if err := m.ApplyTaskAdmission(task.ID, "created", "running", false, "resume", false); err != nil {
		t.Fatal(err)
	}
	engine.Resume(task)
	var credited int64
	if err := m.pg.QueryRow(`SELECT extract(epoch from deadline_at)::bigint FROM tasks WHERE id=$1`, id).Scan(&credited); err != nil {
		t.Fatal(err)
	}
	if credited <= time.Now().Unix() {
		t.Fatalf("resume did not credit the paused interval: deadline=%d now=%d", credited, time.Now().Unix())
	}
	// The SQL read rounds a fractional epoch while the handle truncates it.
	if got := engine.taskDeadline(task); got < credited-1 || got > credited+1 {
		t.Fatalf("coordinator deadline = %d, want the credited %d", got, credited)
	}
	time.Sleep(3 * deadlinePollInterval / 2)
	if engine.isSettling(task.ID) {
		t.Fatal("the resumed task was timed out on its pre-pause deadline")
	}
	if got := m.TaskStatus(task.ID); got != "running" {
		t.Fatalf("resumed task status = %q, want running", got)
	}
}

// Finding 13: a task waiting for the operator keeps its status and reason even
// past its deadline; the coordinator must not run a final round or overwrite it.
func TestNeedsOperatorTaskIsNotTimedOut(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, id := timeoutTestTask(t, m, "blocked past deadline", 1)
	if _, err := m.StampTaskFirstRun(task.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // deadline passed
	const reason = "target unreachable: no route to host"
	if err := m.PG().SetNeedsOperator(id, reason); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskStatus(task.ID, db.StatusNeedsOperator); err != nil {
		t.Fatal(err)
	}

	engine := timeoutTestEngine(m)
	runCoordinator(t, engine, task)
	time.Sleep(3 * deadlinePollInterval / 2)
	if engine.isSettling(task.ID) {
		t.Fatal("a needs_operator task entered the timeout wrap-up")
	}
	var status, blocked string
	if err := m.pg.QueryRow(`SELECT status, blocked_reason FROM tasks WHERE id=$1`, id).Scan(&status, &blocked); err != nil {
		t.Fatal(err)
	}
	if status != db.StatusNeedsOperator || blocked != reason {
		t.Fatalf("persisted state = %q/%q, want %q/%q", status, blocked, db.StatusNeedsOperator, reason)
	}
	if got := m.TaskStatus(task.ID); got != db.StatusNeedsOperator {
		t.Fatalf("live status = %q, want %q", got, db.StatusNeedsOperator)
	}
}

// The planner's goal-met verdict must not overwrite a terminal status that
// already won (the timeout coordinator, or a failed run).
func TestGoalMetWriteKeepsWinningTerminalStatus(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, id := timeoutTestTask(t, m, "goal met race", 0)
	if won, err := m.SetTaskStatusGuarded(task.ID, "timeout"); err != nil || !won {
		t.Fatalf("install winning terminal status: won=%v err=%v", won, err)
	}
	engine := NewEngine(m)
	engine.finishGoalMet(task)
	var status string
	if err := m.pg.QueryRow(`SELECT status FROM tasks WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "timeout" {
		t.Fatalf("goal-met write overwrote the winning terminal status: %q", status)
	}
	if got := m.TaskStatus(task.ID); got != "timeout" {
		t.Fatalf("live status = %q, want timeout", got)
	}
}

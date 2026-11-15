package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// A transient database error on a terminal intent-state write must not strand the
// intent in running: the write is retried a bounded number of times.
func TestSetIntentStateRetriesTransientWriteFailure(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("intent write retry", "a transient error must not strand the intent", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "retry me"}, 10, nil, "human")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := task.Store.CompareAndSetIntentState(intentID, "open", "running"); err != nil || !changed {
		t.Fatalf("claim intent: changed=%v err=%v", changed, err)
	}

	previous := intentStateWrite
	t.Cleanup(func() { intentStateWrite = previous })
	e := NewEngine(m)

	t.Run("a transient failure is retried", func(t *testing.T) {
		calls := 0
		intentStateWrite = func(store *db.ExplorationStore, id int64, expected, state string) error {
			calls++
			if calls < intentStateWriteAttempts {
				return errors.New("transient write failure")
			}
			return previous(store, id, expected, state)
		}
		if err := e.setIntentState(task, intentID, "running", "done"); err != nil {
			t.Fatalf("terminal write after transient failures: %v", err)
		}
		if calls != intentStateWriteAttempts {
			t.Fatalf("write attempts = %d, want %d", calls, intentStateWriteAttempts)
		}
		node, err := task.Store.GetNode(intentID)
		if err != nil || node == nil || node.State != "done" {
			t.Fatalf("intent state = %+v err=%v, want done", node, err)
		}
	})

	t.Run("a state conflict is final", func(t *testing.T) {
		calls := 0
		intentStateWrite = func(*db.ExplorationStore, int64, string, string) error {
			calls++
			return fmt.Errorf("%w: intent already moved", db.ErrIntentStateConflict)
		}
		err := e.setIntentState(task, intentID, "running", "stopped")
		if !errors.Is(err, db.ErrIntentStateConflict) {
			t.Fatalf("conflict error = %v, want ErrIntentStateConflict", err)
		}
		if calls != 1 {
			t.Fatalf("a CAS conflict was retried %d times, want 1", calls)
		}
	})
}

package db

import (
	"errors"
	"testing"
	"time"
)

// A write for a task that is paused, finished or gone is refused and fn never
// runs; a live task runs fn.
func TestWithLiveTaskRefusesTasksThatAreNotLive(t *testing.T) {
	d, assets, _ := testSetup(t)
	t.Cleanup(func() { d.Close() })

	newTask := func(t *testing.T) *Task {
		t.Helper()
		task, err := d.CreateTask("live task", "withlivetask", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
		return task
	}
	run := func(task *Task) (ran bool, err error) {
		err = assets.WithLiveTask(task.ID, func(*AssetStore) error { ran = true; return nil })
		return ran, err
	}

	live := newTask(t)
	if ran, err := run(live); err != nil || !ran {
		t.Fatalf("a live task was refused: ran=%v err=%v", ran, err)
	}
	if ok, reason, err := assets.TaskLive(live.ID); err != nil || !ok {
		t.Fatalf("TaskLive(live) = %v %q %v", ok, reason, err)
	}

	for name, stop := range map[string]func(*Task) error{
		"paused":   func(task *Task) error { return d.SetPaused(task.ID, true) },
		"finished": func(task *Task) error { return d.SetStatus(task.ID, "done") },
		"deleted":  func(task *Task) error { return d.DeleteTask(task.ID) },
	} {
		t.Run(name, func(t *testing.T) {
			task := newTask(t)
			if err := stop(task); err != nil {
				t.Fatal(err)
			}
			if ran, err := run(task); !errors.Is(err, ErrTaskNotLive) || ran {
				t.Fatalf("a %s task was not refused: ran=%v err=%v", name, ran, err)
			}
			if ok, _, err := assets.TaskLive(task.ID); err != nil || ok {
				t.Fatalf("TaskLive(%s) = %v err=%v, want not live", name, ok, err)
			}
		})
	}
	if err := assets.WithLiveTask(0, func(*AssetStore) error { return nil }); !errors.Is(err, ErrTaskNotLive) {
		t.Fatalf("task id 0 must be refused, got %v", err)
	}
}

// The check and the write are one transaction: a state change that holds the task
// row makes the writer wait, and the writer then sees the committed state. A
// second, non-transactional check before the write would let this race through.
func TestWithLiveTaskWaitsForAConcurrentTaskChange(t *testing.T) {
	d, assets, _ := testSetup(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("live task race", "withlivetask race", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	blocker, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}

	ran := make(chan bool, 1)
	result := make(chan error, 1)
	go func() {
		result <- assets.WithLiveTask(task.ID, func(*AssetStore) error { ran <- true; return nil })
	}()
	// Observe the actual row-lock wait, rather than assuming a sleep means the
	// writer reached it.
	waiting := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := d.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock'
			  AND query LIKE '%FROM tasks WHERE id=$1 FOR SHARE%'
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("the write did not wait for the task row lock: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !waiting {
		t.Fatal("the enrichment write never reached the task row lock")
	}

	// Waiting for one task must not hold the global asset-write lock.
	const otherURL = "https://unrelated-task-live.invalid/"
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE url=$1 OR domain='unrelated-task-live.invalid'`, otherURL)
	})
	otherWrite := make(chan error, 1)
	go func() {
		_, err := assets.UpsertHTTPService(UpsertHTTPServiceReq{URL: otherURL})
		otherWrite <- err
	}()
	select {
	case err := <-otherWrite:
		if err != nil {
			t.Fatalf("unrelated asset write: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = blocker.Rollback()
		<-otherWrite
		t.Fatal("a task row wait held the global asset-write lock")
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrTaskNotLive) {
			t.Fatalf("after the pause committed, the write = %v, want ErrTaskNotLive", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the write never finished after the task row was released")
	}
	select {
	case <-ran:
		t.Fatal("fn ran for a task that was paused before the write could proceed")
	default:
	}
}

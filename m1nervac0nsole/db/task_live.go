package db

import (
	"database/sql"
	"errors"
	"fmt"
)

// ErrTaskNotLive means a write was refused because its task is missing, deleted,
// archived, paused, queued (not started) or finished.
var ErrTaskNotLive = errors.New("task is not live")

// rowQuerier is the QueryRow half shared by *DB and *sql.Tx.
type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// taskLiveness reads a task's state with the given suffix ("" = plain read,
// " FOR SHARE" = lock it against concurrent deletion/state change). A task with
// no row is not live. A read failure is returned as an error, never as "live".
func taskLiveness(q rowQuerier, taskID int64, lock string) (live bool, reason string, err error) {
	if taskID <= 0 {
		return false, "no task", nil
	}
	var (
		status           string
		paused, queued   bool
		deleted, archive sql.NullTime
	)
	err = q.QueryRow(`SELECT status, paused, queued, deleted_at, archived_at FROM tasks WHERE id=$1`+lock, taskID).
		Scan(&status, &paused, &queued, &deleted, &archive)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, "task no longer exists", nil
	case err != nil:
		return false, "", fmt.Errorf("read task state: %w", err)
	case deleted.Valid || archive.Valid:
		return false, "task was deleted or archived", nil
	case paused:
		return false, "task is paused", nil
	case queued:
		return false, "task has not started (queued)", nil
	case IsTerminal(status):
		return false, "task is finished (" + status + ")", nil
	}
	return true, "", nil
}

// TaskLive reports whether engine-side work may still be done for a task. It is
// the early, cheap refusal used before dispatching a request; it is NOT enough to
// guard a write on its own (the state can change right after it is read) - use
// WithLiveTask for that.
func (s *AssetStore) TaskLive(taskID int64) (live bool, reason string, err error) {
	if s.tx != nil {
		return taskLiveness(s.tx, taskID, "")
	}
	return taskLiveness(s.db, taskID, "")
}

// WithLiveTask runs fn, with a transaction-scoped AssetStore, only if the task is
// live, and holds a row lock on the task (FOR SHARE) until fn's writes commit.
// Task deletion takes the same row FOR UPDATE and then locks the assets table, so
// a deletion that starts first makes this refuse, and a write that starts first
// finishes before the deletion proceeds: no asset can be (re)created for a task
// that was deleted while a slow request was in flight. fn must do its writes
// through the store it is handed. Refusal returns ErrTaskNotLive.
func (s *AssetStore) WithLiveTask(taskID int64, fn func(*AssetStore) error) error {
	scoped := s
	if s.tx == nil {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck
		scoped = &AssetStore{db: s.db, company: s.company, tx: tx}
	}
	// Wait for this task before taking the global asset-write lock; otherwise
	// deleting one task stalls unrelated tasks' asset writes.
	live, reason, err := taskLiveness(scoped.tx, taskID, " FOR SHARE")
	if err != nil {
		return err
	}
	if !live {
		return fmt.Errorf("%w: %s", ErrTaskNotLive, reason)
	}
	if err := lockCompanyScopeMutation(scoped.tx); err != nil {
		return err
	}
	if err := fn(scoped); err != nil {
		return err
	}
	if s.tx == nil {
		return scoped.tx.Commit()
	}
	return nil
}

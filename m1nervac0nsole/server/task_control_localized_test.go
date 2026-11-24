package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestTaskControlApplyResponsesLocalized is a pause control that finishes without going through DB or engine state
// Actually execute the path through applyTaskControl, so that the constant is really carried on the returned error connection
// Confirm it. All three branches go in order: s.m.Task (map lookup) → deletion barrier → t.lifecycleSnapshot() (reads the in-memory
// Reads the Status/Paused fields directly), so with just one task in the tasks map and an empty Engine,
// Runs without the Store or DB. The success path (actual pause) goes through ApplyTaskPause(DB), so
// Does not fall through here — all error branches return before this point.
func TestTaskControlApplyResponsesLocalized(t *testing.T) {
	// Terminal-status task: isTerminalStatus(done) branch.
	terminalServer := func() (*Server, *Task) {
		tk := &Task{ID: "1", Status: "done"}
		return &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}, tk
	}
	// Already-paused running task: lifecycle.Paused branch.
	pausedServer := func() (*Server, *Task) {
		tk := &Task{ID: "1", Status: "running", Paused: true}
		return &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}, tk
	}
	// Task with a deletion barrier in place: IsDeleting branch.
	deletingServer := func() (*Server, *Task) {
		tk := &Task{ID: "1", Status: "running"}
		s := &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}
		s.engine.deleting.Store("1", true)
		return s, tk
	}

	cases := []struct {
		name  string
		setup func() (*Server, *Task)
		want  string
	}{
		{"terminal", terminalServer, errTaskCtrlTerminalPause},
		{"already-paused", pausedServer, errTaskCtrlAlreadyPaused},
		{"deleting", deletingServer, errTaskCtrlDeleting},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, tk := c.setup()
			_, err := s.applyTaskControl(tk, "pause")
			if err == nil {
				t.Fatal("expected an error, but got nil")
			}
			if err.Error() != c.want {
				t.Fatalf("returned error = %q, want %q", err.Error(), c.want)
			}
		})
	}
}

// TestControlTasksBatchResponsesLocalized checks the response body of the batch control endpoint against the actual
// Checks over HTTP. ① An empty task_ids is rejected with writeErr as a 400 with a size error before s.m is accessed
// Also reachable via &Server{}. ② Pausing a single finished-state job in a batch returns 200 with items[].error as
// so the path by which the applyTaskControl error propagates into the batch JSON
// verify this behavior.
func TestControlTasksBatchResponsesLocalized(t *testing.T) {
	t.Run("size-error", func(t *testing.T) {
		s := &Server{}
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/control",
			strings.NewReader(`{"task_ids":[],"action":"pause"}`))
		rec := httptest.NewRecorder()
		s.controlTasksBatch(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status code = %d, want 400 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("item-error-surfaces", func(t *testing.T) {
		tk := &Task{ID: "1", Status: "done"}
		s := &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/control",
			strings.NewReader(`{"task_ids":["1"],"action":"pause"}`))
		rec := httptest.NewRecorder()
		s.controlTasksBatch(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status code = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		var out struct {
			Items []struct {
				ID    string `json:"id"`
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("failed to parse response JSON: %v (body %q)", err, rec.Body.String())
		}
		if len(out.Items) != 1 {
			t.Fatalf("items count = %d, want 1", len(out.Items))
		}
		if out.Items[0].OK || out.Items[0].Error != errTaskCtrlTerminalPause {
			t.Fatalf("items[0] = %+v, want error %q", out.Items[0], errTaskCtrlTerminalPause)
		}
	})
}

// TestIntentStateConflictWrapsSentinel checks that the error wraps the conflict
// sentinel and keeps the paused state in the message.
func TestIntentStateConflictWrapsSentinel(t *testing.T) {
	err := fmt.Errorf(errIntentCtrlStateConflictFmt, db.ErrIntentStateConflict)
	if !errors.Is(err, db.ErrIntentStateConflict) {
		t.Fatalf("errors.Is(.., ErrIntentStateConflict) = false; the %%w wrapping is broken: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "paused") {
		t.Fatalf("the enum value paused was not preserved in the message: %q", err.Error())
	}
}

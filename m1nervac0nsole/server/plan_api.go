package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// planDraftOfTask reports whether the draft named in the path belongs to the
// task in the path, answering the error status otherwise: a draft is scoped to
// the task that commissioned it, so applying or discarding it through a
// different task's route would write into the wrong engagement.
func planDraftOfTask(w http.ResponseWriter, r *http.Request, pg *db.DB, taskID, draftID int64) bool {
	draft, err := pg.GetPlanDraft(r.Context(), draftID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, http.StatusNotFound, "plan draft not found")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	case draft.TaskID != taskID:
		writeErr(w, http.StatusNotFound, "plan draft not found")
	default:
		return true
	}
	return false
}

// planPathIDs parses the task and draft ids of a plan route, answering 400 when
// either is malformed so the caller can return immediately.
func planPathIDs(w http.ResponseWriter, r *http.Request) (taskID, draftID int64, ok bool) {
	taskID, err := parseTaskID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return 0, 0, false
	}
	draftID, err = strconv.ParseInt(r.PathValue("draft"), 10, 64)
	if err != nil || draftID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid plan draft id")
		return 0, 0, false
	}
	return taskID, draftID, true
}

// taskPlans serves GET /api/tasks/{id}/plans. Drafts are per task; an unknown
// task simply has none, so the review screen can render an empty list.
func (s *Server) taskPlans(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, err := parseTaskID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	drafts, err := pg.ListPlanDrafts(r.Context(), taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": drafts})
}

// applyTaskPlan serves POST /api/tasks/{id}/plans/{draft}/apply. An inclusion
// widens the engagement, so the body must carry allow_include; the DB layer
// refuses it otherwise and the refusal is reported as a 400 naming the flag.
func (s *Server) applyTaskPlan(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, draftID, ok := planPathIDs(w, r)
	if !ok {
		return
	}
	var req struct {
		AllowInclude bool `json:"allow_include"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !planDraftOfTask(w, r, pg, taskID, draftID) {
		return
	}
	draft, err := pg.ApplyPlanDraft(r.Context(), draftID, req.AllowInclude)
	switch {
	case errors.Is(err, db.ErrPlanDraftInclude):
		writeErr(w, http.StatusBadRequest, db.ErrPlanDraftInclude.Error())
	case errors.Is(err, db.ErrPlanDraftState):
		writeErr(w, http.StatusConflict, db.ErrPlanDraftState.Error())
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, http.StatusNotFound, "plan draft not found")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		// The applied plan added goals, intents and hints, so nudge an idle
		// running task the way other operator graph writes do.
		if t, ok := s.m.Task(strconv.FormatInt(taskID, 10)); ok {
			t.Notify()
		}
		writeJSON(w, http.StatusOK, map[string]any{"draft": draft})
	}
}

// deleteTaskPlan serves DELETE /api/tasks/{id}/plans/{draft}. Only a pending
// draft can be discarded; an applied one keeps its record because its nodes
// exist and point back at it.
func (s *Server) deleteTaskPlan(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, draftID, ok := planPathIDs(w, r)
	if !ok {
		return
	}
	if !planDraftOfTask(w, r, pg, taskID, draftID) {
		return
	}
	err := pg.DiscardPlanDraft(r.Context(), draftID)
	switch {
	case errors.Is(err, db.ErrPlanDraftState):
		writeErr(w, http.StatusConflict, db.ErrPlanDraftState.Error())
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, http.StatusNotFound, "plan draft not found")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

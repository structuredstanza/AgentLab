package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/structuredstanza/AgentLab/artex-global/db"
)

const (
	maxTaskNameRunes           = 200
	maxTaskMetadataRequestSize = 16 << 10
)

// Error response message that the task metadata modification API returns to the user. JSON field name API
// (name, pinned) are kept verbatim, while only the human-readable message is written in Korean.
const (
	errTaskMetaRequestTooLarge = "The request body is too large"
	errTaskMetaNoFields        = "You must provide either name or pinned"
	errTaskMetaNameEmpty       = "The task name cannot be empty"
	errTaskMetaNameTooLongFmt  = "A task name can be at most %d characters"
)

// updateTaskMetadata changes list-only task metadata. It intentionally does not
// touch lifecycle state, scheduling, or the task's immutable description/goal.
func (s *Server) updateTaskMetadata(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskMetadataRequestSize)
	var request struct {
		Name          *string `json:"name"`
		Pinned        *bool   `json:"pinned"`
		PlanQuietMode *bool   `json:"plan_quiet_mode"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, errTaskMetaRequestTooLarge)
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	if request.Name == nil && request.Pinned == nil && request.PlanQuietMode == nil {
		writeErr(w, http.StatusBadRequest, "at least one of name, pinned or plan_quiet_mode must be provided")
		return
	}
	if request.Name != nil {
		name := strings.TrimSpace(*request.Name)
		if name == "" {
			writeErr(w, http.StatusBadRequest, errTaskMetaNameEmpty)
			return
		}
		if utf8.RuneCountInString(name) > maxTaskNameRunes {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf(errTaskMetaNameTooLongFmt, maxTaskNameRunes))
			return
		}
		request.Name = &name
	}
	task, err := s.m.UpdateTaskMetadata(taskID, db.TaskPatch{Name: request.Name, Pinned: request.Pinned, PlanQuietMode: request.PlanQuietMode})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if task == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	dto := taskDTO(task, s.resolvedTaskStatus(task))
	blockedReasons, _ := s.m.PG().TaskBlockedReasons()
	applyTaskBlockedReason(&dto, blockedReasons)
	writeJSON(w, http.StatusOK, dto)
}

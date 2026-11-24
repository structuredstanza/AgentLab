package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

const (
	maxTaskNameRunes           = 200
	maxTaskMetadataRequestSize = 16 << 10
)

// User-facing error responses from the task metadata API.
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
		SpeedProfile  *string `json:"speed_profile"`
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
	if request.Name == nil && request.Pinned == nil && request.PlanQuietMode == nil && request.SpeedProfile == nil {
		writeErr(w, http.StatusBadRequest, "at least one of name, pinned, plan_quiet_mode or speed_profile must be provided")
		return
	}
	if request.SpeedProfile != nil && !db.ValidSpeedProfile(*request.SpeedProfile) {
		writeErr(w, http.StatusBadRequest, db.ErrTaskSpeedProfileInvalid.Error())
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
	task, err := s.m.UpdateTaskMetadata(taskID, db.TaskPatch{Name: request.Name, Pinned: request.Pinned, PlanQuietMode: request.PlanQuietMode, SpeedProfile: request.SpeedProfile})
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
	s.applyTaskSpeedProfileOne(&dto)
	writeJSON(w, http.StatusOK, dto)
}

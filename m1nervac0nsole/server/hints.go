package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

const (
	hintStateActive   = "active"
	hintStateConsumed = "consumed"
)

// setHintState closes or reopens one hint of a task. The planner only reads
// active hints, so an operator can retire guidance that was superseded or is
// no longer wanted without deleting its node or lineage.
func (s *Server) setHintState(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, http.StatusConflict, "The task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	hid, err := strconv.ParseInt(r.PathValue("hid"), 10, 64)
	if err != nil || hid <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid hint id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var req struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	state := strings.ToLower(strings.TrimSpace(req.State))
	if state != hintStateActive && state != hintStateConsumed {
		writeErr(w, http.StatusBadRequest, "state must be active or consumed")
		return
	}
	node, err := t.Store.GetNode(hid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindHint {
		writeErr(w, http.StatusNotFound, "hint not found")
		return
	}
	if err := t.Store.SetNodeState(hid, state); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	t.Notify()
	writeJSON(w, http.StatusOK, map[string]any{"id": hid, "state": state})
}

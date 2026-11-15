package server

import (
	"errors"
	"net/http"
	"strconv"

	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Scope rules are the operator's explicit layer over the boundary the hunt
// accumulates. They live beside task_scope rows and decide for the hosts they
// match, so "include api.corp.example" is obeyed even when a broad row excludes
// corp.example. The guard reads them through TaskScopeChecker.Judge.

func (s *Server) taskScopeRuleList(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, errAssetStoreDisabled)
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	rules, err := as.ListTaskScopeRuleRows(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}

func (s *Server) taskScopeRuleAdd(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, errAssetStoreDisabled)
		return
	}
	var body struct {
		Effect  string `json:"effect"`
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	id, err := as.AddTaskScopeRule(taskID, body.Effect, body.Pattern, body.Note)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *Server) taskScopeRuleDelete(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, errAssetStoreDisabled)
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	ruleID, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid rule id")
		return
	}
	if err := as.DeleteTaskScopeRule(taskID, ruleID); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) taskScopeRuleUpdate(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, errAssetStoreDisabled)
		return
	}
	var body struct {
		Effect  string `json:"effect"`
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	ruleID, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid rule id")
		return
	}
	if err := as.UpdateTaskScopeRule(taskID, ruleID, body.Effect, body.Pattern, body.Note); err != nil {
		// A missing rule is the only 404 here; a rejected pattern or effect is
		// the caller's mistake, exactly as the add handler answers it.
		if errors.Is(err, pgdb.ErrPolicyRuleNotFound) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

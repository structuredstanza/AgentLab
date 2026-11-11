package server

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/artex-global/db"
)

// Knowledge base and reflection pool, owner side. Mirrors server/lessons.go:
// the agent may only write task-scoped candidates, while promotion to company,
// environment or global scope (and adoption) is an owner action performed here.
// Every rendered or stored string is scrubbed by the store; the redaction count
// is returned so the owner sees what was generalised.
//
// An environment entry describes the platform the agents run on (proxy
// behaviour, network shape, sandbox edges), not a target; it is visible to every
// task and SHOULD be tagged "env:<name>" for the deployment it was seen on.

var (
	knowledgeScopes   = map[string]bool{"global": true, "environment": true, "company": true, "task": true}
	knowledgeKinds    = map[string]bool{"technique": true, "tool": true, "opsec": true, "indicator": true, "playbook": true, "lead": true, "note": true}
	knowledgeStatuses = map[string]bool{"candidate": true, "adopted": true, "retired": true}
	reflectionKinds   = map[string]bool{"opsec": true, "noise": true, "lookfor": true, "learning": true, "mistake": true}
)

// parseIDParam parses an optional positive integer query parameter. ok=false
// means the parameter was present but invalid.
func parseIDParam(raw string) (id int64, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// writeKnowledgeError maps the store's sentinels onto the API contract: a full
// per-task cap is a 409 (the body names the cap), a rejected entry is a 400,
// and a missing row is a 404.
func writeKnowledgeError(w http.ResponseWriter, err error, action string) {
	switch {
	case errors.Is(err, db.ErrMemoryCapReached):
		writeErr(w, 409, db.ErrMemoryCapReached.Error())
	case errors.Is(err, db.ErrMemoryInvalid):
		writeErr(w, 400, err.Error())
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, 404, "knowledge entry not found")
	case isFKViolation(err):
		writeErr(w, 400, "unknown company")
	default:
		log.Printf("[memory] knowledge %s failed: %v", action, err)
		writeErr(w, 500, "knowledge "+action+" failed")
	}
}

// listKnowledge serves GET /api/knowledge. Without task_id it is the owner
// view over every scope; with task_id it is that task's visibility lens, and a
// query switches to ranked full-text search inside the same lens.
func (s *Server) listKnowledge(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := strings.TrimSpace(q.Get("scope"))
	kind := strings.TrimSpace(q.Get("kind"))
	status := strings.TrimSpace(q.Get("status"))
	query := strings.TrimSpace(q.Get("q"))
	if scope != "" && !knowledgeScopes[scope] {
		writeErr(w, 400, "invalid scope")
		return
	}
	if kind != "" && !knowledgeKinds[kind] {
		writeErr(w, 400, "invalid kind")
		return
	}
	if status != "" && !knowledgeStatuses[status] {
		writeErr(w, 400, "invalid status")
		return
	}
	taskID, ok := parseIDParam(q.Get("task_id"))
	if !ok {
		writeErr(w, 400, "invalid task id")
		return
	}
	limit, ok := parseIDParam(q.Get("limit"))
	if !ok {
		writeErr(w, 400, "invalid limit")
		return
	}
	if taskID > 0 {
		task, err := s.m.PG().GetTask(taskID)
		if err != nil {
			log.Printf("[memory] knowledge task lookup failed for %d: %v", taskID, err)
			writeErr(w, 500, "task lookup failed")
			return
		}
		if task == nil {
			writeErr(w, 404, "task not found")
			return
		}
		// A bare query inside a task lens is ranked full-text search; adding a
		// scope/status filter falls through to the filterable list query.
		if query != "" && scope == "" && status == "" {
			var kinds []string
			if kind != "" {
				kinds = []string{kind}
			}
			hits, err := s.m.PG().SearchKnowledge(r.Context(), taskID, query, kinds, int(limit))
			if err != nil {
				writeKnowledgeError(w, err, "search")
				return
			}
			writeJSON(w, 200, map[string]any{"entries": hits, "count": len(hits)})
			return
		}
	}
	entries, err := s.m.PG().ListKnowledge(r.Context(), db.KnowledgeFilter{
		Scope: scope, Kind: kind, Status: status, Query: query, TaskID: taskID, Limit: int(limit),
	})
	if err != nil {
		writeKnowledgeError(w, err, "list")
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "count": len(entries)})
}

// createKnowledge serves POST /api/knowledge: the operator writes any scope
// directly as adopted. Global, environment and company entries carry no origin
// task, so the store only scrubs secrets and IP/email literals.
func (s *Server) createKnowledge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope     string   `json:"scope"`
		CompanyID int64    `json:"company_id"`
		TaskID    int64    `json:"task_id"`
		Kind      string   `json:"kind"`
		Title     string   `json:"title"`
		Body      string   `json:"body"`
		Tags      []string `json:"tags"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	scope := strings.TrimSpace(body.Scope)
	kind := strings.TrimSpace(body.Kind)
	title := strings.TrimSpace(body.Title)
	if !knowledgeScopes[scope] {
		writeErr(w, 400, "invalid scope")
		return
	}
	if !knowledgeKinds[kind] {
		writeErr(w, 400, "invalid kind")
		return
	}
	if title == "" {
		writeErr(w, 400, "title required")
		return
	}
	switch scope {
	case "global", "environment":
		if body.CompanyID != 0 || body.TaskID != 0 {
			writeErr(w, 400, scope+" entry takes no ids")
			return
		}
	case "company":
		if body.CompanyID <= 0 || body.TaskID != 0 {
			writeErr(w, 400, "company entry needs a company id")
			return
		}
	case "task":
		if body.TaskID <= 0 || body.CompanyID != 0 {
			writeErr(w, 400, "task entry needs a task id")
			return
		}
		task, err := s.m.PG().GetTask(body.TaskID)
		if err != nil {
			log.Printf("[memory] knowledge task lookup failed for %d: %v", body.TaskID, err)
			writeErr(w, 500, "task lookup failed")
			return
		}
		if task == nil {
			writeErr(w, 404, "task not found")
			return
		}
	}
	entry, redactions, err := s.m.PG().AddKnowledge(r.Context(), db.KnowledgeInput{
		Scope: scope, CompanyID: body.CompanyID, TaskID: body.TaskID,
		Kind: kind, Title: title, Body: body.Body, Tags: body.Tags,
		Source: "operator", Status: "adopted",
	})
	if err != nil {
		writeKnowledgeError(w, err, "create")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry, "redactions": redactions})
}

// patchKnowledge serves PATCH /api/knowledge/{id}. A task-scoped entry cannot
// be adopted here: it must be promoted, which generalises the origin task's
// identifiers first.
func (s *Server) patchKnowledge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid knowledge id")
		return
	}
	var body struct {
		Title  *string   `json:"title"`
		Body   *string   `json:"body"`
		Kind   *string   `json:"kind"`
		Tags   *[]string `json:"tags"`
		Status *string   `json:"status"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if body.Kind != nil && !knowledgeKinds[strings.TrimSpace(*body.Kind)] {
		writeErr(w, 400, "invalid kind")
		return
	}
	if body.Status != nil && !knowledgeStatuses[strings.TrimSpace(*body.Status)] {
		writeErr(w, 400, "invalid status")
		return
	}
	cur, err := s.m.PG().GetKnowledge(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "knowledge entry not found")
		return
	}
	if err != nil {
		writeKnowledgeError(w, err, "load")
		return
	}
	if body.Status != nil && strings.TrimSpace(*body.Status) == "adopted" && cur.Scope == "task" {
		writeErr(w, 409, "a task-scoped entry must be promoted, not adopted")
		return
	}
	entry, redactions, err := s.m.PG().UpdateKnowledge(r.Context(), id, db.KnowledgePatch{
		Title: body.Title, Body: body.Body, Kind: body.Kind, Tags: body.Tags, Status: body.Status,
	})
	if err != nil {
		writeKnowledgeError(w, err, "update")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry, "redactions": redactions})
}

// promoteKnowledge serves POST /api/knowledge/{id}/promote: task -> company,
// environment or global, adopted, re-scrubbed with the origin task's
// identifiers. An environment promotion SHOULD carry an "env:<name>" tag; the
// operator adds it with the create/patch tags.
func (s *Server) promoteKnowledge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid knowledge id")
		return
	}
	var body struct {
		Scope     string `json:"scope"`
		CompanyID int64  `json:"company_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	scope := strings.TrimSpace(body.Scope)
	if scope != "company" && scope != "environment" && scope != "global" {
		writeErr(w, 400, "promotion scope must be company, environment or global")
		return
	}
	if scope == "company" && body.CompanyID <= 0 {
		writeErr(w, 400, "company promotion needs a company id")
		return
	}
	if scope != "company" && body.CompanyID != 0 {
		writeErr(w, 400, scope+" promotion takes no company id")
		return
	}
	entry, redactions, err := s.m.PG().PromoteKnowledge(r.Context(), id, scope, body.CompanyID)
	if err != nil {
		writeKnowledgeError(w, err, "promote")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry, "redactions": redactions})
}

// deleteKnowledge serves DELETE /api/knowledge/{id}.
func (s *Server) deleteKnowledge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid knowledge id")
		return
	}
	if err := s.m.PG().DeleteKnowledge(r.Context(), id); err != nil {
		writeKnowledgeError(w, err, "delete")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// taskReflections serves GET /api/tasks/{id}/reflections. Reflections are
// strictly per task; kind may be repeated or comma-separated.
func (s *Server) taskReflections(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid task id")
		return
	}
	var kinds []string
	for _, raw := range r.URL.Query()["kind"] {
		for _, k := range strings.Split(raw, ",") {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if !reflectionKinds[k] {
				writeErr(w, 400, "invalid reflection kind")
				return
			}
			kinds = append(kinds, k)
		}
	}
	limit, ok := parseIDParam(r.URL.Query().Get("limit"))
	if !ok {
		writeErr(w, 400, "invalid limit")
		return
	}
	task, err := s.m.PG().GetTask(id)
	if err != nil {
		log.Printf("[memory] reflection task lookup failed for %d: %v", id, err)
		writeErr(w, 500, "task lookup failed")
		return
	}
	if task == nil {
		writeErr(w, 404, "task not found")
		return
	}
	refl, err := s.m.PG().ListReflections(r.Context(), id, kinds, int(limit))
	if err != nil {
		writeKnowledgeError(w, err, "reflection list")
		return
	}
	writeJSON(w, 200, map[string]any{"reflections": refl, "count": len(refl)})
}

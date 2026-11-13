package server

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
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
	knowledgeSources  = map[string]bool{"operator": true, "agent": true, "reflection": true}
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

// parseTimeParam parses an optional RFC3339 query parameter. ok=false means
// the parameter was present but invalid.
func parseTimeParam(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, true
	}
	v, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return v, true
}

// knowledgeSorts is the sort whitelist; anything else is rejected rather than
// silently ignored.
var knowledgeSorts = map[string]bool{"created": true, "updated": true, "title": true}

// parseOffsetParam parses an optional non-negative integer query parameter;
// unlike an id, zero is a valid offset. ok=false means invalid.
func parseOffsetParam(raw string) (n int, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// listKnowledge serves GET /api/knowledge. Without task_id it is the owner
// view over every scope; with task_id it is that task's visibility lens. A
// query ranks by full-text relevance unless an explicit sort is given, in
// both views.
//
// The answer is {"entries", "total", "count", "relaxed", "limit", "offset"}.
// total is the whole filtered set, so a pager can step past one page; count is
// the page length. relaxed is true when the query matched no entry exactly and
// the store ORed its terms instead, so a UI can say "no exact match; showing
// related" and a script knows the rows are a widened set rather than the
// filter's answer.
func (s *Server) listKnowledge(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := strings.TrimSpace(q.Get("scope"))
	kind := strings.TrimSpace(q.Get("kind"))
	status := strings.TrimSpace(q.Get("status"))
	source := strings.TrimSpace(q.Get("source"))
	tag := strings.TrimSpace(q.Get("tag"))
	query := strings.TrimSpace(q.Get("q"))
	sortBy := strings.TrimSpace(q.Get("sort"))
	order := strings.ToLower(strings.TrimSpace(q.Get("order")))
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
	if source != "" && !knowledgeSources[source] {
		writeErr(w, 400, "invalid source")
		return
	}
	if sortBy != "" && !knowledgeSorts[sortBy] {
		writeErr(w, 400, "invalid sort")
		return
	}
	if order != "" && order != "asc" && order != "desc" {
		writeErr(w, 400, "invalid order")
		return
	}
	taskID, ok := parseIDParam(q.Get("task_id"))
	if !ok {
		writeErr(w, 400, "invalid task id")
		return
	}
	originTaskID, ok := parseIDParam(q.Get("origin_task_id"))
	if !ok {
		writeErr(w, 400, "invalid origin task id")
		return
	}
	companyID, ok := parseIDParam(q.Get("company_id"))
	if !ok {
		writeErr(w, 400, "invalid company id")
		return
	}
	createdAfter, ok := parseTimeParam(q.Get("created_after"))
	if !ok {
		writeErr(w, 400, "invalid created_after")
		return
	}
	createdBefore, ok := parseTimeParam(q.Get("created_before"))
	if !ok {
		writeErr(w, 400, "invalid created_before")
		return
	}
	limit, ok := parseIDParam(q.Get("limit"))
	if !ok {
		writeErr(w, 400, "invalid limit")
		return
	}
	offset, ok := parseOffsetParam(q.Get("offset"))
	if !ok {
		writeErr(w, 400, "invalid offset")
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
	}
	effLimit := int(limit)
	if effLimit <= 0 {
		effLimit = 50
	}
	if effLimit > 200 {
		effLimit = 200
	}
	entries, total, relaxed, err := s.m.PG().ListKnowledgeMatch(r.Context(), db.KnowledgeFilter{
		Scope: scope, Kind: kind, Status: status, Source: source, Tag: tag,
		Query: query, TaskID: taskID, OriginTaskID: originTaskID, CompanyID: companyID,
		CreatedAfter: createdAfter, CreatedBefore: createdBefore,
		Sort: sortBy, Order: order, Ranked: query != "" && sortBy == "",
		Limit: effLimit, Offset: offset,
	})
	if err != nil {
		writeKnowledgeError(w, err, "list")
		return
	}
	writeJSON(w, 200, map[string]any{
		"entries": entries, "total": total, "count": len(entries),
		"relaxed": relaxed, "limit": effLimit, "offset": offset,
	})
}

// getKnowledge serves GET /api/knowledge/{id}.
func (s *Server) getKnowledge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid knowledge id")
		return
	}
	entry, err := s.m.PG().GetKnowledge(r.Context(), id)
	if err != nil {
		writeKnowledgeError(w, err, "load")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry})
}

// knowledgeStats serves GET /api/knowledge/stats.
func (s *Server) knowledgeStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.m.PG().KnowledgeStats(r.Context())
	if err != nil {
		writeKnowledgeError(w, err, "stats")
		return
	}
	writeJSON(w, 200, stats)
}

// createKnowledge serves POST /api/knowledge: the operator writes any scope
// directly as adopted. Global, environment and company entries carry no origin
// task, so the store only scrubs secrets and IP/email literals.
//
// With ?dry_run=true the same validation and scrubbing run but nothing is
// inserted: the response carries the entry that WOULD be stored (no id, no
// timestamps) and the redaction count, so the operator can see what would be
// generalised before committing.
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
	in := db.KnowledgeInput{
		Scope: scope, CompanyID: body.CompanyID, TaskID: body.TaskID,
		Kind: kind, Title: title, Body: body.Body, Tags: body.Tags,
		Source: "operator", Status: "adopted",
	}
	if dry := strings.TrimSpace(r.URL.Query().Get("dry_run")); dry == "1" || strings.EqualFold(dry, "true") {
		entry, redactions, err := s.m.PG().DryRunKnowledge(r.Context(), in)
		if err != nil {
			writeKnowledgeError(w, err, "preview")
			return
		}
		writeJSON(w, 200, map[string]any{"entry": entry, "redactions": redactions, "dry_run": true})
		return
	}
	entry, redactions, err := s.m.PG().AddKnowledge(r.Context(), in)
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

// demoteKnowledge serves POST /api/knowledge/{id}/demote: an adopted company,
// environment or global entry becomes a candidate of the given task again.
// Promotion generalised the origin's identifiers on the way out and demotion
// cannot restore them, so the returned entry is still the generalised text -
// the response says so with "generalised": true. A task-scoped entry is
// refused; it is already where a demotion would put it.
func (s *Server) demoteKnowledge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid knowledge id")
		return
	}
	var body struct {
		TaskID int64 `json:"task_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if body.TaskID <= 0 {
		writeErr(w, 400, "task_id required")
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
	entry, err := s.m.PG().DemoteKnowledge(r.Context(), id, body.TaskID)
	if err != nil {
		writeKnowledgeError(w, err, "demote")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry, "generalised": true})
}

// knowledgeBulkMax bounds one bulk batch: enough for a page of checkboxes,
// small enough that a request cannot hold the connection for minutes.
const knowledgeBulkMax = 100

// knowledgeErrorText flattens a store error into the per-id bulk result. The
// batch is best effort, so each row names its own failure and the rest still
// run; an unexpected error is logged rather than echoed.
func knowledgeErrorText(err error) string {
	switch {
	case errors.Is(err, db.ErrMemoryCapReached):
		return db.ErrMemoryCapReached.Error()
	case errors.Is(err, db.ErrMemoryInvalid):
		return strings.TrimSuffix(err.Error(), ": "+db.ErrMemoryInvalid.Error())
	case errors.Is(err, sql.ErrNoRows):
		return "knowledge entry not found"
	case isFKViolation(err):
		return "unknown company"
	default:
		log.Printf("[memory] knowledge bulk item failed: %v", err)
		return "operation failed"
	}
}

// bulkKnowledge serves POST /api/knowledge/bulk. Each id is applied on its own
// and reported on its own: one bad id never hides the fate of the others, and
// the response is a result row per requested id, in request order. Actions are
// promote (scope + company_id), retire, adopt and delete.
func (s *Server) bulkKnowledge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs       []int64 `json:"ids"`
		Action    string  `json:"action"`
		Scope     string  `json:"scope"`
		CompanyID int64   `json:"company_id"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	action := strings.TrimSpace(body.Action)
	switch action {
	case "promote", "retire", "adopt", "delete":
	default:
		writeErr(w, 400, "action must be promote, retire, adopt or delete")
		return
	}
	if len(body.IDs) == 0 {
		writeErr(w, 400, "ids required")
		return
	}
	if len(body.IDs) > knowledgeBulkMax {
		writeErr(w, 400, "at most 100 ids per batch")
		return
	}
	scope := strings.TrimSpace(body.Scope)
	if action == "promote" {
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
	}
	results := make([]map[string]any, 0, len(body.IDs))
	for _, id := range body.IDs {
		row := map[string]any{"id": id, "ok": true}
		var err error
		if id <= 0 {
			err = fmt.Errorf("invalid knowledge id: %w", db.ErrMemoryInvalid)
		} else {
			switch action {
			case "promote":
				_, _, err = s.m.PG().PromoteKnowledge(r.Context(), id, scope, body.CompanyID)
			case "retire":
				status := "retired"
				_, _, err = s.m.PG().UpdateKnowledge(r.Context(), id, db.KnowledgePatch{Status: &status})
			case "adopt":
				status := "adopted"
				_, _, err = s.m.PG().UpdateKnowledge(r.Context(), id, db.KnowledgePatch{Status: &status})
			case "delete":
				err = s.m.PG().DeleteKnowledge(r.Context(), id)
			}
		}
		if err != nil {
			row["ok"] = false
			row["error"] = knowledgeErrorText(err)
		}
		results = append(results, row)
	}
	writeJSON(w, 200, map[string]any{"results": results})
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

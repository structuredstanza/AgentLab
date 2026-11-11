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

	"github.com/structuredstanza/AgentLab/artex-global/db"
)

// The reflection pool's owner surface: the cross-task curation view over what
// agents learned. taskReflections (server/knowledge.go) stays the per-task lens
// an agent reads through; these handlers list across tasks, edit, delete, and
// graduate one reflection into a task-scoped knowledge candidate. Promotion of
// that candidate remains a separate operator action.

var reflectionSources = map[string]bool{"engine": true, "worker": true, "planner": true}

// writeReflectionError maps the store's sentinels onto the API contract: a full
// per-task cap is a 409, a rejected edit is a 400, a missing row is a 404.
func writeReflectionError(w http.ResponseWriter, err error, action string) {
	switch {
	case errors.Is(err, db.ErrMemoryCapReached):
		writeErr(w, 409, db.ErrMemoryCapReached.Error())
	case errors.Is(err, db.ErrMemoryInvalid):
		writeErr(w, 400, err.Error())
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, 404, "reflection not found")
	default:
		log.Printf("[memory] reflection %s failed: %v", action, err)
		writeErr(w, 500, "reflection "+action+" failed")
	}
}

// parseSince accepts an RFC3339 instant or a bare YYYY-MM-DD date, so a UI can
// filter by day and a script can filter by moment.
func parseSince(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", raw)
}

// parseOffset parses a non-negative page offset; ok=false means invalid.
func parseOffset(raw string) (offset int, ok bool) {
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

// listReflections serves GET /api/reflections: the cross-task pool with the
// same filter vocabulary as the knowledge list, plus paging. task_id narrows
// to one task when the UI drills in; q runs over the generated tsv.
func (s *Server) listReflections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	taskID, ok := parseIDParam(q.Get("task_id"))
	if !ok {
		writeErr(w, 400, "invalid task id")
		return
	}
	var kinds []string
	for _, raw := range q["kind"] {
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
	source := strings.TrimSpace(q.Get("source"))
	if source != "" && !reflectionSources[source] {
		writeErr(w, 400, "invalid reflection source")
		return
	}
	limit, ok := parseIDParam(q.Get("limit"))
	if !ok {
		writeErr(w, 400, "invalid limit")
		return
	}
	n := int(limit)
	if n <= 0 {
		n = 50
	}
	if n > 200 {
		n = 200
	}
	offset, ok := parseOffset(q.Get("offset"))
	if !ok {
		writeErr(w, 400, "invalid offset")
		return
	}
	var since *time.Time
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		t, err := parseSince(raw)
		if err != nil {
			writeErr(w, 400, "invalid since (want RFC3339 or YYYY-MM-DD)")
			return
		}
		since = &t
	}
	refl, total, err := s.m.PG().ListReflectionsPage(r.Context(), db.ReflectionFilter{
		TaskID: taskID, Kinds: kinds, Source: source,
		Query: strings.TrimSpace(q.Get("q")), Since: since,
		Limit: n, Offset: offset,
	})
	if err != nil {
		writeReflectionError(w, err, "list")
		return
	}
	writeJSON(w, 200, map[string]any{
		"reflections": refl, "total": total, "count": len(refl),
		"limit": n, "offset": offset,
	})
}

// reflectionStats serves GET /api/reflections/stats.
func (s *Server) reflectionStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.m.PG().ReflectionStats(r.Context())
	if err != nil {
		writeReflectionError(w, err, "stats")
		return
	}
	writeJSON(w, 200, stats)
}

// patchReflection serves PATCH /api/reflections/{id}. Only the text an operator
// legitimately refines is editable: kind, source, task, dedupe key and signal
// are write-time facts of the observation. The store re-runs the same scrub and
// task-identifier generalisation an agent write gets.
func (s *Server) patchReflection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid reflection id")
		return
	}
	var body struct {
		Summary *string `json:"summary"`
		Detail  *string `json:"detail"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if body.Summary == nil && body.Detail == nil {
		writeErr(w, 400, "nothing to update")
		return
	}
	refl, err := s.m.PG().UpdateReflection(r.Context(), id, body.Summary, body.Detail)
	if err != nil {
		writeReflectionError(w, err, "update")
		return
	}
	writeJSON(w, 200, map[string]any{"reflection": refl})
}

// deleteReflection serves DELETE /api/reflections/{id}.
func (s *Server) deleteReflection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid reflection id")
		return
	}
	if err := s.m.PG().DeleteReflection(r.Context(), id); err != nil {
		writeReflectionError(w, err, "delete")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// graduateReflection serves POST /api/reflections/{id}/graduate: one
// reflection becomes a task-scoped knowledge candidate for its own task, tagged
// "reflection:<id>" so its origin is visible. It never promotes - the operator
// promotes the candidate afterwards. No bookkeeping is stored on the
// reflection: AddKnowledge's per-task title upsert absorbs a second graduation
// of the same summary.
func (s *Server) graduateReflection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid reflection id")
		return
	}
	var body struct {
		Kind  string   `json:"kind"`
		Title string   `json:"title"`
		Tags  []string `json:"tags"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	kind := strings.TrimSpace(body.Kind)
	if !knowledgeKinds[kind] {
		writeErr(w, 400, "invalid kind")
		return
	}
	refl, err := s.m.PG().GetReflection(r.Context(), id)
	if err != nil {
		writeReflectionError(w, err, "load")
		return
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		title = refl.Summary
	}
	tags := append(append([]string{}, body.Tags...), fmt.Sprintf("reflection:%d", refl.ID))
	entry, redactions, err := s.m.PG().AddKnowledge(r.Context(), db.KnowledgeInput{
		Scope: "task", TaskID: refl.TaskID, Kind: kind, Title: title, Body: refl.Detail,
		Tags: tags, Source: "reflection", Status: "candidate",
	})
	if err != nil {
		writeReflectionError(w, err, "graduate")
		return
	}
	writeJSON(w, 200, map[string]any{"entry": entry, "redactions": redactions})
}

package server

import "net/http"

// knowledgeReview serves GET /api/knowledge/review: one task's promotion
// queue, strongest evidence first. The owner gate is unchanged - this only
// lists what is waiting; the existing promote endpoint does the promotion.
func (s *Server) knowledgeReview(w http.ResponseWriter, r *http.Request) {
	taskID, ok := parseIDParam(r.URL.Query().Get("task_id"))
	if !ok || taskID == 0 {
		writeErr(w, 400, "invalid task id")
		return
	}
	items, err := s.m.PG().KnowledgeReview(r.Context(), taskID)
	if err != nil {
		writeKnowledgeError(w, err, "review")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

// knowledgeReviewCounts serves GET /api/knowledge/review/counts: how many
// candidates each task has waiting, for the tasks list. A task with none is
// absent, so an idle installation answers {"counts":{}} rather than null.
func (s *Server) knowledgeReviewCounts(w http.ResponseWriter, r *http.Request) {
	counts, err := s.m.PG().KnowledgeReviewCounts(r.Context())
	if err != nil {
		writeKnowledgeError(w, err, "review counts")
		return
	}
	writeJSON(w, 200, map[string]any{"counts": counts})
}

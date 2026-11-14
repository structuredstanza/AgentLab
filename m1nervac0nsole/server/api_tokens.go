package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Bounds for a minted token's lifetime. A harness that outlives its engagement is
// worse than a re-mint, so the ceiling is 30 days.
const (
	apiTokenDefaultTTLHours = 24
	apiTokenMaxTTLHours     = 720
)

// apiTokenCreated is the mint response: the row plus the plaintext, which is
// returned exactly once and is not recoverable afterwards.
type apiTokenCreated struct {
	db.APIToken
	Token string `json:"token"`
}

// POST /api/tokens - mints a read-only token scoped to one task.
func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		Name     string `json:"name"`
		TaskID   int64  `json:"task_id"`
		TTLHours int    `json:"ttl_hours"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, 400, "name is required")
		return
	}
	if body.TTLHours == 0 {
		body.TTLHours = apiTokenDefaultTTLHours
	}
	if body.TTLHours < 1 || body.TTLHours > apiTokenMaxTTLHours {
		writeErr(w, 400, "ttl_hours must be between 1 and 720")
		return
	}
	var exists bool
	if err := pg.QueryRow(`SELECT EXISTS (SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, body.TaskID).Scan(&exists); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !exists {
		writeErr(w, 404, "task not found")
		return
	}
	plaintext, row, err := pg.CreateAPIToken(r.Context(), name, body.TaskID, time.Duration(body.TTLHours)*time.Hour)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, apiTokenCreated{APIToken: *row, Token: plaintext})
}

// GET /api/tokens - every token with its state, never the plaintext or hash.
func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	items, err := pg.ListAPITokens(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// DELETE /api/tokens/{id} - revokes a token; the row is kept for the audit trail.
func (s *Server) deleteAPIToken(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad token id")
		return
	}
	if err := pg.RevokeAPIToken(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrAPITokenNotFound) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/tokens/audit - the newest MCP calls across every token.
func (s *Server) listMCPAudit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	items, err := pg.ListMCPAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

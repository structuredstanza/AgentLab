package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestTaskTemplateResponsesLocalized drives the real response paths that do not
// touch the database: the body decoder rejects an oversized request, the field
// validator rejects an over-length name, and writeTaskTemplateErr maps the
// name-conflict sentinel to an HTTP 409 response.
func TestTaskTemplateResponsesLocalized(t *testing.T) {
	// decodeTaskTemplateRequest — MaxBytesReader errors on an oversized body
	// before any DB access, so the 413 message is produced on its own.
	body := `{"name":"` + strings.Repeat("a", maxTaskTemplateRequestBytes+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/task-templates", strings.NewReader(body))
	rec := httptest.NewRecorder()
	var decoded taskTemplateRequest
	if _, ok := decodeTaskTemplateRequest(rec, req, &decoded); ok {
		t.Fatalf("too-large: decoding must not pass (status=%d)", rec.Code)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too-large status=%d, want 413", rec.Code)
	}

	// validateTaskTemplateRequest — a name past the rune limit returns the
	// field-too-long error surfaced by writeErr.
	longName := strings.Repeat("a", db.MaxTaskTemplateNameRunes+1)
	err := validateTaskTemplateRequest(taskTemplateRequest{Name: &longName})
	if err == nil {
		t.Fatal("name-too-long: validation must not pass")
	}

	// The name-conflict sentinel maps to HTTP 409.
	rec = httptest.NewRecorder()
	writeTaskTemplateErr(rec, db.ErrTaskTemplateNameConflict)
	if rec.Code != http.StatusConflict {
		t.Fatalf("name-conflict status=%d, want 409", rec.Code)
	}
}

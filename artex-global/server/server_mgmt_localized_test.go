package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServerMgmtAPIReturnedFormat guards that the model-list probe format string
// keeps its status-code and body placeholders (a %d→wrong-verb edit would drop
// them).
func TestServerMgmtAPIReturnedFormat(t *testing.T) {
	msg := fmt.Sprintf(errMgmtAPIReturned, 404, "boom-body")
	if !strings.Contains(msg, "404") || !strings.Contains(msg, "boom-body") {
		t.Fatalf("the format string must preserve the status code and body: %q", msg)
	}
}

// TestServerMgmtPGGate503 exercises the real shared DB gate every management handler
// passes through: with no PostgreSQL handle, pg() writes 503 and returns nil.
func TestServerMgmtPGGate503(t *testing.T) {
	s := &Server{m: &Manager{}} // pg == nil
	rec := httptest.NewRecorder()
	if got := s.pg(rec); got != nil {
		t.Fatal("pg() must return nil when there is no DB handle")
	}
	if rec.Code != 503 {
		t.Fatalf("expected status code 503 but got %d", rec.Code)
	}
}

// TestServerMgmtDeleteTaskBadIDLocalized drives pgDeleteTask through its first
// guard (non-numeric id → 400) without any DB or engine.
func TestServerMgmtDeleteTaskBadIDLocalized(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodDelete, "/api/tasks/abc", nil)
	req.SetPathValue("id", "abc")
	rec := httptest.NewRecorder()
	s.pgDeleteTask(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status code 400 but got %d (body %s)", rec.Code, rec.Body.Bytes())
	}
}

// TestServerMgmtListModelsNoKeyLocalized drives pgListModels with no api key and
// no profile id, so it returns {"ok":false,"error":...} before touching the DB.
func TestServerMgmtListModelsNoKeyLocalized(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/llm/models", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	s.pgListModels(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected status code 200 but got %d", rec.Code)
	}
	got := decodeErrorField(t, rec.Body.Bytes())
	if got != errMgmtNoAPIKey {
		t.Fatalf("must match errMgmtNoAPIKey: %q", got)
	}
}

// TestServerMgmtValidateTemplate exercises the prompt-template editor validator (pure
// function, no DB): both the parse-error and the disallowed-variable branches must
// return a message.
func TestServerMgmtValidateTemplate(t *testing.T) {
	if validateTemplate("{{", nil) == "" {
		t.Fatal("a broken template must return an error message")
	}
	msg := validateTemplate("{{.Bogus}}", nil)
	if msg == "" {
		t.Fatal("a variable not on the allowlist must return an error message")
	}
	if !strings.Contains(msg, "Bogus") {
		t.Fatalf("the variable name must appear in the message: %q", msg)
	}
}

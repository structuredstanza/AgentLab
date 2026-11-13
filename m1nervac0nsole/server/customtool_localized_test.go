package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// customtool.go handler tests: validation error responses over HTTP. Agent-facing tool results are not covered.

// newCustomToolServer creates a Server that passes the pg gate (s.pg) but has no actual DB connection.
// &db.DB{} has a nil embedded *sql.DB, but the pointer itself is non-nil, so pg() does not write a 503
// without modifying it and return it as is. All the validation branches below run BEFORE any actual DB call such as pg.GetTool
// Returns early, so it never dereferences a nil DB (confirmed by tracing the code path).
func newCustomToolServer() *Server {
	return &Server{m: &Manager{pg: &db.DB{}}}
}

// TestCustomToolCreateValidationLocalized drives the three pgCreateCustomTool validation paths over HTTP. All return before pg.GetTool.
func TestCustomToolCreateValidationLocalized(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"bad-key", `{"key":"BadKey","kind":"command"}`},
		{"bad-kind", `{"key":"goodkey","kind":"bogus"}`},
		{"http-no-schema", `{"key":"goodkey","kind":"http"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCustomToolServer()
			req := httptest.NewRequest(http.MethodPost, "/api/tools/custom", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			s.pgCreateCustomTool(rec, req)
			if rec.Code != 400 && rec.Code != 409 {
				t.Fatalf("expected a validation-error status code but got %d (body %q)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestCustomToolTestRunValidationLocalized drives the three pgTestCustomTool validation paths over HTTP. None touch the DB.
func TestCustomToolTestRunValidationLocalized(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"bad-body", `not-json`},
		{"shell", `{"kind":"shell"}`},
		{"unknown-kind", `{"kind":"bogus"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCustomToolServer()
			req := httptest.NewRequest(http.MethodPost, "/api/tools/custom/test", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			s.pgTestCustomTool(rec, req)
			if rec.Code != 400 {
				t.Fatalf("expected status code 400 but got %d (body %q)", rec.Code, rec.Body.String())
			}
		})
	}
}

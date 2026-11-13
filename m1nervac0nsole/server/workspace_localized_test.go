package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestWorkspaceHandlerResponsesLocalized drives the workspace file-manager handlers
// over real HTTP and checks their status codes. They only touch s.m.dir and the
// filesystem (never s.m.pg), so a temp-dir Manager is enough — no DB.
func TestWorkspaceHandlerResponsesLocalized(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: dir}}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
		code    int
	}{
		{"read-missing", s.wsRead, httptest.NewRequest(http.MethodGet, "/api/workspace/read?path=nope.txt", nil), 404},
		{"read-dir", s.wsRead, httptest.NewRequest(http.MethodGet, "/api/workspace/read?path=sub", nil), 400},
		{"list-missing", s.wsList, httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=nope", nil), 404},
		{"list-not-dir", s.wsList, nil, 400}, // req built below (needs a real file)
		{"delete-root", s.wsDelete, httptest.NewRequest(http.MethodDelete, "/api/workspace/delete?path=", nil), 400},
	}

	// list-not-dir needs an actual file to point at.
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases[3].req = httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=a.txt", nil)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.handler(rec, c.req)
			if rec.Code != c.code {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, c.code, rec.Body.String())
			}
		})
	}
}

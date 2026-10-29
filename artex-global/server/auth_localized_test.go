package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequireAuthMessagesLocalized checks that requireAuth returns 401 for missing or invalid tokens.
func TestRequireAuthMessagesLocalized(t *testing.T) {
	s := &Server{jwtKey: []byte(strings.Repeat("k", 32))}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.requireAuth(next)

	cases := []struct {
		name   string
		bearer string
	}{
		{"missing-token", ""},
		{"invalid-token", "Bearer not-a-valid-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/tasks", nil)
			if c.bearer != "" {
				r.Header.Set("Authorization", c.bearer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status code = %d, expected 401", rec.Code)
			}
		})
	}
}

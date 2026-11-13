//go:build !embedui

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWebUIStubNotFound: a request served by the default (!embedui) build must get 404.
func TestWebUIStubNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	(&Server{}).webuiHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status code is not 404: %d", rec.Code)
	}
}

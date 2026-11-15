package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteOriginErrorCarriesTheChallenge proves a classified refusal reaches
// the client with its status, its stage and the headers the transport set,
// which is what lets a browser answer a 407 with its proxy credential.
func TestWriteOriginErrorCarriesTheChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	writeOriginError(rec, &OriginError{
		Stage:  "policy",
		Status: http.StatusProxyAuthRequired,
		Reason: "no backend-issued session",
		Header: http.Header{"Proxy-Authenticate": {`Basic realm="test"`}},
	})

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", rec.Code)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got != `Basic realm="test"` {
		t.Fatalf("challenge = %q, want the transport's header", got)
	}
	if got := rec.Header().Get("X-M1nervac0nsole-Gateway"); got != "policy" {
		t.Fatalf("stage = %q, want policy", got)
	}
}

// TestWriteOriginErrorWithoutHeaders proves a refusal with no headers set is
// unchanged: the status and the stage, nothing else.
func TestWriteOriginErrorWithoutHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeOriginError(rec, &OriginError{Stage: "policy", Status: http.StatusForbidden})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none", got)
	}
}

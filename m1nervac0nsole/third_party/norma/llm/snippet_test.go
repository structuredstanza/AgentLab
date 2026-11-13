package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The upstream body is copied into the error, which callers persist to
// llm_health and llm_records and display in the UI. An upstream that echoes the
// credential back must not get it into those columns.
func TestUpstreamErrorBodyIsBoundedAndScrubbed(t *testing.T) {
	const echoed = "sk-TESTKEY12345"
	big := strings.Repeat("x", 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided: ` + echoed + `"},"pad":"` + big + `"}`))
	}))
	defer srv.Close()

	cfg := Config{HTTPClient: srv.Client(), MaxRetries: -1}
	_, err := doStream(context.Background(), cfg, srv.URL, []byte(`{}`), func(*http.Request) {}, "openai")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, echoed) {
		t.Errorf("the echoed credential reached the error: %s", msg)
	}
	if !strings.Contains(msg, "REDACTED") {
		t.Errorf("no redaction marker: %s", msg)
	}
	if !strings.Contains(msg, "status 401") {
		t.Errorf("the status was lost: %s", msg)
	}
	if len(msg) > errBodyLimit+80 {
		t.Errorf("error carries %d bytes of upstream body, want it bounded", len(msg))
	}
	t.Logf("error: %s", msg)
}

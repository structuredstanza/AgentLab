package mcphttp

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The announced POST endpoint must stay on the configured SSE origin: a relative
// endpoint resolves against it, an absolute same-origin one is accepted (default
// ports normalised), and any other origin is refused.
func TestReadSSEEndpointOrigin(t *testing.T) {
	for _, tc := range []struct {
		name     string
		base     string
		announce string
		want     string
	}{
		{"relative", "http://127.0.0.1:8787/sse", "/message?sessionId=1", "http://127.0.0.1:8787/message?sessionId=1"},
		{"same origin absolute", "https://mcp.example.com/sse", "https://mcp.example.com:443/message", "https://mcp.example.com:443/message"},
		{"other host", "http://127.0.0.1:8787/sse", "http://evil.example/message", ""},
		{"other port", "http://127.0.0.1:8787/sse", "http://127.0.0.1:9999/message", ""},
		{"other scheme", "http://127.0.0.1:8787/sse", "https://127.0.0.1:8787/message", ""},
		{"protocol relative", "http://127.0.0.1:8787/sse", "//evil.example/message", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader("event: endpoint\ndata: " + tc.announce + "\n\n"))
			got, err := readSSEEndpoint(r, tc.base)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("cross-origin endpoint %q accepted as %q", tc.announce, got)
				}
				if !strings.Contains(err.Error(), "cross-origin") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("readSSEEndpoint: %v", err)
			}
			if got != tc.want {
				t.Fatalf("endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// A cross-origin announcement must be refused before the configured headers
// (Authorization) are sent to that origin.
func TestLegacySSECrossOriginEndpointRefused(t *testing.T) {
	var mu sync.Mutex
	var hits int
	var auth string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: %s/message\n\n", other.URL)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := NewSSE(ctx, "fixture", srv.URL+"/sse", map[string]string{"Authorization": "Bearer secret"}, false)
	mu.Lock()
	gotHits, gotAuth := hits, auth
	mu.Unlock()
	if gotHits != 0 {
		t.Fatalf("cross-origin endpoint received %d request(s)", gotHits)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization header leaked to the cross-origin endpoint: %q", gotAuth)
	}
	if err == nil {
		t.Fatal("cross-origin message endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

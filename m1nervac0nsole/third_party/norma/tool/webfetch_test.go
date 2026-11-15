package tool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func fetchOnce(t *testing.T, cfg WebFetchConfig, url string) Result {
	t.Helper()
	in, _ := json.Marshal(map[string]any{"url": url})
	res, err := webFetchRunner(cfg)(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("webFetchRunner: %v", err)
	}
	return res
}

// A configured proxy is the only route: when the proxy fails at the transport
// level, WebFetch reports that failure and must not re-fetch the URL directly.
func TestWebFetchProxyFailureHasNoDirectFallback(t *testing.T) {
	var directHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		_, _ = w.Write([]byte("<html><body><p>direct</p></body></html>"))
	}))
	defer target.Close()

	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		// Drop the connection without answering: a transport-level proxy failure.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
		http.Error(w, "proxy error", http.StatusBadGateway)
	}))
	defer proxy.Close()

	res := fetchOnce(t, WebFetchConfig{Proxy: proxy.URL}, target.URL+"/page")
	if !res.IsError {
		t.Fatalf("proxy failure was not reported as an error: %q", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "configured proxy") {
		t.Fatalf("proxy failure not classified: %q", res.Flatten())
	}
	if n := proxyHits.Load(); n == 0 {
		t.Fatal("configured proxy was never used")
	}
	if n := directHits.Load(); n != 0 {
		t.Fatalf("URL was re-fetched directly %d time(s) after the proxy failed", n)
	}
}

// Without a proxy the tool still fetches directly and renders the page.
func TestWebFetchDirectStillWorks(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Heading</h1><p>body text</p></body></html>"))
	}))
	defer target.Close()

	res := fetchOnce(t, WebFetchConfig{}, target.URL+"/page")
	if res.IsError {
		t.Fatalf("direct fetch failed: %q", res.Flatten())
	}
	if out := res.Flatten(); !strings.Contains(out, "Heading") || !strings.Contains(out, "body text") {
		t.Fatalf("page not rendered: %q", out)
	}
}

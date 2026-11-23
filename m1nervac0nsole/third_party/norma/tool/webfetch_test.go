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

// A refused CONNECT is classified from the gateway's stage and reason, not
// reported as bare status text, and the proxy credential never appears.
func TestWebFetchClassifiesRefusedConnect(t *testing.T) {
	for _, tc := range []struct {
		name, stage, reason string
		status              int
		want                []string
	}{
		{"policy", "policy", "no authorized rule covers http target.example:443", http.StatusForbidden, []string{"policy stage (CONNECT 403): no authorized rule covers http target.example:443.", "do not retry"}},
		{"dial", "dial", "dial tcp: connection refused (runuser secretpw)", http.StatusBadGateway, []string{"CONNECT 502, stage dial): dial tcp: connection refused (*** ***)"}},
		{"credential", "policy", "no backend-issued session for this connection", http.StatusProxyAuthRequired, []string{"CONNECT 407", "proxy credential", "platform fault, not a block by the target"}},
		{"unstaged", "", "", http.StatusTeapot, []string{"CONNECT 418"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.stage != "" {
					w.Header().Set("X-M1nervac0nsole-Gateway", tc.stage)
				}
				w.WriteHeader(tc.status)
				if tc.reason != "" {
					_, _ = w.Write([]byte(tc.reason + "\n"))
				}
			}))
			defer proxy.Close()
			cfg := WebFetchConfig{Proxy: strings.Replace(proxy.URL, "http://", "http://runuser:secretpw@", 1)}
			res := fetchOnce(t, cfg, "https://target.example/page")
			got := res.Flatten()
			if !res.IsError {
				t.Fatalf("refused CONNECT was not an error: %q", got)
			}
			for _, w := range append(tc.want, "configured proxy") {
				if !strings.Contains(got, w) {
					t.Errorf("error %q lacks %q", got, w)
				}
			}
			if strings.Contains(got, "secretpw") || strings.Contains(got, "runuser") {
				t.Errorf("error leaks the proxy credential: %q", got)
			}
		})
	}
}

// A refusal that arrives as an ordinary response (plain HTTP through the
// gateway) keeps its stage and reason in the result header.
func TestWebFetchReportsGatewayStageOnPlainResponse(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-M1nervac0nsole-Gateway", "policy")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("no authorized rule covers target.example\n"))
	}))
	defer proxy.Close()
	got := fetchOnce(t, WebFetchConfig{Proxy: proxy.URL}, "http://target.example/page").Flatten()
	for _, w := range []string{"[403 Forbidden]", "Gateway-Stage: policy", "Gateway-Reason: no authorized rule covers target.example"} {
		if !strings.Contains(got, w) {
			t.Errorf("result %q lacks %q", got, w)
		}
	}
}

// An origin whose certificate no configured CA signed is named as a trust
// failure, which the model can tell apart from a block.
func TestWebFetchNamesCertificateTrustFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	res := fetchOnce(t, WebFetchConfig{}, srv.URL+"/page")
	if !res.IsError || !strings.Contains(res.Flatten(), "TLS certificate verification failed") {
		t.Fatalf("trust failure not classified: %q", res.Flatten())
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

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

// A custom http tool call goes through the recorder and never through the
// ambient HTTP_PROXY of the backend process.
func TestHTTPToolIgnoresAmbientProxyEnv(t *testing.T) {
	var envHits, recorderHits atomic.Int32
	envProxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { envHits.Add(1) }))
	defer envProxy.Close()
	recorder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorderHits.Add(1)
		if r.RequestURI != "http://origin.example.test/x" {
			t.Errorf("recorder got %q", r.RequestURI)
		}
		_, _ = w.Write([]byte("via-recorder"))
	}))
	defer recorder.Close()
	t.Setenv("HTTP_PROXY", envProxy.URL)
	t.Setenv("http_proxy", envProxy.URL)

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": "http://origin.example.test/x"})
	ctx := execbox.WithSession(context.Background(), credentialSession())
	res, err := (&Server{m: &Manager{globalProxy: recorder.URL}}).runHTTPTool(ctx, execRaw, map[string]any{}, nil)
	if err != nil || res.IsError {
		t.Fatalf("runHTTPTool: %v %s", err, res.Flatten())
	}
	if recorderHits.Load() != 1 || envHits.Load() != 0 {
		t.Fatalf("recorder hits = %d, env proxy hits = %d; want 1 and 0", recorderHits.Load(), envHits.Load())
	}
}

// A recorder CA that cannot be loaded fails the call instead of falling back to
// the default roots.
func TestHTTPToolMissingCAFailsClosed(t *testing.T) {
	tr, err := traffic.OpenWithTransport(t.TempDir(), "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	s := &Server{m: &Manager{traffic: tr, trafficOn: true}}
	ctx := execbox.WithSession(context.Background(), credentialSession())

	_ = os.Remove(tr.CACertPath())
	if _, _, err := s.httpProxyTransport(ctx); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("missing CA: err = %v, want a CA error", err)
	}
	if err := os.MkdirAll(filepath.Dir(tr.CACertPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tr.CACertPath(), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.httpProxyTransport(ctx); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("garbage CA: err = %v, want a CA error", err)
	}
}

// forwardingProxyServer is a Server whose recording proxy forwards absolute-URI
// requests to the origin, so the tests that read a real response still run.
func forwardingProxyServer(t *testing.T) *Server {
	t.Helper()
	fwd := &http.Transport{}
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RequestURI = ""
		resp, err := fwd.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(p.Close)
	return &Server{m: &Manager{globalProxy: p.URL}}
}

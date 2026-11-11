package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
)

// proxyStatusServer serves only the native proxy status route on loopback.
func proxyStatusServer(t *testing.T, connected bool) *nativeproxy.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profiles/7/status" || r.URL.Query().Get("provider") != "codex" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"connected": connected})
	}))
	t.Cleanup(srv.Close)
	c, err := nativeproxy.New(srv.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProfileUsableFollowsProxyReadiness(t *testing.T) {
	profile := &db.LLMProfile{ID: 7, AuthMethod: "codex"}

	if s := (&Server{nativeProxy: proxyStatusServer(t, true)}); !s.profileUsable(profile) {
		t.Fatal("connected native proxy profile was rejected")
	}
	if s := (&Server{nativeProxy: proxyStatusServer(t, false)}); s.profileUsable(profile) {
		t.Fatal("disconnected native proxy profile was accepted")
	}
	if s := (&Server{}); s.profileUsable(profile) {
		t.Fatal("native proxy profile accepted without a native proxy")
	}
}

func TestAPIKeyProfileUsableWithoutProxy(t *testing.T) {
	s := &Server{}
	if !s.profileUsable(&db.LLMProfile{ID: 3, AuthMethod: "api_key", APIKey: "k"}) {
		t.Fatal("API-key profile rejected when native proxy is off")
	}
	if s.profileUsable(&db.LLMProfile{ID: 3, AuthMethod: "api_key"}) {
		t.Fatal("API-key profile without a key was accepted")
	}
}

func TestNativeProxyProfileStatusUnavailableWithoutProxy(t *testing.T) {
	s := &Server{}
	_, err := s.nativeProxyProfileStatus(context.Background(), &db.LLMProfile{ID: 7, AuthMethod: "codex"})
	if err == nil {
		t.Fatal("expected errNativeProxyUnavailable without a native proxy")
	}
}

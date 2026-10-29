package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sdkbridge"
)

// bridgeStatusServer serves only the bridge status route on loopback.
func bridgeStatusServer(t *testing.T, connected bool) *sdkbridge.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profiles/7/status" || r.URL.Query().Get("provider") != "openai-codex" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"connected": connected})
	}))
	t.Cleanup(srv.Close)
	c, err := sdkbridge.New(srv.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProfileUsableFollowsBridgeReadiness(t *testing.T) {
	profile := &db.LLMProfile{ID: 7, AuthMethod: "codex"}

	if s := (&Server{sdk: bridgeStatusServer(t, true)}); !s.profileUsable(profile) {
		t.Fatal("connected SDK profile was rejected")
	}
	if s := (&Server{sdk: bridgeStatusServer(t, false)}); s.profileUsable(profile) {
		t.Fatal("disconnected SDK profile was accepted")
	}
	if s := (&Server{}); s.profileUsable(profile) {
		t.Fatal("SDK profile accepted without a bridge")
	}
}

func TestAPIKeyProfileUsableWithoutBridge(t *testing.T) {
	s := &Server{}
	if !s.profileUsable(&db.LLMProfile{ID: 3, AuthMethod: "api_key", APIKey: "k"}) {
		t.Fatal("API-key profile rejected when bridge is off")
	}
	if s.profileUsable(&db.LLMProfile{ID: 3, AuthMethod: "api_key"}) {
		t.Fatal("API-key profile without a key was accepted")
	}
}

func TestSDKProfileStatusUnavailableWithoutBridge(t *testing.T) {
	s := &Server{}
	_, err := s.sdkProfileStatus(context.Background(), &db.LLMProfile{ID: 7, AuthMethod: "codex"})
	if err == nil {
		t.Fatal("expected errSDKUnavailable without a bridge")
	}
}

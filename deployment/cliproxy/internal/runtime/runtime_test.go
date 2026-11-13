package runtime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/privacy"
)

func TestOAuthOriginGates(t *testing.T) {
	for _, tc := range []struct {
		provider contract.Provider
		url      string
		want     bool
	}{
		{contract.ProviderClaude, "https://claude.ai/oauth/authorize", true},
		{contract.ProviderCodex, "https://auth.openai.com/oauth/authorize", true},
		{contract.ProviderAntigravity, "https://accounts.google.com/o/oauth2/v2/auth", true},
		{contract.ProviderClaude, "https://claude.ai.attacker.invalid/oauth", false},
		{contract.ProviderCodex, "https://auth.openai.com@attacker.invalid/oauth", false},
		{contract.ProviderAntigravity, "https://accounts.google.com/o/oauth2/auth", false},
	} {
		if got := validAuthorizationOrigin(tc.provider, tc.url); got != tc.want {
			t.Errorf("validAuthorizationOrigin(%q, %q) = %t, want %t", tc.provider, tc.url, got, tc.want)
		}
	}
	for _, tc := range []struct {
		provider contract.Provider
		url      string
		want     bool
	}{
		{contract.ProviderClaude, "http://localhost:54545/oauth-callback?code=x", true},
		{contract.ProviderCodex, "http://127.0.0.1:1455/callback?code=x", true},
		{contract.ProviderAntigravity, "http://localhost:51121/oauth-callback?code=x", true},
		{contract.ProviderClaude, "http://localhost:54546/oauth-callback?code=x", false},
		{contract.ProviderClaude, "http://localhost.attacker.invalid:54545/callback?code=x", false},
		{contract.ProviderClaude, "https://localhost:54545/callback?code=x", false},
	} {
		if got := validCallbackOrigin(tc.provider, tc.url); got != tc.want {
			t.Errorf("validCallbackOrigin(%q, %q) = %t, want %t", tc.provider, tc.url, got, tc.want)
		}
	}
}

func TestCaptureStorePersistsRawTruncatedResponse(t *testing.T) {
	root := t.TempDir()
	captures, err := newCaptureStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer captures.file.Close()

	body := []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n")
	if err := captures.Record(privacy.Record{
		Direction:   privacy.DirectionResponse,
		Provider:    contract.ProviderCodex,
		Model:       "model",
		Profile:     "1",
		SessionID:   "session",
		Path:        "/v1/responses",
		ContentType: "text/event-stream",
		Body:        body,
		Complete:    false,
		Truncated:   true,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "captures", "native-sse.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	var got privacy.Record
	if err := json.Unmarshal(bytes.TrimSpace(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Direction != privacy.DirectionResponse || !bytes.Equal(got.Body, body) || got.Complete || !got.Truncated {
		t.Fatalf("captured source response = %#v; body or completion metadata was lost", got)
	}
}

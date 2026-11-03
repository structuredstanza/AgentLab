package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/artex/cliproxyhost/internal/contract"
	"github.com/artex/cliproxyhost/internal/privacy"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// TestNativeHostRealExecutorsFixture traverses the authenticated host API, real
// pinned native executors, private grant store, and final outbound capture/policy.
// The local CONNECT proxy terminates TLS only for official provider hostnames.
func TestNativeHostRealExecutorsFixture(t *testing.T) {
	proxy, proxyURL, caFile := newNativeFixtureProxy(t)
	t.Setenv("SSL_CERT_FILE", caFile)
	t.Setenv("HTTPS_PROXY", proxyURL)
	t.Setenv("HTTP_PROXY", proxyURL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("https_proxy", proxyURL)
	t.Setenv("http_proxy", proxyURL)
	t.Setenv("no_proxy", "")

	const capability = "local-fixture-capability-never-export"
	rt, err := New(t.TempDir(), []byte(capability))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.captures.file.Close() })
	rt.cfg.ProxyURL = proxyURL
	api := httptest.NewServer(rt.HTTPHandler())
	t.Cleanup(api.Close)

	if status, _ := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/models?provider=claude", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("models without host capability status=%d, want 401", status)
	}
	for _, p := range []contract.Provider{contract.ProviderClaude, contract.ProviderCodex, contract.ProviderAntigravity} {
		status, body := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/models?provider="+string(p), capability, nil)
		if status != http.StatusOK || !bytes.Contains(body, []byte(`"models":[`)) {
			t.Fatalf("prelogin models for %s: status=%d body=%s", p, status, body)
		}
	}
	var disconnected map[string]any
	if status, body := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/profiles/7/status?provider=claude", capability, nil); status != http.StatusOK || json.Unmarshal(body, &disconnected) != nil || disconnected["connected"] != false {
		t.Fatalf("missing-grant status=%d body=%s, want disconnected profile", status, body)
	}
	if status, _ := fixtureRequest(t, api.Client(), http.MethodPost, api.URL+"/v1/profiles/99/infer", "", []byte(`{}`)); status != http.StatusUnauthorized {
		t.Fatalf("missing-grant inference status=%d, want 401 without capability", status)
	}

	const profile contract.ProfileID = "7"
	grants := []struct {
		provider contract.Provider
		id       string
		email    string
		access   string
		refresh  string
		metadata string
	}{
		{contract.ProviderClaude, "native-fixture-c1", "claude@example.invalid", "claude-old-access", "claude-old-refresh", `{"type":"claude","access_token":"claude-old-access","refresh_token":"claude-old-refresh","expired":"2001-01-01T00:00:00Z","account_uuid":"claude-account"}`},
		{contract.ProviderCodex, "native-fixture-o1", "codex@example.invalid", "codex-old-access", "codex-old-refresh", `{"type":"codex","access_token":"codex-old-access","refresh_token":"codex-old-refresh","id_token":"old.id.token","expired":"2001-01-01T00:00:00Z","account_id":"codex-account","plan_type":"pro"}`},
		{contract.ProviderAntigravity, "native-fixture-g1", "gemini@example.invalid", "gemini-old-access", "gemini-old-refresh", `{"type":"antigravity","access_token":"gemini-old-access","refresh_token":"gemini-old-refresh","expired":"2001-01-01T00:00:00Z","project_id":"fixture-project"}`},
	}
	for _, g := range grants {
		rec := &contract.Record{CoreAuthID: g.id, Email: g.email, ExpiresAt: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), Raw: []byte(g.metadata)}
		if _, err := rt.store.Save(context.Background(), profile, g.provider, 0, rec); err != nil {
			t.Fatalf("seed private synthetic %s grant: %v", g.provider, err)
		}
		if g.provider == contract.ProviderCodex {
			other := *rec
			other.CoreAuthID = "native-fixture-o2"
			if _, err := rt.store.Save(context.Background(), "8", g.provider, 0, &other); err != nil {
				t.Fatalf("seed mismatched synthetic account: %v", err)
			}
		}
	}

	// The real host usage route refreshes the native auth through the core manager,
	// persists both rotated tokens, then runs the provider's actual quota recipe.
	for _, g := range grants {
		status, body := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/profiles/7/usage?provider="+string(g.provider), capability, nil)
		if status != http.StatusOK {
			t.Fatalf("usage for %s: status=%d body=%s", g.provider, status, body)
		}
		var report contract.UsageReport
		if err := json.Unmarshal(body, &report); err != nil || report.Provider != g.provider || len(report.Windows) == 0 {
			t.Fatalf("normalized usage for %s = %s (%v)", g.provider, body, err)
		}
		if g.provider == contract.ProviderAntigravity {
			w := report.Windows[0]
			if len(report.Windows) != 1 || w.ID != "five_hour" || w.RemainingFraction != 0.25 || w.UsedFraction != 0.75 ||
				w.ResetsAt == nil || *w.ResetsAt != "2026-10-31T00:00:00.000Z" {
				t.Fatalf("normalized Antigravity usage = %+v, want measured five_hour .25 remaining with reset", report.Windows)
			}
		}
		stored, err := rt.store.Load(context.Background(), profile, g.provider)
		if err != nil || stored.CoreAuthID != g.id {
			t.Fatalf("refresh changed core auth binding for %s: record=%+v err=%v", g.provider, stored, err)
		}
		for _, token := range []string{g.access, g.refresh} {
			if bytes.Contains(stored.Raw, []byte(token)) {
				t.Fatalf("%s retained pre-refresh token %q", g.provider, token)
			}
		}
		var updated map[string]any
		if err := json.Unmarshal(stored.Raw, &updated); err != nil || updated["access_token"] == nil || updated["refresh_token"] == nil {
			t.Fatalf("%s rotated grant missing access/refresh token: %s (%v)", g.provider, stored.Raw, err)
		}
	}

	models := map[contract.Provider]string{}
	otherModels := map[contract.Provider]string{}
	for _, p := range []contract.Provider{contract.ProviderClaude, contract.ProviderCodex, contract.ProviderAntigravity} {
		var catalog struct {
			Models []contract.Model `json:"models"`
		}
		_, body := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/models?provider="+string(p), capability, nil)
		if err := json.Unmarshal(body, &catalog); err != nil || len(catalog.Models) == 0 {
			t.Fatalf("decode native catalog %s: %s (%v)", p, body, err)
		}
		models[p] = catalog.Models[0].ID
		if len(catalog.Models) > 1 {
			otherModels[p] = catalog.Models[1].ID
		}
		if p == contract.ProviderAntigravity {
			models[p], otherModels[p] = "gemini-4-argon", "gemini-3.8-flash-high"
			foundModel, foundOther := false, false
			for _, model := range catalog.Models {
				foundModel = foundModel || model.ID == models[p]
				foundOther = foundOther || model.ID == otherModels[p]
			}
			if !foundModel || !foundOther {
				t.Fatalf("native Antigravity catalog lacks required logical and wire models: %s", body)
			}
		}
	}

	const directProfile contract.ProfileID = "2"
	directGrants := []struct {
		provider  contract.Provider
		id        string
		email     string
		access    string
		refresh   string
		metadata  string
		tokenHost string
		tokenPath string
	}{
		{contract.ProviderClaude, "native-direct-c1", "claude-direct@example.invalid", "claude-direct-old-access", "claude-direct-old-refresh", `{"type":"claude","access_token":"claude-direct-old-access","refresh_token":"claude-direct-old-refresh","expired":"2001-01-01T00:00:00Z","account_uuid":"claude-direct-account"}`, "platform.claude.com", "/v1/oauth/token"},
		{contract.ProviderCodex, "native-direct-o1", "codex-direct@example.invalid", "codex-direct-old-access", "codex-direct-old-refresh", `{"type":"codex","access_token":"codex-direct-old-access","refresh_token":"codex-direct-old-refresh","id_token":"old.id.token","expired":"2001-01-01T00:00:00Z","account_id":"codex-direct-account","plan_type":"pro"}`, "auth.openai.com", "/oauth/token"},
		{contract.ProviderAntigravity, "native-direct-g1", "gemini-direct@example.invalid", "gemini-direct-old-access", "gemini-direct-old-refresh", `{"type":"antigravity","access_token":"gemini-direct-old-access","refresh_token":"gemini-direct-old-refresh","expired":"2001-01-01T00:00:00Z","project_id":"fixture-project"}`, "oauth2.googleapis.com", "/token"},
	}
	for _, g := range directGrants {
		rec := &contract.Record{CoreAuthID: g.id, Email: g.email, ExpiresAt: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), Raw: []byte(g.metadata)}
		if _, err := rt.store.Save(context.Background(), directProfile, g.provider, 0, rec); err != nil {
			t.Fatalf("seed direct %s grant: %v", g.provider, err)
		}
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	preRefreshClaude := proxy.countHostPath("platform.claude.com", "/v1/oauth/token")
	b := contract.Binding{Provider: contract.ProviderClaude, Model: models[contract.ProviderClaude], Profile: directProfile, SessionID: "cancel-session", CredentialID: "native-direct-c1"}
	turnCtx := rt.turn(canceledCtx, b, nil)
	if _, err := (nativeStreamer{host: rt}).ExecuteStream(turnCtx, []string{string(contract.ProviderClaude)}, cliproxyexecutor.Request{Model: b.Model}, cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: b.CredentialID}}); err == nil {
		t.Fatal("ExecuteStream with canceled context succeeded, want cancellation error")
	}
	if proxy.countHostPath("platform.claude.com", "/v1/oauth/token") != preRefreshClaude {
		t.Fatalf("ExecuteStream initiated refresh on canceled-before-start context: before=%d after=%d", preRefreshClaude, proxy.countHostPath("platform.claude.com", "/v1/oauth/token"))
	}

	for _, g := range directGrants {
		model := models[g.provider]
		beforeRefresh := proxy.countHostPath(g.tokenHost, g.tokenPath)
		beforeInference := proxy.countInference(g.provider)

		status, events := fixtureInferenceProfile(t, api.Client(), api.URL, capability, string(directProfile), g.provider, model, "direct-session-"+string(g.provider), nativeToolRequest(g.provider, model, false), nil)
		if status != http.StatusOK || !containsFixtureDone(events) {
			t.Fatalf("direct inference on expired %s grant failed: status=%d events=%+v", g.provider, status, events)
		}
		if proxy.countHostPath(g.tokenHost, g.tokenPath) <= beforeRefresh {
			t.Fatalf("direct inference did not trigger native refresh for %s: before=%d after=%d", g.provider, beforeRefresh, proxy.countHostPath(g.tokenHost, g.tokenPath))
		}
		if proxy.countInference(g.provider) <= beforeInference {
			t.Fatalf("direct inference did not reach provider for %s", g.provider)
		}
		stored, err := rt.store.Load(context.Background(), directProfile, g.provider)
		if err != nil || stored == nil || stored.CoreAuthID != g.id {
			t.Fatalf("direct inference did not preserve CoreAuthID for %s: %+v (%v)", g.provider, stored, err)
		}
		if bytes.Contains(stored.Raw, []byte(g.access)) || bytes.Contains(stored.Raw, []byte(g.refresh)) {
			t.Fatalf("direct inference failed to rotate tokens in store for %s: %s", g.provider, stored.Raw)
		}
	}
	for _, tc := range []struct {
		status   int
		wantCode string
	}{
		{http.StatusTooManyRequests, "quota_exhausted"},
		{http.StatusUnauthorized, "upstream_unauthorized"},
		{http.StatusForbidden, "upstream_forbidden"},
	} {
		prompt := []byte(strings.Replace(string(nativeToolRequest(contract.ProviderClaude, models[contract.ProviderClaude], false)), "fixture user prompt", fmt.Sprintf("fixture upstream status %d", tc.status), 1))
		requestBody, err := json.Marshal(map[string]any{"provider": contract.ProviderClaude, "model": models[contract.ProviderClaude], "session_id": fmt.Sprintf("status-session-%d", tc.status), "input": json.RawMessage(prompt)})
		if err != nil {
			t.Fatal(err)
		}
		got, raw := fixtureRequest(t, api.Client(), http.MethodPost, api.URL+"/v1/profiles/"+string(directProfile)+"/infer", capability, requestBody)
		if got != tc.status || !bytes.Contains(raw, []byte(`"code":"`+tc.wantCode+`"`)) || bytes.Contains(raw, []byte("fixture-secret-provider-detail")) {
			t.Fatalf("upstream HTTP %d response status=%d body=%s; want safe code %q without provider detail", tc.status, got, raw, tc.wantCode)
		}
	}

	missingCalls := proxy.countInference(contract.ProviderClaude)
	missingStatus, _ := fixtureInferenceProfile(t, api.Client(), api.URL, capability, "99", contract.ProviderClaude, models[contract.ProviderClaude], "missing-grant", nativeToolRequest(contract.ProviderClaude, models[contract.ProviderClaude], false), nil)
	if missingStatus == http.StatusOK || proxy.countInference(contract.ProviderClaude) != missingCalls {
		t.Fatalf("missing-grant inference reached provider: status=%d calls=%d->%d", missingStatus, missingCalls, proxy.countInference(contract.ProviderClaude))
	}
	// A real tool turn followed by the tool result and its host-issued receipt
	// proves each native HTTP executor can replay admitted state without a shim.
	for _, g := range grants {
		model := models[g.provider]
		first := nativeToolRequest(g.provider, model, false)
		status, records := fixtureInference(t, api.Client(), api.URL, capability, g.provider, model, "same-session-"+string(g.provider), first, nil)
		if status != http.StatusOK {
			t.Fatalf("first %s inference status=%d records=%s", g.provider, status, records)
		}
		done := fixtureDone(t, records)
		if done.Stop != "tool" || len(done.Receipt) == 0 || len(done.State) == 0 {
			t.Fatalf("first %s turn terminal=%s state=%s receipt-present=%t", g.provider, done.Stop, done.State, done.Receipt != "")
		}
		second := nativeToolRequest(g.provider, model, true)
		state := json.RawMessage(done.State)
		replay := []map[string]any{{"state": state, "receipt": done.Receipt}}
		status, secondRecords := fixtureInference(t, api.Client(), api.URL, capability, g.provider, model, "same-session-"+string(g.provider), second, replay)
		if status != http.StatusOK || fixtureDone(t, secondRecords).Stop != "end" {
			t.Fatalf("tool-result replay for %s: status=%d records=%s", g.provider, status, secondRecords)
		}
		if g.provider == contract.ProviderClaude {
			refusal := []byte(strings.Replace(string(nativeToolRequest(g.provider, model, false)), "fixture user prompt", "fixture explicit refusal", 1))
			status, refusalEvents := fixtureInference(t, api.Client(), api.URL, capability, g.provider, model, "refusal-session", refusal, nil)
			if status != http.StatusOK || fixtureDone(t, refusalEvents).Stop != "refusal" {
				t.Fatalf("native refusal status=%d records=%+v", status, refusalEvents)
			}
			truncatedInput := []byte(strings.Replace(string(nativeToolRequest(g.provider, model, false)), "fixture user prompt", "fixture explicit truncation", 1))
			status, truncatedEvents := fixtureInference(t, api.Client(), api.URL, capability, g.provider, model, "truncated-session", truncatedInput, nil)
			if status != http.StatusOK || containsFixtureDone(truncatedEvents) || !containsFixtureError(truncatedEvents) {
				t.Fatalf("truncated native stream status=%d records=%+v", status, truncatedEvents)
			}

			cancelCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cancelInput := []byte(strings.Replace(string(nativeToolRequest(g.provider, model, false)), "fixture user prompt", "fixture cancellation", 1))
			cancelBody, err := json.Marshal(map[string]any{"provider": g.provider, "model": model, "session_id": "cancel-session", "input": json.RawMessage(cancelInput)})
			if err != nil {
				t.Fatal(err)
			}
			cancelReq, err := http.NewRequestWithContext(cancelCtx, http.MethodPost, api.URL+"/v1/profiles/7/infer", bytes.NewReader(cancelBody))
			if err != nil {
				t.Fatal(err)
			}
			cancelReq.Header.Set("Authorization", "Bearer "+capability)
			cancelDone := make(chan error, 1)
			go func() {
				resp, err := api.Client().Do(cancelReq)
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				cancelDone <- err
			}()
			select {
			case <-proxy.cancelStarted:
			case <-time.After(5 * time.Second):
				cancel()
				proxy.releaseCancellation()
				t.Fatal("native upstream did not enter deterministic cancellation gate")
			}
			cancel()
			select {
			case err := <-cancelDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled host inference error=%v, want context cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled host inference did not drain")
			}
			proxy.releaseCancellation()
			select {
			case err := <-proxy.cancelObserved:
				if err == nil {
					t.Fatal("native upstream remained connected after host cancellation")
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					t.Fatalf("native upstream did not observe cancellation before deadline: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("native upstream cancellation gate did not observe disconnect")
			}
		}
		assertNativePreparedRequest(t, proxy.snapshot(), g.provider)

		before := proxy.countInference(g.provider)
		status, denied := fixtureInference(t, api.Client(), api.URL, capability, g.provider, model, "different-session", second, replay)
		if status == http.StatusOK || containsFixtureDone(denied) || proxy.countInference(g.provider) != before {
			t.Fatalf("%s replay bound to another session reached provider: status=%d records=%+v calls=%d->%d", g.provider, status, denied, before, proxy.countInference(g.provider))
		}
		if g.provider == contract.ProviderCodex {
			status, body := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/profiles/8/usage?provider=codex", capability, nil)
			if status != http.StatusOK {
				t.Fatalf("load alternate native account: status=%d body=%s", status, body)
			}
			before = proxy.countInference(g.provider)
			status, denied = fixtureInferenceProfile(t, api.Client(), api.URL, capability, "8", g.provider, model, "same-session-"+string(g.provider), second, replay)
			if status == http.StatusOK || containsFixtureDone(denied) || proxy.countInference(g.provider) != before {
				t.Fatalf("Codex replay bound to another account reached provider: status=%d records=%+v calls=%d->%d", status, denied, before, proxy.countInference(g.provider))
			}
			otherModel := otherModels[g.provider]
			if otherModel == "" {
				t.Fatal("native Codex catalog has no second model for receipt mismatch fixture")
			}
			status, denied = fixtureInference(t, api.Client(), api.URL, capability, g.provider, otherModel, "same-session-"+string(g.provider), nativeToolRequest(g.provider, otherModel, true), replay)
			if status == http.StatusOK || containsFixtureDone(denied) || proxy.countInference(g.provider) != before {
				t.Fatalf("Codex replay bound to another model reached provider: status=%d records=%+v calls=%d->%d", status, denied, before, proxy.countInference(g.provider))
			}
		}
		if g.provider == contract.ProviderAntigravity {
			otherModel := otherModels[g.provider]
			before = proxy.countInference(g.provider)
			status, denied = fixtureInference(t, api.Client(), api.URL, capability, g.provider, otherModel, "same-session-"+string(g.provider), nativeToolRequest(g.provider, otherModel, true), replay)
			if status == http.StatusOK || containsFixtureDone(denied) || proxy.countInference(g.provider) != before {
				t.Fatalf("Antigravity replay bound to another model reached provider: status=%d records=%+v calls=%d->%d", status, denied, before, proxy.countInference(g.provider))
			}
		}
	}

	// Canary and opaque foreign state are denied by the host before the native
	// executor opens its official provider connection.
	for _, g := range grants {
		model := models[g.provider]
		before := proxy.countInference(g.provider)
		canary := []byte(strings.Replace(string(nativeToolRequest(g.provider, model, false)), "fixture user prompt", "ARTEX outbound canary", 1))
		status, _ := fixtureInference(t, api.Client(), api.URL, capability, g.provider, model, "blocked-canary", canary, nil)
		if status == http.StatusOK || proxy.countInference(g.provider) != before {
			t.Fatalf("%s ARTEX canary reached provider: status=%d calls=%d->%d", g.provider, status, before, proxy.countInference(g.provider))
		}
	}
	foreign := []byte(`{"model":"` + models[contract.ProviderCodex] + `","input":[{"type":"message","role":"user","content":"fixture"},{"type":"reasoning","summary":[],"encrypted_content":"foreign-opaque-state"}]}`)
	before := proxy.countInference(contract.ProviderCodex)
	status, _ := fixtureInference(t, api.Client(), api.URL, capability, contract.ProviderCodex, models[contract.ProviderCodex], "foreign-state", foreign, nil)
	if status == http.StatusOK || proxy.countInference(contract.ProviderCodex) != before {
		t.Fatalf("foreign Codex opaque state reached provider: status=%d calls=%d->%d", status, before, proxy.countInference(contract.ProviderCodex))
	}
	binary := []byte(`{"model":"` + models[contract.ProviderAntigravity] + `","contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"AAEC"}}]}]}`)
	before = proxy.countInference(contract.ProviderAntigravity)
	status, _ = fixtureInference(t, api.Client(), api.URL, capability, contract.ProviderAntigravity, models[contract.ProviderAntigravity], "binary-attachment", binary, nil)
	if status == http.StatusOK || proxy.countInference(contract.ProviderAntigravity) != before {
		t.Fatalf("binary attachment reached Antigravity: status=%d calls=%d->%d", status, before, proxy.countInference(contract.ProviderAntigravity))
	}

	archive, err := os.ReadFile(filepath.Join(filepath.Dir(rt.captures.file.Name()), "native-sse.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	foundNativeArtifact, foundThoughtSignature := false, false
	for _, line := range bytes.Split(archive, []byte("\n")) {
		var record privacy.Record
		if len(line) == 0 || json.Unmarshal(line, &record) != nil || record.Provider != contract.ProviderAntigravity || record.Direction != privacy.DirectionResponse {
			continue
		}
		foundNativeArtifact = foundNativeArtifact || bytes.Contains(record.Body, []byte("unknown_native_artifact"))
		foundThoughtSignature = foundThoughtSignature || bytes.Contains(record.Body, []byte("thoughtSignature"))
	}
	if !foundNativeArtifact || !foundThoughtSignature {
		t.Fatalf("private raw native SSE archive lost source artifacts: unknown=%t thoughtSignature=%t", foundNativeArtifact, foundThoughtSignature)
	}
	foundTruncatedRaw := false
	for _, line := range bytes.Split(archive, []byte("\n")) {
		var record privacy.Record
		if len(line) != 0 && json.Unmarshal(line, &record) == nil && record.Provider == contract.ProviderClaude && record.Direction == privacy.DirectionResponse && bytes.Contains(record.Body, []byte("fixture_truncated_native_artifact")) && !record.Complete {
			foundTruncatedRaw = true
		}
	}
	if !foundTruncatedRaw {
		t.Fatal("incomplete upstream native response was not preserved in the private raw archive")
	}
	for _, request := range proxy.snapshot() {
		if strings.Contains(strings.ToLower(string(request.body)), "artex") || strings.Contains(strings.ToLower(request.header.Get("user-agent")), "artex") {
			t.Fatalf("ARTEX identity escaped in final provider request to %s%s", request.host, request.path)
		}
	}
}

type nativeFixtureRequest struct {
	host, path string
	method     string
	header     http.Header
	body       []byte
}

type nativeFixtureProxy struct {
	url               string
	server            *http.Server
	mu                sync.Mutex
	seen              []nativeFixtureRequest
	gen               map[contract.Provider]int
	cancelStarted     chan struct{}
	cancelRelease     chan struct{}
	cancelObserved    chan error
	cancelReleaseOnce sync.Once
	caKey             *rsa.PrivateKey
	ca                *x509.Certificate
}

func newNativeFixtureProxy(t *testing.T) (*nativeFixtureProxy, string, string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Native host fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &nativeFixtureProxy{caKey: caKey, ca: ca, gen: make(map[contract.Provider]int), cancelStarted: make(chan struct{}), cancelRelease: make(chan struct{}), cancelObserved: make(chan error, 1)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.url = "http://" + listener.Addr().String()
	f.server = &http.Server{Handler: http.HandlerFunc(f.connect)}
	go func() { _ = f.server.Serve(listener) }()
	t.Cleanup(func() { _ = f.server.Close(); f.releaseCancellation() })
	return f, f.url, caFile
}
func (f *nativeFixtureProxy) releaseCancellation() {
	f.cancelReleaseOnce.Do(func() { close(f.cancelRelease) })
}

func (f *nativeFixtureProxy) connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = client.Close()
		return
	}
	if err = rw.Flush(); err != nil {
		_ = client.Close()
		return
	}
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = strings.TrimSuffix(r.Host, ":443")
	}
	leaf, err := f.certificate(host)
	if err != nil {
		_ = client.Close()
		return
	}
	conn := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.seen = append(f.seen, nativeFixtureRequest{host: host, path: req.URL.Path, method: req.Method, header: req.Header.Clone(), body: append([]byte(nil), body...)})
		f.mu.Unlock()
		status, headers, response := f.answer(host, req.URL.Path, req.Method, req.Header, body)
		cancel := headers.Get("X-Fixture-Cancel") == "true"
		truncated := headers.Get("X-Fixture-Truncate") == "true"
		headers.Del("X-Fixture-Cancel")
		headers.Del("X-Fixture-Truncate")
		if cancel {
			if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")); err != nil {
				return
			}
			if _, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", len(response), response); err != nil {
				return
			}
			close(f.cancelStarted)
			<-f.cancelRelease
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := br.ReadByte()
			f.cancelObserved <- err
			return
		}
		length := int64(len(response))
		if truncated {
			length += 64
		}
		resp := &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: headers, Body: io.NopCloser(bytes.NewReader(response)), ContentLength: length, Close: false, Request: req}
		if err := resp.Write(conn); err != nil {
			return
		}
	}
}

func (f *nativeFixtureProxy) certificate(host string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func (f *nativeFixtureProxy) answer(host, path, method string, header http.Header, body []byte) (int, http.Header, []byte) {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	if host == "platform.claude.com" && path == "/v1/oauth/token" {
		return 200, h, []byte(`{"access_token":"claude-fresh-access","refresh_token":"claude-fresh-refresh","token_type":"Bearer","expires_in":3600,"account":{"uuid":"claude-account"},"organization":{"uuid":"org-fixture","name":"Fixture"}}`)
	}
	if host == "auth.openai.com" && path == "/oauth/token" {
		return 200, h, []byte(`{"access_token":"codex-fresh-access","refresh_token":"codex-fresh-refresh","id_token":"` + fixtureCodexIDToken() + `","token_type":"Bearer","expires_in":3600}`)
	}
	if host == "oauth2.googleapis.com" && path == "/token" {
		return 200, h, []byte(`{"access_token":"gemini-fresh-access","refresh_token":"gemini-fresh-refresh","expires_in":3600}`)
	}
	if host == "api.anthropic.com" && path == "/api/oauth/usage" {
		return 200, h, []byte(`{"plan":"max","five_hour":{"utilization":23,"resets_at":"2026-10-31T00:00:00Z"},"seven_day":{"utilization":41}}`)
	}
	if host == "chatgpt.com" && path == "/backend-api/wham/usage" {
		return 200, h, []byte(`{"plan_type":"pro","rate_limit":{"primary_window":{"used_percent":31,"limit_window_seconds":18000,"reset_at":1793400000},"secondary_window":{"used_percent":12,"limit_window_seconds":604800,"reset_after_seconds":3600}}}`)
	}
	if host == "daily-cloudcode-pa.googleapis.com" && path == "/v1internal:retrieveUserQuotaSummary" {
		return http.StatusOK, h, []byte(`{"plan":"fixture","buckets":[{"bucketId":"fixture-five-hour","displayName":"5-hour quota","remainingFraction":0.25,"resetTime":"2026-10-31T00:00:00Z"}]}`)
	}
	if host == "daily-cloudcode-pa.googleapis.com" && path == "/v1internal:fetchAvailableModels" {
		return http.StatusOK, h, []byte(`{"buckets":[{"bucketId":"fixture-five-hour","displayName":"5-hour quota","remainingFraction":0.25}]}`)
	}
	provider := providerForFixtureHost(host)
	if provider == "" {
		return http.StatusForbidden, h, []byte(`{"error":"unmapped fixture origin"}`)
	}
	if auth := header.Get("Authorization"); strings.Contains(auth, "-old-access") {
		return http.StatusUnauthorized, h, []byte(`{"error":{"type":"authentication_error","message":"token expired"}}`)
	}
	switch provider {
	case contract.ProviderClaude:
		if path == "/api/oauth/profile" {
			return http.StatusOK, h, []byte(`{"account":{"uuid":"claude-account","email_address":"claude@example.invalid"}}`)
		}
		if path != "/v1/messages" {
			return http.StatusNotFound, h, []byte(`{}`)
		}
	case contract.ProviderCodex:
		if path != "/backend-api/codex/responses" {
			return http.StatusNotFound, h, []byte(`{}`)
		}
	case contract.ProviderAntigravity:
		if !strings.Contains(path, "streamGenerateContent") {
			return http.StatusNotFound, h, []byte(`{}`)
		}
	}
	if provider == contract.ProviderClaude {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusUnauthorized, http.StatusForbidden} {
			if bytes.Contains(body, []byte(fmt.Sprintf("fixture upstream status %d", status))) {
				h.Set("Content-Type", "application/json")
				return status, h, []byte(`{"error":{"message":"fixture-secret-provider-detail","type":"api_error","code":"quota_exhausted"}}`)
			}
		}
	}
	f.mu.Lock()
	f.gen[provider]++
	f.mu.Unlock()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	if provider == contract.ProviderClaude && bytes.Contains(body, []byte("fixture explicit refusal")) {
		return http.StatusOK, h, []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-fixture-refusal\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"fixture\",\"content\":[],\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"I cannot help with that request.\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}
	if provider == contract.ProviderClaude && bytes.Contains(body, []byte("fixture explicit truncation")) {
		h.Set("X-Fixture-Truncate", "true")
		return http.StatusOK, h, []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-fixture-truncated\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"fixture\",\"content\":[],\"usage\":{\"input_tokens\":1}},\"unknown_native_artifact\":\"fixture_truncated_native_artifact\"}\n\n")
	}
	if provider == contract.ProviderClaude && bytes.Contains(body, []byte("fixture cancellation")) {
		h.Set("X-Fixture-Cancel", "true")
		return http.StatusOK, h, []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-fixture-cancel\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"fixture\",\"content\":[],\"usage\":{\"input_tokens\":1}}}\n\n")
	}
	isResult := bytes.Contains(body, []byte("tool_result")) || bytes.Contains(body, []byte("function_call_output")) || bytes.Contains(body, []byte("functionResponse"))
	return http.StatusOK, h, nativeFixtureSSE(provider, isResult)
}

func providerForFixtureHost(host string) contract.Provider {
	switch host {
	case "api.anthropic.com":
		return contract.ProviderClaude
	case "chatgpt.com":
		return contract.ProviderCodex
	case "daily-cloudcode-pa.googleapis.com":
		return contract.ProviderAntigravity
	default:
		return ""
	}
}

func nativeFixtureSSE(p contract.Provider, result bool) []byte {
	if result {
		switch p {
		case contract.ProviderClaude:
			return []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-fixture-end\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"fixture\",\"content\":[],\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"finished\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		case contract.ProviderCodex:
			return []byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-fixture-end\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"fixture\",\"output\":[{\"type\":\"message\",\"id\":\"msg-end\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"finished\"}]}],\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\n")
		default:
			return []byte("data: {\"response\":{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"finished\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":1,\"totalTokenCount\":3},\"unknown_native_artifact\":{\"preserve\":true}}}\n\n")
		}
	}
	switch p {
	case contract.ProviderClaude:
		return []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-fixture-tool\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"fixture\",\"content\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call-fixture\",\"name\":\"lookup\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\\\"fixture\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	case contract.ProviderCodex:
		return []byte("data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc-fixture\",\"call_id\":\"call-fixture\",\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\\\"fixture\\\"}\",\"status\":\"completed\"}}\n" +
			"data: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"type\":\"reasoning\",\"id\":\"rs-fixture\",\"summary\":[],\"encrypted_content\":\"" + fixtureCodexEncryptedContent(2) + "\"}}\n" +
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-fixture-tool\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"fixture\",\"output\":[{\"type\":\"reasoning\",\"id\":\"rs-fixture\",\"summary\":[],\"encrypted_content\":\"" + fixtureCodexEncryptedContent(2) + "\"},{\"type\":\"function_call\",\"id\":\"fc-fixture\",\"call_id\":\"call-fixture\",\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\\\"fixture\\\"}\"}],\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n")
	default:
		return []byte("data: {\"response\":{\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"id\":\"call-fixture\",\"name\":\"lookup\",\"args\":{\"q\":\"fixture\"}},\"thoughtSignature\":\"EjQKMgEMOdbHO0Gd+c9Mxk4ELwPGbpCEcp2mFfYYLix2UVtBH3fL8GECc4+JITVnHF4qZDsA\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2,\"thoughtsTokenCount\":1,\"totalTokenCount\":5},\"unknown_native_artifact\":{\"preserve\":true}}}\n\n")
	}
}

func (f *nativeFixtureProxy) snapshot() []nativeFixtureRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]nativeFixtureRequest, len(f.seen))
	copy(out, f.seen)
	return out
}

func (f *nativeFixtureProxy) countHostPath(host, path string) int {
	count := 0
	for _, r := range f.snapshot() {
		if r.host == host && r.path == path {
			count++
		}
	}
	return count
}

func (f *nativeFixtureProxy) countInference(p contract.Provider) int {
	count := 0
	for _, r := range f.snapshot() {
		if providerForFixtureHost(r.host) != p || r.method != http.MethodPost {
			continue
		}
		switch p {
		case contract.ProviderClaude:
			if r.path == "/v1/messages" {
				count++
			}
		case contract.ProviderCodex:
			if strings.HasSuffix(r.path, "/responses") {
				count++
			}
		case contract.ProviderAntigravity:
			if strings.Contains(r.path, "streamGenerateContent") {
				count++
			}
		}
	}
	return count
}

func fixtureRequest(t *testing.T, client *http.Client, method, target, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, result
}

type fixtureEvent struct {
	Type     string          `json:"type"`
	Code     string          `json:"code"`
	Message  string          `json:"message"`
	Stop     string          `json:"stop"`
	State    json.RawMessage `json:"state"`
	Receipt  string          `json:"receipt"`
	Response json.RawMessage `json:"response"`
	Data     string          `json:"data"`
}

func fixtureInference(t *testing.T, client *http.Client, host, token string, p contract.Provider, model, session string, input []byte, replay []map[string]any) (int, []fixtureEvent) {
	t.Helper()
	return fixtureInferenceProfile(t, client, host, token, "7", p, model, session, input, replay)
}

func fixtureInferenceProfile(t *testing.T, client *http.Client, host, token, profile string, p contract.Provider, model, session string, input []byte, replay []map[string]any) (int, []fixtureEvent) {
	t.Helper()
	value := map[string]any{"provider": p, "model": model, "session_id": session, "input": json.RawMessage(input), "replay": replay}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := fixtureRequest(t, client, http.MethodPost, host+"/v1/profiles/"+profile+"/infer", token, body)
	var events []fixtureEvent
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var event fixtureEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode host inference record %q: %v", scanner.Text(), err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return status, events
}

func fixtureDone(t *testing.T, events []fixtureEvent) fixtureEvent {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == "done" {
			return events[i]
		}
	}
	t.Fatalf("no done record in host inference stream: %+v", events)
	return fixtureEvent{}
}
func containsFixtureDone(events []fixtureEvent) bool {
	for _, event := range events {
		if event.Type == "done" {
			return true
		}
	}
	return false
}
func containsFixtureError(events []fixtureEvent) bool {
	for _, event := range events {
		if event.Type == "error" {
			return true
		}
	}
	return false
}

func assertNativePreparedRequest(t *testing.T, requests []nativeFixtureRequest, p contract.Provider) {
	t.Helper()
	for i := len(requests) - 1; i >= 0; i-- {
		r := requests[i]
		if providerForFixtureHost(r.host) != p || r.method != http.MethodPost {
			continue
		}
		switch p {
		case contract.ProviderClaude:
			if r.path != "/v1/messages" {
				continue
			}
			if !bytes.Contains(r.body, []byte(`"thinking"`)) || !strings.HasPrefix(r.header.Get("User-Agent"), "claude-cli/") || !bytes.Contains(r.body, []byte("You are Claude Code, Anthropic's official CLI for Claude.")) || !bytes.Contains(r.body, []byte("fixture caller-owned system")) {
				t.Fatalf("Claude final request lost thinking, hard-cloak identity, or caller system text: %s headers=%v", r.body, r.header)
			}
		case contract.ProviderCodex:
			if !strings.HasSuffix(r.path, "/responses") {
				continue
			}
			if !bytes.Contains(r.body, []byte(`"reasoning"`)) || !bytes.Contains(r.body, []byte(`"high"`)) || r.header.Get("User-Agent") != "codex-tui/0.154.0 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.154.0)" || r.header.Get("Originator") != "codex-tui" {
				t.Fatalf("Codex final request lost reasoning or hard-cloak identity: %s headers=%v", r.body, r.header)
			}
		case contract.ProviderAntigravity:
			if !strings.Contains(r.path, "streamGenerateContent") {
				continue
			}
			if !bytes.Contains(r.body, []byte("thinking")) || !bytes.Contains(r.body, []byte("high")) || !bytes.Contains(r.body, []byte(`"userAgent":"antigravity"`)) {
				t.Fatalf("Antigravity final request lost thinking or source-native default identity: %s headers=%v", r.body, r.header)
			}
		}
		return
	}
	t.Fatalf("no final native provider request observed for %s", p)
}

func nativeToolRequest(p contract.Provider, model string, result bool) []byte {
	switch p {
	case contract.ProviderClaude:
		messages := `[{"role":"user","content":"fixture user prompt"}]`
		if result {
			messages = `[{"role":"user","content":"fixture user prompt"},{"role":"assistant","content":[{"type":"tool_use","id":"call-fixture","name":"lookup","input":{"q":"fixture"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-fixture","content":"tool result"}]}]`
		}
		return []byte(`{"model":"` + model + `","max_tokens":128,"system":"fixture caller-owned system","thinking":{"type":"enabled","budget_tokens":1024},"tools":[{"name":"lookup","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}],"messages":` + messages + `}`)
	case contract.ProviderCodex:
		input := `[{"type":"message","role":"user","content":"fixture user prompt"}]`
		if result {
			input = `[{"type":"message","role":"user","content":"fixture user prompt"},{"type":"function_call","call_id":"call-fixture","name":"lookup","arguments":"{\"q\":\"fixture\"}"},{"type":"function_call_output","call_id":"call-fixture","output":"tool result"}]`
		}
		return []byte(`{"model":"` + model + `","input":` + input + `,"reasoning":{"effort":"high","summary":"detailed"},"tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}]}`)
	default:
		contents := `[{"role":"user","parts":[{"text":"fixture user prompt"}]}]`
		if result {
			contents = `[{"role":"user","parts":[{"text":"fixture user prompt"}]},{"role":"model","parts":[{"functionCall":{"id":"call-fixture","name":"lookup","args":{"q":"fixture"}},"thoughtSignature":"EjQKMgEMOdbHO0Gd+c9Mxk4ELwPGbpCEcp2mFfYYLix2UVtBH3fL8GECc4+JITVnHF4qZDsA"}]},{"role":"function","parts":[{"functionResponse":{"id":"call-fixture","name":"lookup","response":{"result":"tool result"}}}]}]`
		}
		return []byte(`{"model":"` + model + `","contents":` + contents + `,"generationConfig":{"thinkingConfig":{"thinkingLevel":"high"}},"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}]}]}`)
	}
}

func fixtureCodexEncryptedContent(seed byte) string {
	payload := make([]byte, 1+8+16+16+32)
	payload[0] = 0x80
	for i := 9; i < len(payload); i++ {
		payload[i] = seed + byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func fixtureCodexIDToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"email": "codex@example.invalid", "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "codex-account", "chatgpt_plan_type": "pro"}})
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + "."
}

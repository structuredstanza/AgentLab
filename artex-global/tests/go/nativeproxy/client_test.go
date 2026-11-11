package nativeproxy_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
)

func proxyServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestNewFromEnvUnsetIsUnavailable(t *testing.T) {
	t.Setenv("ARTEX_NATIVE_PROXY_URL", "")
	c, err := nativeproxy.NewFromEnv()
	if c != nil || err != nil {
		t.Fatalf("NewFromEnv() = %v, %v; want nil, nil", c, err)
	}
}

func TestNewFromEnvReadsTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(" tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q; want bearer from trimmed token file", got)
		}
		_, _ = io.WriteString(w, "")
	})
	t.Setenv("ARTEX_NATIVE_PROXY_URL", srv.URL)
	t.Setenv("ARTEX_NATIVE_PROXY_TOKEN_FILE", path)
	c, err := nativeproxy.NewFromEnv()
	if err != nil || c == nil {
		t.Fatalf("NewFromEnv() = %v, %v", c, err)
	}
	if _, err := c.Infer(context.Background(), "7", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestNewFromEnvRequiresTokenFileWhenURLSet(t *testing.T) {
	t.Setenv("ARTEX_NATIVE_PROXY_URL", "http://127.0.0.1:1")
	t.Setenv("ARTEX_NATIVE_PROXY_TOKEN_FILE", "")
	if _, err := nativeproxy.NewFromEnv(); err == nil {
		t.Fatal("NewFromEnv() with URL but no token file: want error")
	}
}

func TestNewRejectsUnsafeInputs(t *testing.T) {
	cases := map[string][2]string{
		"query":       {"http://127.0.0.1:1?x=1", "tok"},
		"credentials": {"http://u:p@127.0.0.1:1", "tok"},
		"scheme":      {"ftp://127.0.0.1:1", "tok"},
		"empty token": {"http://127.0.0.1:1", ""},
	}
	for name, c := range cases {
		if _, err := nativeproxy.New(c[0], c[1]); err == nil {
			t.Errorf("%s: New(%q) succeeded; want error", name, c[0])
		}
	}
}
func TestPollDecodesStructuredLoginPrompt(t *testing.T) {
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/profiles/7/login/sid-1" {
			t.Errorf("request = %s %s; want GET /v1/profiles/7/login/sid-1", r.Method, r.URL.EscapedPath())
		}
		_, _ = io.WriteString(w, `{"status":"pending","prompt":{"message":"Enter the verification code"}}`)
	})
	c, err := nativeproxy.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := c.Poll(context.Background(), "7", "sid-1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Prompt == nil || sess.Prompt.Message != "Enter the verification code" {
		t.Fatalf("prompt = %#v; want structured message", sess.Prompt)
	}
}

func TestInferPostsBodyToProfileInferPath(t *testing.T) {
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/profiles/7/infer" {
			t.Errorf("request = %s %s; want POST /v1/profiles/7/infer", r.Method, r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token on native proxy request")
		}
		if r.Header.Get("Accept") != "application/x-ndjson" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	})
	c, err := nativeproxy.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Infer(context.Background(), "7", []byte(`{"provider":"claude"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != `{"provider":"claude"}` {
		t.Fatalf("echoed body = %q", got)
	}
}

func TestInferNon2xxReturnsSafeCodeOnly(t *testing.T) {
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":{"code":"upstream_failed","message":"upstream service failed"},"detail":"secret provider prose"}`)
	})
	c, err := nativeproxy.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Infer(context.Background(), "7", []byte(`{}`))
	var be *nativeproxy.Error
	if !errors.As(err, &be) {
		t.Fatalf("err = %v; want *Error", err)
	}
	if be.Status != http.StatusBadGateway || be.Code != "upstream_failed" {
		t.Fatalf("Error = %+v; want status 502 code upstream_failed", be)
	}
	if strings.Contains(err.Error(), "secret provider prose") {
		t.Fatalf("error leaked provider prose: %v", err)
	}
}
func TestInferNon2xxRejectsUnsafeErrorCodeProse(t *testing.T) {
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":{"code":"bad raw upstream token with spaces and prose"}}`)
	})
	c, err := nativeproxy.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Infer(context.Background(), "7", []byte(`{}`))
	var be *nativeproxy.Error
	if !errors.As(err, &be) {
		t.Fatalf("err = %v; want *Error", err)
	}
	if be.Code != "proxy_error" {
		t.Fatalf("code = %q; want proxy_error for unsafe error code prose", be.Code)
	}
}

func TestProfileIDIsEscapedAsOneSegment(t *testing.T) {
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/v1/profiles/a%2F..%2Fb/infer" {
			t.Errorf("escaped path = %q; want one escaped profile segment", got)
		}
	})
	c, err := nativeproxy.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Infer(context.Background(), "a/../b", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestModelsUsesRootLocalCatalogRoute(t *testing.T) {
	srv := proxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" || r.URL.Query().Get("provider") != "claude" {
			t.Errorf("request = %s %s?%s; want GET /v1/models?provider=claude", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"models":[{"id":"m","name":"Model","context_window":1234,"supported_efforts":["high"]}]}`)
	})
	c, err := nativeproxy.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	models, err := c.Models(context.Background(), "claude")
	if err != nil || len(models) != 1 || models[0].ID != "m" || models[0].ContextWindow == nil || *models[0].ContextWindow != 1234 {
		t.Fatalf("Models() = %+v, %v", models, err)
	}
}

func TestInferRejectsBodiesAboveHostLimit(t *testing.T) {
	c, err := nativeproxy.New("http://127.0.0.1:1", "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Infer(context.Background(), "7", make([]byte, nativeproxy.MaxInferenceBodyBytes+1))
	if err == nil || !strings.Contains(err.Error(), "8 MiB") {
		t.Fatalf("oversized inference body error = %v", err)
	}
}

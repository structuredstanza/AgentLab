package sdkbridge

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
)

func bridgeServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestNewFromEnvUnsetIsUnavailable(t *testing.T) {
	t.Setenv("ARTEX_SDK_BRIDGE_URL", "")
	c, err := NewFromEnv()
	if c != nil || err != nil {
		t.Fatalf("NewFromEnv() = %v, %v; want nil, nil", c, err)
	}
}

func TestNewFromEnvReadsTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(" tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := bridgeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q; want bearer from trimmed token file", got)
		}
		_, _ = io.WriteString(w, "")
	})
	t.Setenv("ARTEX_SDK_BRIDGE_URL", srv.URL)
	t.Setenv("ARTEX_SDK_BRIDGE_TOKEN_FILE", path)
	c, err := NewFromEnv()
	if err != nil || c == nil {
		t.Fatalf("NewFromEnv() = %v, %v", c, err)
	}
	if _, err := c.Infer(context.Background(), "7", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestNewFromEnvRequiresTokenFileWhenURLSet(t *testing.T) {
	t.Setenv("ARTEX_SDK_BRIDGE_URL", "http://127.0.0.1:1")
	t.Setenv("ARTEX_SDK_BRIDGE_TOKEN_FILE", "")
	if _, err := NewFromEnv(); err == nil {
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
		if _, err := New(c[0], c[1]); err == nil {
			t.Errorf("%s: New(%q) succeeded; want error", name, c[0])
		}
	}
}

func TestInferPostsBodyToProfileInferPath(t *testing.T) {
	srv := bridgeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/profiles/7/infer" {
			t.Errorf("request = %s %s; want POST /v1/profiles/7/infer", r.Method, r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token on bridge request")
		}
		if r.Header.Get("Accept") != "application/x-ndjson" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	})
	c, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Infer(context.Background(), "7", []byte(`{"provider":"anthropic"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != `{"provider":"anthropic"}` {
		t.Fatalf("echoed body = %q", got)
	}
}

func TestInferNon2xxReturnsSafeCodeOnly(t *testing.T) {
	srv := bridgeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"upstream_failed","detail":"secret provider prose"}`)
	})
	c, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Infer(context.Background(), "7", []byte(`{}`))
	var be *Error
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

func TestProfileIDIsEscapedAsOneSegment(t *testing.T) {
	srv := bridgeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/v1/profiles/a%2F..%2Fb/infer" {
			t.Errorf("escaped path = %q; want one escaped profile segment", got)
		}
	})
	c, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Infer(context.Background(), "a/../b", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

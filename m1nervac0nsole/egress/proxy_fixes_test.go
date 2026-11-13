package egress

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newH2TestProxy builds a proxy whose client trusts only the proxy CA.
func newH2TestProxy(t *testing.T, p *Proxy) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CA.PEM()) {
		t.Fatal("proxy CA is not a valid PEM certificate")
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(mustURL(p.Addr())),
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: false, // the client speaks HTTP/1.1; the proxy picks upstream ALPN
	}}
}

// An origin that negotiates h2 must be reached.
//
// The proxy re-dialled with NextProtos=[http/1.1] to force HTTP/1.1, but the
// uTLS Chrome preset carries its own ALPN extension, so the preset's list won
// and the second handshake negotiated h2 again — after which an HTTP/1.1
// request over an h2 connection was dropped by the server (read: EOF, 502).
// Every h2-capable origin, i.e. most of the TLS web, was unreachable.
func TestProxyReachesHTTP2Origin(t *testing.T) {
	var sawUA, sawProto string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUA = r.Header.Get("User-Agent")
		sawProto = r.Proto
		io.WriteString(w, "h2-ok")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	p := newTestProxy(t, nil)
	client := newH2TestProxy(t, p)

	resp, err := client.Get(origin.URL + "/h2")
	if err != nil {
		t.Fatalf("request to an h2 origin failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "h2-ok" {
		t.Fatalf("body = %q, want h2-ok", body)
	}
	if sawProto != "HTTP/2.0" {
		t.Errorf("origin saw %s, want HTTP/2.0 (the proxy must speak h2, not re-dial)", sawProto)
	}
	if sawUA != p.Identity.UserAgent {
		t.Errorf("origin saw User-Agent %q, want the engagement identity", sawUA)
	}
}

// The identity's headers are replaced, but the caller's credentials must reach
// the origin. An allowlist used to drop X-API-Key, X-Auth-Token, SOAPAction and
// every vendor X-* header, so an authenticated request got 401 through the proxy
// and 200 without it — a silent change to what the tool was testing.
func TestCallerCredentialsReachTheOrigin(t *testing.T) {
	in := [][2]string{
		{"X-API-Key", "secret-value"},
		{"X-Auth-Token", "tok"},
		{"SOAPAction", "urn:op"},
		{"X-Vendor-Anything", "v"},
		{"Authorization", "Bearer abc"},
		{"Cookie", "session=1"},
		// Identity-owned: must be replaced, never forwarded.
		{"User-Agent", "sqlmap/1.7"},
		{"Accept", "text/sqlmap"},
		{"Sec-Fetch-Mode", "cors"},
		{"Accept-Language", "ko-KR"},
	}
	got := canonicalHeaders(chromeWindows, "GET", "example.com", "/", in)
	seen := map[string]string{}
	for _, kv := range got {
		seen[strings.ToLower(kv[0])] = kv[1]
	}

	for key, want := range map[string]string{
		"x-api-key":         "secret-value",
		"x-auth-token":      "tok",
		"soapaction":        "urn:op",
		"x-vendor-anything": "v",
		"authorization":     "Bearer abc",
		"cookie":            "session=1",
	} {
		if seen[key] != want {
			t.Errorf("%s = %q, want %q (the caller's credential must survive)", key, seen[key], want)
		}
	}
	for key, banned := range map[string]string{
		"user-agent":      "sqlmap/1.7",
		"accept":          "text/sqlmap",
		"sec-fetch-mode":  "cors",
		"accept-language": "ko-KR",
	} {
		if seen[key] == banned {
			t.Errorf("%s was forwarded from the caller (%q); the identity must win", key, banned)
		}
	}
	if seen["user-agent"] != chromeWindows.UserAgent {
		t.Errorf("user-agent = %q, want the engagement identity", seen["user-agent"])
	}
}

// A plain-HTTP proxy request carries no port, and dialling a bare host fails
// with "missing port in address" — so every http:// request returned 502.
func TestDialAuthorityFillsTheSchemeDefault(t *testing.T) {
	cases := map[string]string{
		"http://example.com/":            "example.com:80",
		"https://example.com/":           "example.com:443",
		"http://example.com:8080/":       "example.com:8080",
		"https://example.com:8443/x":     "example.com:8443",
		"http://[2001:db8::1]/":          "[2001:db8::1]:80",
		"http://[2001:db8::1]:8080/path": "[2001:db8::1]:8080",
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := dialAuthority(u); got != want {
			t.Errorf("dialAuthority(%q) = %q, want %q", raw, got, want)
		}
	}
}

// An existing but unreadable CA must not be silently replaced: the guest points
// every tool's trust store at ca.pem, so a new CA there breaks all HTTPS.
func TestCAIsNotSilentlyReplaced(t *testing.T) {
	dir := t.TempDir()
	// A complete, valid pair loads.
	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("reload of an intact CA failed: %v", err)
	}
	if string(again.PEM()) != string(first.PEM()) {
		t.Fatal("the CA changed between loads")
	}

	// A truncated key must be an error, and ca.pem must survive untouched.
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	certBefore, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("an unreadable ca.key was accepted; the CA would have been replaced")
	}
	certAfter, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if string(certBefore) != string(certAfter) {
		t.Fatal("ca.pem was overwritten after a failed load")
	}

	// A missing key is the same story.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("a missing ca.key was treated as first use")
	}
}

// A key from a different CA parses cleanly but signs leaves nothing can verify.
func TestCAMismatchedPairIsRejected(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	if _, err := LoadOrCreateCA(dirA); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dirB); err != nil {
		t.Fatal(err)
	}
	// Take B's key with A's certificate.
	keyB, err := os.ReadFile(filepath.Join(dirB, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA, "ca.key"), keyB, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dirA); err == nil {
		t.Fatal("a key from a different CA was accepted")
	}
}

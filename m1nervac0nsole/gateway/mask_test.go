package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
)

// originSees sends one request through the real round trip at level and
// returns the headers the origin received.
func originSees(t *testing.T, level MaskLevel, method string, body io.Reader, set map[string]string) http.Header {
	t.Helper()
	got := make(chan http.Header, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) {
		c.MaskFor = func(netpolicy.Session) MaskLevel { return level }
	})
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	uc, _, err := tr.Handshake(context.Background(), connCtx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	defer uc.Close()

	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+"/x", body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range set {
		req.Header.Set(k, v)
	}
	res, err := tr.RoundTrip(context.Background(), connCtx, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	select {
	case h := <-got:
		return h
	default:
		t.Fatalf("origin was not reached: status %d", res.StatusCode)
		return nil
	}
}

// The mask must leave a body-carrying API call alone: its Content-Type and
// Accept are the caller's, and a navigation header would misdescribe it.
func TestMaskLeavesAPIPostAlone(t *testing.T) {
	h := originSees(t, MaskNavigation, http.MethodPost, strings.NewReader("{}"), map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/vnd.api+json",
	})
	if h.Get("Content-Type") != "application/json" || h.Get("Accept") != "application/vnd.api+json" {
		t.Errorf("Content-Type/Accept changed: %v", h)
	}
	if h.Get("Sec-Fetch-Mode") != "" {
		t.Errorf("POST got Sec-Fetch-Mode %q", h.Get("Sec-Fetch-Mode"))
	}
}

// A User-Agent that is not a tool default is the caller's choice at every level.
func TestMaskKeepsNonToolUserAgent(t *testing.T) {
	const ua = "() { :; }; echo x"
	for _, level := range []MaskLevel{MaskUA, MaskNavigation} {
		h := originSees(t, level, http.MethodGet, nil, map[string]string{"User-Agent": ua})
		if got := h.Get("User-Agent"); got != ua {
			t.Errorf("%s: User-Agent = %q, want it unchanged", level, got)
		}
	}
}

func TestMaskReplacesToolUserAgent(t *testing.T) {
	for _, ua := range []string{"curl/8.5.0", "Fuzz Faster U Fool v2.1.0"} {
		h := originSees(t, MaskUA, http.MethodGet, nil, map[string]string{"User-Agent": ua})
		if got := h.Get("User-Agent"); got != useragent.Get() {
			t.Errorf("%s: User-Agent = %q, want %q", ua, got, useragent.Get())
		}
		if h.Get("Sec-Ch-Ua") == "" || h.Get("Sec-Fetch-Mode") != "" {
			t.Errorf("%s: ua level must add sec-ch-ua and nothing navigational: %v", ua, h)
		}
	}
	h := originSees(t, MaskUA, http.MethodGet, nil, map[string]string{"User-Agent": "curl/8.5.0", "Sec-Ch-Ua": "mine"})
	if h.Get("Sec-Ch-Ua") != "mine" {
		t.Errorf("sec-ch-ua = %q, want the caller's kept", h.Get("Sec-Ch-Ua"))
	}
}

func TestMaskNavigationFillsChromeHeaders(t *testing.T) {
	h := originSees(t, MaskNavigation, http.MethodGet, nil, nil)
	for k, v := range map[string]string{
		"Upgrade-Insecure-Requests": "1", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Language": "en-US,en;q=0.9",
		"Accept": navAccept, "User-Agent": useragent.Get(),
	} {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
}

func TestMaskNoneChangesNothing(t *testing.T) {
	h := originSees(t, MaskNone, http.MethodGet, nil, map[string]string{"User-Agent": "curl/8.5.0"})
	if h.Get("User-Agent") != "curl/8.5.0" || h.Get("Sec-Fetch-Mode") != "" || h.Get("Sec-Ch-Ua") != "" {
		t.Errorf("MaskNone altered the request: %v", h)
	}
}

// A WebSocket upgrade is consumed before RoundTrip (prepare strips the
// hop-by-hop Upgrade/Connection from every request the transport forwards), so
// it cannot be driven through RoundTrip to an origin. What the mask owes an
// upgrade is to leave it alone and not make it look like a page load.
func TestMaskNavigationLeavesUpgradeAlone(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("User-Agent", "curl/8.5.0")
	applyMask(MaskNavigation, req)
	if req.Header.Get("Upgrade") != "websocket" || req.Header.Get("Connection") != "Upgrade" {
		t.Errorf("mask touched Upgrade/Connection: %v", req.Header)
	}
	if req.Header.Get("Sec-Fetch-Mode") != "" || req.Header.Get("Accept") != "" {
		t.Errorf("upgrade request got navigation headers: %v", req.Header)
	}
	if req.Header.Get("User-Agent") != useragent.Get() {
		t.Errorf("tool UA kept on an upgrade: %q", req.Header.Get("User-Agent"))
	}

	// Connection-only upgrade signalling is an upgrade too.
	req = httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
	req.Header.Set("Connection", "keep-alive, Upgrade")
	applyMask(MaskNavigation, req)
	if req.Header.Get("Sec-Fetch-Mode") != "" {
		t.Errorf("Connection: Upgrade request got navigation headers")
	}

	// prepare runs the mask before it strips, so the upgrade is seen as one.
	req = httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	if out := prepare(req, MaskNavigation); out.Header.Get("Sec-Fetch-Mode") != "" {
		t.Errorf("prepare treated an upgrade as a navigation: %v", out.Header)
	}
}

func TestMaskNavigationAddsNoAcceptEncoding(t *testing.T) {
	h := originSees(t, MaskNavigation, http.MethodGet, nil, nil)
	// Go's transport adds gzip itself only when the caller left it unset and
	// reads the body back transparently; the mask must not add anything wider.
	if ae := h.Get("Accept-Encoding"); strings.Contains(ae, "br") || strings.Contains(ae, "zstd") {
		t.Errorf("Accept-Encoding = %q, mask added a coding the client did not ask for", ae)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	applyMask(MaskNavigation, req)
	if _, ok := req.Header["Accept-Encoding"]; ok {
		t.Errorf("applyMask added Accept-Encoding: %v", req.Header)
	}
}

// Client hints describe the built-in Chrome; with another UA they are omitted.
func TestMaskHintsOnlyForBuiltInUserAgent(t *testing.T) {
	prev := useragent.Get()
	defer useragent.Set(prev)

	useragent.Set(useragent.Default)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	applyMask(MaskUA, req)
	if req.Header.Get("Sec-Ch-Ua") == "" {
		t.Errorf("built-in UA: hints missing")
	}

	useragent.Set("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0")
	req = httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	applyMask(MaskUA, req)
	if req.Header.Get("User-Agent") != useragent.Get() {
		t.Errorf("UA not replaced: %q", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("Sec-Ch-Ua") != "" || req.Header.Get("Sec-Ch-Ua-Platform") != "" {
		t.Errorf("overridden UA got Chrome hints: %v", req.Header)
	}
}

// A CONNECT to an IP literal carries no SNI; the handshake must still verify
// the authorized authority instead of failing on an empty ServerName.
func TestHandshakeWithoutSNIUsesAuthority(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	var asked atomic.Value
	tr := newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) {
		c.CertException = func(_ netpolicy.Session, name string) bool { asked.Store(name); return true }
	})
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	uc, _, err := tr.Handshake(context.Background(), connCtx, conn, "")
	if err != nil {
		t.Fatalf("Handshake without SNI: %v", err)
	}
	uc.Close()
	if got, _ := asked.Load().(string); got != "127.0.0.1" {
		t.Errorf("CertException asked about %q, want the authority 127.0.0.1", got)
	}
}

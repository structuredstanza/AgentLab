package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The proxy's whole purpose is that one identity reaches the origin, so the
// tests assert what the origin receives rather than what the caller sent.
func TestProxyReplacesToolUserAgentAndHeaders(t *testing.T) {
	var got http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	body := proxyGet(t, p, origin.URL+"/path?q=1")

	if body != "ok" {
		t.Fatalf("body = %q", body)
	}
	if ua := got.Get("User-Agent"); ua != p.Identity.UserAgent {
		t.Fatalf("origin saw User-Agent %q, want the engagement identity", ua)
	}
	// A tool's own fingerprinting headers must not survive the proxy.
	for _, leak := range []string{"Go-http-client", "curl", "python"} {
		if strings.Contains(got.Get("User-Agent"), leak) {
			t.Errorf("User-Agent still names the client: %q", got.Get("User-Agent"))
		}
	}
	for _, want := range []string{"Sec-Ch-Ua", "Sec-Fetch-Mode", "Accept-Language", "Accept-Encoding"} {
		if got.Get(want) == "" {
			t.Errorf("origin did not receive %s; the request is not browser-shaped", want)
		}
	}
}

// Header order is part of the fingerprint, so the emitted order must be Chrome's
// and not Go's sorted order. The origin is a raw listener here because
// httptest parses the request into a map and discards the order under test.
func TestForwardedHeaderOrderIsChromeNotSorted(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	captured := make(chan string, 1)
	go func() {
		conn, err := raw.Accept()
		if err != nil {
			captured <- ""
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			head.WriteString(line)
			if trimCRLF(line) == "" {
				break
			}
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		captured <- head.String()
	}()

	p := newTestProxy(t, nil)
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET http://"+raw.Addr().String()+"/ HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n")
	bufio.NewReader(conn).ReadString('\n')

	out := <-captured
	if out == "" {
		t.Fatal("the origin received no request")
	}
	want := []string{"Host:", "Connection:", "sec-ch-ua:", "sec-ch-ua-mobile:", "sec-ch-ua-platform:",
		"Upgrade-Insecure-Requests:", "User-Agent:", "Accept:", "Sec-Fetch-Site:", "Sec-Fetch-Mode:",
		"Sec-Fetch-User:", "Sec-Fetch-Dest:", "Accept-Encoding:", "Accept-Language:"}
	pos := -1
	for _, w := range want {
		at := strings.Index(out, "\r\n"+w)
		if at < 0 {
			t.Fatalf("header %q missing from the forwarded request:\n%s", w, out)
		}
		if at < pos {
			t.Fatalf("header %q is out of Chrome's order:\n%s", w, out)
		}
		pos = at
	}
	if strings.Contains(out, "curl/7.88.1") {
		t.Fatal("the caller's User-Agent survived into the forwarded request")
	}
}

// A CONNECT tunnel must be terminated, not passed through: that is the only way
// the upstream handshake carries a browser fingerprint.
func TestProxyTerminatesTLSAndTrustsItsOwnCA(t *testing.T) {
	var sawUA string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUA = r.Header.Get("User-Agent")
		io.WriteString(w, "secure")
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	// The client trusts only the proxy's CA, never the origin's certificate.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CA.PEM()) {
		t.Fatal("proxy CA is not a valid PEM certificate")
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(mustURL(p.Addr())),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	resp, err := client.Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("request through the proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure" {
		t.Fatalf("body = %q", body)
	}
	if sawUA != p.Identity.UserAgent {
		t.Fatalf("origin saw %q, want the engagement identity", sawUA)
	}
}

// A refusal is the point of the gate: the request must not reach the origin.
func TestGateRefusalNeverReachesOrigin(t *testing.T) {
	var hits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer origin.Close()

	p := newTestProxy(t, denyAll{})
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET "+origin.URL+"/secret HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "403") {
		t.Fatalf("status line = %q, want a 403 refusal", line)
	}
	if hits != 0 {
		t.Fatalf("origin was reached %d times despite the refusal", hits)
	}
}

// A CONNECT tunnel carrying plaintext must be relayed, not terminated: the
// recording proxy CONNECTs to this proxy even for an http:// target, and a TLS
// handshake here consumed the request and answered nothing (the 502 that made
// every plain-HTTP target uncaptured).
func TestProxyRelaysPlaintextThroughConnect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain")
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "http://")

	p := newTestProxy(t, nil)
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT reply = %q (%v)", line, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read the CONNECT headers: %v", err)
		}
		if l == "\r\n" {
			break
		}
	}
	io.WriteString(conn, "GET /plain HTTP/1.1\r\nHost: "+authority+"\r\nConnection: close\r\n\r\n")
	out, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read the relayed response: %v", err)
	}
	if !strings.Contains(string(out), "plain") {
		t.Fatalf("relayed response = %q, want the origin's body", out)
	}
}

// The gate still applies to a relayed tunnel: a relay must not become an
// unthrottled path to a target the engagement forbids.
func TestRelayedTunnelHonoursTheGate(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "http://")

	p := newTestProxy(t, denyAll{})
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
	br := bufio.NewReader(conn)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("CONNECT reply = %q", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read the CONNECT headers: %v", err)
		}
		if l == "\r\n" {
			break
		}
	}
	io.WriteString(conn, "GET /secret HTTP/1.1\r\nHost: "+authority+"\r\nConnection: close\r\n\r\n")
	out, _ := io.ReadAll(br)
	if !strings.Contains(string(out), "403") {
		t.Fatalf("relayed response = %q, want a refusal", out)
	}
	if hits.Load() != 0 {
		t.Fatalf("origin was reached %d times despite the refusal", hits.Load())
	}
}

type denyAll struct{}

func (denyAll) Allow(context.Context, string, string) (bool, string) { return false, "out of scope" }

func newTestProxy(t *testing.T, gate Gate) *Proxy {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New("127.0.0.1:0", ca, id, gate)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(context.Background())
	t.Cleanup(func() { p.Close() })
	return p
}

func proxyGet(t *testing.T, p *Proxy, target string) string {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(p.Addr()))}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func mustURL(addr string) *url.URL {
	u, err := url.Parse("http://" + addr)
	if err != nil {
		panic(err)
	}
	return u
}

// The CA must mint a leaf the client accepts for both a DNS name and an IP, or
// HTTPS to an IP-literal target fails at the client.
func TestLeafCoversDNSAndIP(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"target.htb", "10.129.14.7"} {
		leaf, err := ca.Leaf(host)
		if err != nil {
			t.Fatalf("Leaf(%q): %v", host, err)
		}
		parsed, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(ca.PEM())
		if _, err := parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("leaf for %q does not verify: %v", host, err)
		}
	}
}

// The CA must survive a restart, or every trust store the guest installed is
// invalidated on the next boot.
func TestCASurvivesReload(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.PEM()) != string(second.PEM()) {
		t.Fatal("reloading the CA produced a different certificate")
	}
}

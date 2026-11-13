package traffic

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestConnectToClosedPortIsRefused pins the recorder's CONNECT honesty. The
// proxy is honest only because go-mitmproxy's ClientConn.UpstreamCert defaults
// to true: handleConnect then dials the target BEFORE answering, so a dead port
// yields 502 and the client learns the truth. Adding
// NewUpstreamCertAddon(false) — a plausible "make interception cheaper" change —
// switches to the lazy path, which answers 200 with a forged certificate and
// lets the client believe the port is open. "Is the port open" is a fact the
// recorder reports to agents, so that lie must not be reintroduced silently.
func TestConnectToClosedPortIsRefused(t *testing.T) {
	proxyAddr := freeLoopbackAddr(t)
	tr, err := Open(t.TempDir(), proxyAddr)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	go tr.Start() // blocking
	defer tr.proxy.Close()

	waitListening(t, proxyAddr)

	deadAddr := closedLoopbackAddr(t)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", deadAddr, deadAddr); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer resp.Body.Close()

	// A CONNECT either fails outright (4xx/5xx) or opens a tunnel (200). Any
	// success code here means the proxy claimed a tunnel to a closed port.
	if resp.StatusCode < 400 {
		t.Fatalf("CONNECT to closed port %s answered %d %q; a tunnel to a dead target must be refused",
			deadAddr, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

// freeLoopbackAddr reserves an ephemeral port and releases it, so the test never
// hardcodes a port. A tiny bind-close race remains, which is why the proxy is
// given a fresh port rather than a well-known one.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// closedLoopbackAddr returns a loopback address nothing is listening on, and
// verifies it: if another process grabbed the released port, the proxy's dial
// would succeed and the test would be asserting the opposite of its intent.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	for range 5 {
		addr := freeLoopbackAddr(t)
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return addr
		}
		conn.Close()
	}
	t.Fatal("could not obtain a closed loopback port")
	return ""
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start listening on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A recorder started with a proxy address must dial through the gateway hook, and
// the hook must carry the operator exit. Without the hook the recorder would dial
// origins directly, which is the unrecorded path the boundary forbids.
func TestRecorderGetsTheGatewayHook(t *testing.T) {
	m, err := NewManager(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	if m.Gateway() == nil {
		t.Fatal("the recorder has no gateway origin transport")
	}
	if m.Traffic() == nil {
		t.Fatal("the recorder did not start")
	}

	// The operator's global proxy is the gateway's exit, never a replacement for
	// the gateway: policy, DNS pinning and the origin handshake stay in the hook.
	previous := m.GlobalProxy()
	t.Cleanup(func() { _ = m.SetGlobalProxy(previous) })
	if err := m.SetGlobalProxy("http://127.0.0.1:9"); err != nil {
		t.Fatalf("SetGlobalProxy: %v", err)
	}
	if got := m.Gateway().Exit().ProxyURL; got != "http://127.0.0.1:9" {
		t.Fatalf("gateway exit = %q, want the operator proxy", got)
	}
	if err := m.SetGlobalProxy(""); err != nil {
		t.Fatalf("clear SetGlobalProxy: %v", err)
	}
	if got := m.Gateway().Exit().ProxyURL; got != "" {
		t.Fatalf("gateway exit after clear = %q, want the configured fallback", got)
	}
}

// The recorder must refuse a request that carries no backend-issued session
// before it resolves or dials anything. This is the manager-level proof that the
// recorder really dials through the hook: without it the CONNECT would reach the
// origin and answer 200.
func TestRecorderRefusesARequestWithoutASession(t *testing.T) {
	addr := freeServerLoopbackAddr(t)
	m, err := NewManager(t.TempDir(), addr)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	// The origin counts accepted connections, so "refused before the dial" is
	// measured rather than inferred from the status code.
	var accepted atomic.Int32
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()

	waitServerListening(t, addr)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial recorder: %v", err)
	}
	defer conn.Close()
	target := origin.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
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

	// A request with no credential is challenged so a browser can answer; the
	// origin is still never dialled.
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT without a session = %d, want 407 from the policy stage", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got == "" {
		t.Fatal("CONNECT without a session carried no Proxy-Authenticate challenge")
	}
	if got := accepted.Load(); got != 0 {
		t.Fatalf("the recorder dialed the origin %d times without a session", got)
	}
}

// A recorder that cannot build its transport fails startup instead of falling
// back to a direct dial.
func TestRecorderRefusesAMissingTransport(t *testing.T) {
	dir := t.TempDir()
	if _, err := openRecorder(filepath.Join(dir, "traffic"), "127.0.0.1:0", nil); err == nil {
		t.Fatal("openRecorder accepted a nil transport; that recorder would dial directly")
	}
}

// freeServerLoopbackAddr reserves an ephemeral port and releases it, so the test
// never hardcodes one. A tiny bind-close race remains, which is why the recorder
// gets a fresh port rather than a well-known one.
func freeServerLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release the loopback port: %v", err)
	}
	return addr
}

// waitServerListening waits for the recorder's listener to accept a connection.
func waitServerListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the recorder never listened on %s", addr)
}

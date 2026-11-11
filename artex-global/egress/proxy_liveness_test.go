package egress

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// connectRaw sends a CONNECT to the proxy and returns the status line, the
// header block and whatever followed it (a body, or the start of a TLS
// handshake if the proxy answered 200).
func connectRaw(t *testing.T, proxyAddr, authority string) (status, head, rest string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read the CONNECT reply: %v", err)
	}
	var h strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if trimCRLF(l) == "" {
			break
		}
		h.WriteString(l)
	}
	body, _ := io.ReadAll(br)
	return strings.TrimSpace(line), h.String(), string(body)
}

// closedLoopbackAddr returns a loopback address nothing listens on.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// A CONNECT to a target that refuses the connection must fail before the
// tunnel exists. Answering 200 first made the proxy claim a reachability it had
// never checked, and the tool read the proxy's own 502 inside the tunnel as the
// site's answer.
func TestConnectToDeadTargetFailsBeforeTLS(t *testing.T) {
	p := newTestProxy(t, nil)
	authority := closedLoopbackAddr(t)

	status, head, body := connectRaw(t, p.Addr(), authority)
	if !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Fatalf("CONNECT to a dead target answered %q, want 502", status)
	}
	if !strings.Contains(head, HeaderEgress+": "+egressDialFailed) {
		t.Fatalf("the failure is not attributed to the proxy: %q", head)
	}
	if !strings.Contains(body, egressDialFailed) {
		t.Fatalf("body %q does not name the failure", body)
	}
	// One line, then the connection ended: no certificate was minted and no
	// TLS handshake followed the reply.
	if strings.Count(body, "\n") != 1 {
		t.Fatalf("body = %q, want a single line", body)
	}
}

// A failed authority is cached, so a retry loop against a dead host costs one
// dial per TTL instead of one per request. The second CONNECT here happens after
// the port was brought up: only the cache can still report it dead.
func TestConnectFailureIsCachedWithinTTL(t *testing.T) {
	p := newTestProxy(t, nil)
	authority := closedLoopbackAddr(t)

	if status, _, _ := connectRaw(t, p.Addr(), authority); !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Fatalf("first CONNECT to a dead target answered %q, want 502", status)
	}

	ln, err := net.Listen("tcp", authority)
	if err != nil {
		t.Fatalf("rebind %s: %v", authority, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	status, head, _ := connectRaw(t, p.Addr(), authority)
	if !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Fatalf("second CONNECT dialled again instead of reusing the cached failure: %q", status)
	}
	if !strings.Contains(head, HeaderEgress) {
		t.Fatalf("cached failure is not attributed to the proxy: %q", head)
	}
}

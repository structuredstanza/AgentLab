package traffic

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServerSpeaksFirstBannerIsRelayed pins that a CONNECT tunnel to a service
// that talks first (FTP, SMTP, MySQL) delivers its banner without the client
// sending anything. The recorder peeks the client's first bytes to tell TLS from
// plain traffic; without a deadline on that peek both sides wait forever.
func TestServerSpeaksFirstBannerIsRelayed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const banner = "220 fake ftp ready\r\n"
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, banner)
			c.Close()
		}
	}()

	proxyAddr := freeLoopbackAddr(t)
	tr, err := OpenWithTransport(t.TempDir(), proxyAddr, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tr.Close()
	go tr.Start() // blocking
	defer tr.proxy.Close()
	waitListening(t, proxyAddr)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	target := ln.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: status %v, err %v", resp, err)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != banner {
		t.Fatalf("banner = %q, err %v; want %q", line, err, banner)
	}
}

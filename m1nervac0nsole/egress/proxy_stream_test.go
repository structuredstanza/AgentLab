package egress

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// largeBodySize is just over the buffered request cap, so any path that still
// buffers a response and cuts it at maxBody produces a visibly short body.
const largeBodySize = maxBody + 4096

// patternBlock is one block of the generated body. A repeating block makes the
// expected digest cheap to compute while any reordering or gap in the stream
// still changes it.
var patternBlock = func() []byte {
	b := make([]byte, 64<<10)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}()

// writePattern writes n bytes of the generated body and returns their digest.
func writePattern(w io.Writer, n int64) string {
	h := sha256.New()
	remaining := n
	for remaining > 0 {
		chunk := int64(len(patternBlock))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := w.Write(patternBlock[:chunk]); err != nil {
			return ""
		}
		h.Write(patternBlock[:chunk])
		remaining -= chunk
	}
	return hex.EncodeToString(h.Sum(nil))
}

// largeBodyDigest is the digest of a complete large body, computed once.
var largeBodyDigest = writePattern(io.Discard, largeBodySize)

// proxyClient returns a client that sends its HTTP/1.1 requests through p.
func proxyClient(t *testing.T, p *Proxy) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustURL(p.Addr())),
			ForceAttemptHTTP2: false,
		},
		Timeout: 2 * time.Minute,
	}
}

// readAllDigest streams a body through sha256 without buffering it, so the test
// itself does not hold a copy of a response larger than the proxy's cap.
func readAllDigest(t *testing.T, r io.Reader) (string, int64) {
	t.Helper()
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		t.Fatalf("reading the forwarded body: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n
}

// A response larger than the request cap must arrive complete and byte-exact
// through the declared-length, chunked and close-delimited framings. A buffered
// path capped at maxBody would return exactly 32 MiB with a nil error.
func TestProxyStreamsLargeResponses(t *testing.T) {
	wantDigest := largeBodyDigest

	t.Run("declared length", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(largeBodySize))
			writePattern(w, largeBodySize)
		}))
		defer origin.Close()

		p := newTestProxy(t, nil)
		resp, err := proxyClient(t, p).Get(origin.URL + "/big")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if resp.ContentLength != largeBodySize {
			t.Errorf("declared length = %d, want %d", resp.ContentLength, largeBodySize)
		}
		got, n := readAllDigest(t, resp.Body)
		if n != largeBodySize {
			t.Fatalf("received %d bytes, want %d (a capped body looks complete)", n, largeBodySize)
		}
		if got != wantDigest {
			t.Fatalf("body digest %s, want %s", got, wantDigest)
		}
	})

	t.Run("chunked", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No Content-Length and a flush before the body: Go frames this
			// response as chunked, which the proxy must re-frame, not buffer.
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			writePattern(w, largeBodySize)
		}))
		defer origin.Close()

		p := newTestProxy(t, nil)
		resp, err := proxyClient(t, p).Get(origin.URL + "/big")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		got, n := readAllDigest(t, resp.Body)
		if n != largeBodySize {
			t.Fatalf("received %d bytes, want %d", n, largeBodySize)
		}
		if got != wantDigest {
			t.Fatalf("body digest %s, want %s", got, wantDigest)
		}
	})

	t.Run("close delimited", func(t *testing.T) {
		// A raw origin is the only way to produce a response with neither a
		// length nor chunking; the body ends when the socket closes.
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		go func() {
			conn, err := raw.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			bufio.NewReader(conn).ReadString('\n')
			io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n")
			writePattern(conn, largeBodySize)
		}()

		p := newTestProxy(t, nil)
		resp, err := proxyClient(t, p).Get("http://" + raw.Addr().String() + "/big")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		got, n := readAllDigest(t, resp.Body)
		if n != largeBodySize {
			t.Fatalf("received %d bytes, want %d (a cap must not look complete here)", n, largeBodySize)
		}
		if got != wantDigest {
			t.Fatalf("body digest %s, want %s", got, wantDigest)
		}
	})
}

// A response that ends before its declared body must surface as an error at the
// client, and must never be followed by a second status line on the same
// connection.
func TestProxyIncompleteResponseIsNotSilentlyComplete(t *testing.T) {
	cases := map[string]string{
		"declared": "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
		"chunked":  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nshort",
	}
	for name, head := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			go func() {
				conn, err := raw.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				bufio.NewReader(conn).ReadString('\n')
				io.WriteString(conn, head)
			}()

			p := newTestProxy(t, nil)
			conn, err := net.Dial("tcp", p.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET http://%s/x HTTP/1.1\r\nHost: x\r\n\r\n", raw.Addr())
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			all, _ := io.ReadAll(conn)

			if got := strings.Count(string(all), "HTTP/1.1 "); got != 1 {
				t.Fatalf("client saw %d status lines, want 1:\n%s", got, all)
			}
			if !strings.HasPrefix(string(all), "HTTP/1.1 200 ") {
				t.Fatalf("first status line is not the origin's:\n%s", all)
			}
			if strings.Contains(string(all), "502") || strings.Contains(string(all), "Bad Gateway") {
				t.Fatalf("a second error response was written after the head:\n%s", all)
			}
			// The origin promised 100 bytes and sent 5. Parsing the client side
			// the way a client does must yield exactly those 5 bytes and then a
			// framing error. The previous implementation swallowed
			// io.ErrUnexpectedEOF and zero-padded the body to the declared
			// length, so asserting only the status line passed on the very bug
			// this test names.
			parsed, perr := http.ReadResponse(bufio.NewReader(strings.NewReader(string(all))), nil)
			if perr != nil {
				t.Fatalf("client could not parse the response: %v\n%s", perr, all)
			}
			body, berr := io.ReadAll(parsed.Body)
			if string(body) != "short" {
				t.Fatalf("client body %q, want %q: a short response was padded to look complete", body, "short")
			}
			if berr == nil {
				t.Fatal("the client read a truncated response without an error, so it looks complete")
			}
		})
	}
}

// HEAD and 304 carry no body, keep their declared metadata, and leave the
// client connection usable.
func TestProxyHeadAndNotModifiedKeepConnection(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "1234")
			w.Header().Set("ETag", `"abc"`)
			return
		}
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.Header().Set("ETag", `"abc"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, "body")
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	client := proxyClient(t, p)

	head, err := client.Head(origin.URL + "/doc")
	if err != nil {
		t.Fatalf("HEAD failed: %v", err)
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d", head.StatusCode)
	}
	if head.ContentLength != 1234 {
		t.Errorf("HEAD Content-Length = %d, want 1234", head.ContentLength)
	}

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/doc", nil)
	req.Header.Set("If-None-Match", `"abc"`)
	nm, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional GET failed: %v", err)
	}
	defer nm.Body.Close()
	if nm.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", nm.StatusCode)
	}
	if b, _ := io.ReadAll(nm.Body); len(b) != 0 {
		t.Fatalf("304 carried a %d-byte body", len(b))
	}

	// Both responses were length-less on the wire except for HEAD's declared
	// length; the connection must still be reusable.
	resp, err := client.Get(origin.URL + "/doc")
	if err != nil {
		t.Fatalf("GET after HEAD/304 failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "body" {
		t.Fatalf("body = %q, want body", body)
	}
}

// A chunked request body must be fully consumed, including its trailer section,
// or the framing bytes are parsed as the next request and the connection dies.
func TestProxyChunkedRequestBodyKeepsConnection(t *testing.T) {
	var sawBody string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		io.WriteString(w, "ok")
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	target := "http://" + origin.Listener.Addr().String() + "/post"
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("first response: %v", err)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
		t.Fatalf("first body = %q, want ok", body)
	}
	resp.Body.Close()
	if sawBody != "hello" {
		t.Fatalf("origin saw body %q, want hello", sawBody)
	}

	// Same connection, second request.
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", "http://"+origin.Listener.Addr().String()+"/next")
	second, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("second request on the same connection failed: %v", err)
	}
	defer second.Body.Close()
	if body, _ := io.ReadAll(second.Body); string(body) != "ok" {
		t.Fatalf("second body = %q", body)
	}
}

// An h2 origin's large body must stream too, and a nondefault authority port
// must survive into the request the origin sees.
func TestProxyStreamsLargeHTTP2Response(t *testing.T) {
	hosts := make(chan string, 1)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hosts <- r.Host:
		default:
		}
		w.Header().Set("Content-Length", fmt.Sprint(largeBodySize))
		writePattern(w, largeBodySize)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	p := newTestProxy(t, nil)
	client := newH2TestProxy(t, p)

	resp, err := client.Get(origin.URL + "/big")
	if err != nil {
		t.Fatalf("request to the h2 origin failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("reading the h2 body: %v", err)
	}
	if n != largeBodySize {
		t.Fatalf("received %d bytes, want %d", n, largeBodySize)
	}
	sawHost := <-hosts
	if _, port, _ := net.SplitHostPort(origin.Listener.Addr().String()); !strings.HasSuffix(sawHost, ":"+port) {
		t.Errorf("origin saw Host %q, want the nondefault port %s preserved", sawHost, port)
	}
}

// The bound is a fixed number of concurrently served connections; past it a new
// connection is answered 503 rather than queued, and the slot comes back when
// the connection that held it ends.
func TestProxyBoundsConcurrentConnections(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer origin.Close()

	p := newProxyWithLimit(t, 1)

	held, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	// Say nothing: the handler for this connection parks reading its head and
	// holds the only slot. Wait until it actually holds it.
	waitSlots(t, p, 1)

	over, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	over.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(over, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", origin.URL)
	line, err := bufio.NewReader(over).ReadString('\n')
	if err != nil {
		t.Fatalf("overload connection got no answer: %v", err)
	}
	if !strings.Contains(line, "503") {
		t.Fatalf("status line = %q, want 503 while the bound is reached", line)
	}

	// Releasing the held connection must return its slot.
	held.Close()
	var lastErr error
	for range 50 {
		c, err := net.Dial("tcp", p.Addr())
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", origin.URL)
		line, err := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if err == nil && strings.Contains(line, "200") {
			return
		}
		lastErr = fmt.Errorf("status line %q", line)
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the slot was never released after the holder closed: %v", lastErr)
}

// A failed exchange must release its slot too, not only a successful one.
func TestProxyReleasesSlotAfterUpstreamFailure(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := closed.Addr().String()
	closed.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer origin.Close()

	p := newProxyWithLimit(t, 1)
	client := proxyClient(t, p)

	resp, err := client.Get("http://" + deadAddr + "/nope")
	if err != nil {
		t.Fatalf("request to a closed port failed at the client: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	// The same single slot must serve the next request. The handler releases it
	// after the response is written, so a client that reconnects the instant it
	// reads the 502 can still be refused; poll like the bound test above rather
	// than assuming the release already happened.
	var lastStatus int
	for range 50 {
		ok, err := client.Get(origin.URL + "/ok")
		if err != nil {
			t.Fatalf("request after a failed exchange failed: %v", err)
		}
		lastStatus = ok.StatusCode
		ok.Body.Close()
		if lastStatus == http.StatusOK {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("status = %d, want 200 (the slot was not released)", lastStatus)
}

// Close must drop the connections being served and let Serve return promptly,
// including a handler parked on an origin that never answers.
func TestProxyCloseReturnsBoundedly(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var heldMu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			// Accept and hold: the proxy's handler parks reading a response
			// that never comes.
			heldMu.Lock()
			held = append(held, conn)
			heldMu.Unlock()
		}
	}()

	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New("127.0.0.1:0", ca, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(context.Background()) }()

	idle, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	busy, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	fmt.Fprintf(busy, "GET http://%s/slow HTTP/1.1\r\nHost: x\r\n\r\n", silent.Addr())
	waitSlots(t, p, 2)

	start := time.Now()
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after Close, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of Close")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}

	// Both connections must be closed, not merely ignored.
	for name, c := range map[string]net.Conn{"idle": idle, "busy": busy} {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadAll(c); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("%s connection was not closed by shutdown", name)
			}
		}
	}
}

// The h2 request URL and the Host header must both keep the authority's port
// and, for an IPv6 literal, its brackets: dropping the port sends every https
// request to 443, and an unbracketed literal is not a legal Host value.
func TestAuthorityPreservedForH2Target(t *testing.T) {
	cases := map[string]string{
		"example.com:443":    "example.com",
		"example.com:8443":   "example.com:8443",
		"[2001:db8::1]:443":  "[2001:db8::1]",
		"[2001:db8::1]:8443": "[2001:db8::1]:8443",
	}
	for authority, wantHost := range cases {
		u, err := url.Parse("https://" + authority + "/p?q=1")
		if err != nil {
			t.Fatalf("parse target for %q: %v", authority, err)
		}
		if u.Host != authority {
			t.Errorf("target URL for %q carries host %q", authority, u.Host)
		}
		if got := hostHeader(authority); got != wantHost {
			t.Errorf("hostHeader(%q) = %q, want %q", authority, got, wantHost)
		}
	}
}

// A client that disconnects mid-body must not hold its connection slot: the
// relay write fails and the handler ends. Closing the origin socket before the
// response body is what keeps that prompt for a close-delimited body, whose
// Close would otherwise drain from a stalled origin.
func TestProxyReleasesSlotWhenClientAborts(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(http.StatusOK)
		flush := w.(http.Flusher)
		flush.Flush()
		// Far more than the socket buffers hold, so the proxy is still writing
		// when the client goes away.
		for range 2000 {
			if _, err := w.Write(patternBlock); err != nil {
				return
			}
			flush.Flush()
		}
	}))
	defer origin.Close()

	p := newProxyWithLimit(t, 1)
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET http://%s/slow HTTP/1.1\r\nHost: x\r\n\r\n", origin.Listener.Addr())
	br := bufio.NewReader(conn)
	// Read the head and a little of the body, then abort.
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	if _, err := br.Discard(1024); err != nil {
		t.Fatalf("reading the start of the body: %v", err)
	}
	conn.Close()

	waitSlots(t, p, 0)

	resp, err := proxyClient(t, p).Get(origin.URL + "/ok")
	if err != nil {
		t.Fatalf("request after the abort failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the aborted connection kept its slot)", resp.StatusCode)
	}
}

// A chunked response's trailer must reach the client: it is part of the
// response, and a proxy that drops it changes what the tool under test sees.
func TestProxyPreservesChunkedResponseTrailer(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Complete")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		io.WriteString(w, "payload")
		w.Header().Set("X-Complete", "yes")
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	resp, err := proxyClient(t, p).Get(origin.URL + "/trailer")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if string(body) != "payload" {
		t.Fatalf("body = %q, want payload", body)
	}
	if got := resp.Trailer.Get("X-Complete"); got != "yes" {
		t.Fatalf("trailer X-Complete = %q, want yes (trailers must survive the proxy)", got)
	}
}

// waitSlots blocks until n connections hold a slot, so a test that depends on
// the accept loop having reached a state does not sleep for it.
func waitSlots(t *testing.T, p *Proxy, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.slots) == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("connection slots = %d, want %d", len(p.slots), n)
}

// newProxyWithLimit builds a proxy whose connection bound is limit, so the
// overload path can be reached without opening maxConnections sockets.
func newProxyWithLimit(t *testing.T, limit int) *Proxy {
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
	p, err := New("127.0.0.1:0", ca, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Replaced before Serve starts, so the accept loop only ever sees this one.
	p.slots = make(chan struct{}, limit)
	go p.Serve(context.Background())
	t.Cleanup(func() { p.Close() })
	return p
}

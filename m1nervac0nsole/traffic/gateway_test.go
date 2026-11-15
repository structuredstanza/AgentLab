package traffic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// gatewaySource is a policy source that returns one fixed state.
type gatewaySource struct {
	mu sync.Mutex
	st netpolicy.State
}

func (s *gatewaySource) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, nil
}

// loopbackPolicy authorizes the loopback fixture addresses and the hostname the
// fixtures are reached by. The policy stage judges the name, so a name grant is
// required before any resolver runs.
func loopbackPolicy() netpolicy.State {
	return netpolicy.State{
		Revision: 1,
		Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "localhost", Protocol: "any", Authorized: true},
			{ID: 2, Effect: "include", Pattern: "127.0.0.1/32", Protocol: "any", Authorized: true},
			{ID: 3, Effect: "include", Pattern: "::1/128", Protocol: "any", Authorized: true},
		},
	}
}

// newGatewayHook builds the origin transport for a loopback fixture. The
// fixtures are self-signed, so they are accepted through the explicit
// exception rather than by weakening verification globally.
func newGatewayHook(t *testing.T) mproxy.OriginTransport {
	t.Helper()
	return gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(&gatewaySource{st: loopbackPolicy()}),
		SessionFor: func(*http.Request) (netpolicy.Session, bool) {
			return netpolicy.Session{ID: "fixture", TaskID: 1, Purpose: netpolicy.PurposeTesting, Revision: 1}, true
		},
		CertException: func(netpolicy.Session, string) bool { return true },
	})
}

// recorder is the running recorder plus a client that trusts only its CA.
type recorder struct {
	tr     *Traffic
	addr   string
	proxy  *url.URL
	pool   *x509.CertPool
	client *http.Client
}

func startRecorder(t *testing.T, ot mproxy.OriginTransport, addons ...mproxy.Addon) *recorder {
	t.Helper()
	addr := freeLoopbackAddr(t)
	tr, err := OpenWithTransport(t.TempDir(), addr, ot)
	if err != nil {
		t.Fatalf("OpenWithTransport: %v", err)
	}
	for _, a := range addons {
		tr.proxy.AddAddon(a)
	}
	go tr.Start() // blocking
	t.Cleanup(func() {
		tr.proxy.Close()
		tr.Close()
	})
	waitListening(t, addr)

	pem, err := os.ReadFile(tr.CACertPath())
	if err != nil {
		t.Fatalf("reading the recorder CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the recorder CA is not valid PEM")
	}
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	return &recorder{
		tr:    tr,
		addr:  addr,
		proxy: proxyURL,
		pool:  pool,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				TLSClientConfig:   &tls.Config{RootCAs: pool},
				ForceAttemptHTTP2: true,
			},
			Timeout: 20 * time.Second,
		},
	}
}

// countingAddon records the addon hooks a test asserts on.
type countingAddon struct {
	mproxy.BaseAddon
	responses   atomic.Int32
	streamed    atomic.Int64
	sseStart    atomic.Int32
	sseMessages atomic.Int32
	sseEnd      atomic.Int32
	wsStart     atomic.Int32
	wsMessages  atomic.Int32
	wsFrames    atomic.Int32
	wsClosed    atomic.Int32
	wsEnd       atomic.Int32
	retained    atomic.Int64
}

func (a *countingAddon) Response(*mproxy.Flow) { a.responses.Add(1) }

func (a *countingAddon) StreamResponseModifier(f *mproxy.Flow, in io.Reader) io.Reader {
	return &countingReader{r: in, n: &a.streamed}
}

func (a *countingAddon) SSEStart(*mproxy.Flow)   { a.sseStart.Add(1) }
func (a *countingAddon) SSEMessage(*mproxy.Flow) { a.sseMessages.Add(1) }
func (a *countingAddon) SSEEnd(f *mproxy.Flow) {
	a.sseEnd.Add(1)
	if f.SSE != nil {
		a.retained.Store(int64(len(f.SSE.Events)))
	}
}
func (a *countingAddon) WebSocketStart(*mproxy.Flow)   { a.wsStart.Add(1) }
func (a *countingAddon) WebSocketMessage(*mproxy.Flow) { a.wsMessages.Add(1) }
func (a *countingAddon) WebSocketFrame(*mproxy.Flow, *mproxy.WebSocketMessage) {
	a.wsFrames.Add(1)
}
func (a *countingAddon) WebSocketClosed(*mproxy.Flow, bool, error) { a.wsClosed.Add(1) }
func (a *countingAddon) WebSocketEnd(*mproxy.Flow)                 { a.wsEnd.Add(1) }

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// TestSingleInterceptionBoundary proves the client trusts only the recorder's
// CA and the origin sees exactly one handshake for one request.
func TestSingleInterceptionBoundary(t *testing.T) {
	var handshakes atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			handshakes.Add(1)
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	rec := startRecorder(t, newGatewayHook(t))
	res, err := rec.client.Get(originURL(srv) + "/x")
	if err != nil {
		t.Fatalf("GET through the recorder: %v", err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)

	if res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		t.Fatal("the client saw no peer certificate")
	}
	caPEM, err := os.ReadFile(rec.tr.CACertPath())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("the recorder CA is not decodable")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf := res.TLS.PeerCertificates[0]
	if leaf.Issuer.String() != ca.Subject.String() {
		t.Fatalf("client leaf issuer = %q, want the recorder CA %q", leaf.Issuer, ca.Subject)
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("origin handshakes = %d, want 1 (one interception boundary)", got)
	}
}

// TestWSSUpgrade proves a WebSocket upgrade reuses the CONNECT's origin
// connection instead of dialing and handshaking a second time.
func TestWSSUpgrade(t *testing.T) {
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{Subprotocols: []string{"chat"}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			handshakes.Add(1)
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	addon := &countingAddon{}
	rec := startRecorder(t, newGatewayHook(t), addon)

	dialer := &websocket.Dialer{
		Proxy:           func(*http.Request) (*url.URL, error) { return rec.proxy, nil },
		TLSClientConfig: &tls.Config{RootCAs: rec.pool},
		Subprotocols:    []string{"chat"},
	}
	wsURL := "wss://localhost:" + portOf(srv.Listener.Addr().String()) + "/ws"
	c, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("wss dial through the recorder: %v", err)
	}
	defer c.Close()
	if c.Subprotocol() != "chat" {
		t.Errorf("subprotocol = %q, want chat", c.Subprotocol())
	}
	if err := c.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "hello" {
		t.Fatalf("echo = %q, want hello", msg)
	}
	c.Close()

	if got := handshakes.Load(); got != 1 {
		t.Fatalf("origin handshakes = %d, want 1 (the WSS upgrade must reuse the CONNECT conn)", got)
	}
	waitFor(t, func() bool { return addon.wsStart.Load() == 1 && addon.wsFrames.Load() >= 2 })
	waitFor(t, func() bool { return addon.wsClosed.Load() == 2 && addon.wsEnd.Load() >= 1 })
	// The frames are never buffered into a Response, so the WebSocket exchange
	// is recorded from its end hook: one row whose body is the transcript.
	waitFor(t, func() bool {
		var n int
		rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
		return n == 1
	})
	var head, blob, method, host string
	var status int
	if err := rec.tr.DB().QueryRow(`SELECT e.method, e.host, e.status, b.resp_head, b.resp_blob FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&method, &host, &status, &head, &blob); err != nil {
		t.Fatal(err)
	}
	if method != "GET" || host != "localhost" || status != http.StatusSwitchingProtocols {
		t.Errorf("WebSocket exchange = %s %s %d, want GET localhost 101", method, host, status)
	}
	// The client closed the TCP connection without a close frame, so the session
	// was cut short and the row says so instead of reading as a whole one.
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "ended with code") {
		t.Errorf("WebSocket exchange head = %q, want the partial marker naming the abrupt end", head)
	}
	transcript := readBlob(t, rec.tr, blob)
	for _, want := range []string{`"kind":"ws-transcript"`, `"dir":"c2s"`, `"dir":"s2c"`, `"data":"aGVsbG8="`} {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript is missing %q: %q", want, transcript)
		}
	}
}

// TestSSEStreamsAndObserved proves events reach the client before the origin
// finishes, and that the SSE hooks observe them.
func TestSSEStreamsAndObserved(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := range 3 {
			fmt.Fprintf(w, "id: %d\ndata: event-%d\n\n", i, i)
			flusher.Flush()
		}
		<-release
	}))
	defer srv.Close()

	addon := &countingAddon{}
	rec := startRecorder(t, newGatewayHook(t), addon)

	res, err := rec.client.Get(originURL(srv) + "/events")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()

	// The origin has not returned yet, so receiving all three events here is
	// only possible if the recorder streams instead of buffering.
	events := make(chan string, 3)
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			if line, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				events <- line
			}
		}
		close(events)
	}()

	for i := range 3 {
		select {
		case got := <-events:
			if want := fmt.Sprintf("event-%d", i); got != want {
				t.Fatalf("event %d = %q, want %q", i, got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("event %d did not stream before the origin finished", i)
		}
	}
	close(release)
	waitFor(t, func() bool { return addon.sseEnd.Load() >= 1 })

	if got := addon.sseStart.Load(); got != 1 {
		t.Errorf("SSEStart fired %d times, want 1", got)
	}
	if got := addon.sseMessages.Load(); got < 3 {
		t.Errorf("SSEMessage fired %d times, want at least 3", got)
	}
	// An SSE exchange is streamed too, so its body is spooled rather than
	// buffered: the row carries what the origin sent, not just metadata.
	waitFor(t, func() bool {
		var n int
		rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
		return n == 1
	})
	var head, blob string
	if err := rec.tr.DB().QueryRow(`SELECT resp_head, resp_blob FROM exchange_bodies`).Scan(&head, &blob); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(head, streamedMarker) || strings.Contains(head, partialMarker) {
		t.Errorf("SSE exchange head = %q, want no capture warning: the body was captured", head)
	}
	stored := readBlob(t, rec.tr, blob)
	for i := range 3 {
		if want := fmt.Sprintf("data: event-%d\n", i); !strings.Contains(stored, want) {
			t.Errorf("the stored SSE body is missing %q: %q", want, stored)
		}
	}
}

// TestSixMiBBody proves a body above the streaming threshold is passed through
// unbuffered: the addon's stream hook sees every byte and Response never fires.
// The exchange is still recorded in full — the stream hook spools the body to
// the blob store, so a 6 MiB response is recoverable rather than metadata only.
func TestSixMiBBody(t *testing.T) {
	const size = 6 << 20
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(payload))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.Write(payload)
	}))
	defer srv.Close()

	addon := &countingAddon{}
	rec := startRecorder(t, newGatewayHook(t), addon)

	res, err := rec.client.Get(originURL(srv) + "/big")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if len(body) != size {
		t.Fatalf("body length = %d, want %d", len(body), size)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != want {
		t.Fatalf("body digest changed in transit")
	}
	if got := addon.streamed.Load(); got != size {
		t.Errorf("StreamResponseModifier saw %d bytes, want %d", got, size)
	}
	if got := addon.responses.Load(); got != 0 {
		t.Errorf("Response fired %d times for a streamed body, want 0 (it must not buffer)", got)
	}
	// One row, and its body is in the store: the stream hook spooled every byte.
	waitFor(t, func() bool {
		var n int
		rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
		return n == 1
	})
	var head, blob string
	var respLen int
	if err := rec.tr.DB().QueryRow(`SELECT b.resp_head, b.resp_blob, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&head, &blob, &respLen); err != nil {
		t.Fatal(err)
	}
	if respLen != size {
		t.Errorf("recorded response length = %d, want %d", respLen, size)
	}
	if strings.Contains(head, streamedMarker) || strings.Contains(head, partialMarker) {
		t.Errorf("streamed exchange head = %q, want no capture warning: the body was captured", head)
	}
	stored := readBlob(t, rec.tr, blob)
	if len(stored) != size {
		t.Errorf("stored body length = %d, want %d", len(stored), size)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(stored))); got != want {
		t.Errorf("stored body digest = %s, want %s", got, want)
	}
	// The paged listing stays metadata-only: no body ever appears in it.
	rows, total, err := rec.tr.Page(PageQuery{Host: "localhost", RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0].RespLen != size {
		t.Fatalf("listing = %d rows (total %d), want one row of %d bytes", len(rows), total, size)
	}
	listing, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing) > 4096 {
		t.Errorf("the listing carries %d bytes; a body leaked into it", len(listing))
	}
}

// TestStreamReserveBreachIsLabelled proves the capture filesystem's reserve is
// the only bound on a streamed body, and that reaching it yields a labelled
// prefix instead of a crash or a row that reads as the whole body.
func TestStreamReserveBreachIsLabelled(t *testing.T) {
	const size = 6 << 20
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.Write(payload)
	}))
	defer srv.Close()

	rec := startRecorder(t, newGatewayHook(t))
	// Room for the first check, then the reserve is reached: a real breach
	// without filling a disk.
	var checks atomic.Int32
	rec.tr.free = func(string) (int64, int64, error) {
		if checks.Add(1) == 1 {
			return 1 << 40, 1 << 40, nil
		}
		return 0, 1 << 40, nil
	}

	res, err := rec.client.Get(originURL(srv) + "/big")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	// The reserve never costs the client a byte.
	if !bytes.Equal(body, payload) {
		t.Fatalf("the client received %d bytes, want the whole %d", len(body), size)
	}

	waitFor(t, func() bool {
		var n int
		rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
		return n == 1
	})
	var head, blob string
	var respLen int
	if err := rec.tr.DB().QueryRow(`SELECT b.resp_head, b.resp_blob, e.resp_len FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).Scan(&head, &blob, &respLen); err != nil {
		t.Fatal(err)
	}
	if respLen != size {
		t.Errorf("recorded response length = %d, want the full %d", respLen, size)
	}
	if !strings.Contains(head, partialMarker) || !strings.Contains(head, "reserve") {
		t.Errorf("breach head = %q, want the partial marker naming the reserve", head)
	}
	stored := readBlob(t, rec.tr, blob)
	if len(stored) == 0 || len(stored) >= size {
		t.Fatalf("stored prefix = %d bytes, want a partial body", len(stored))
	}
	if !bytes.Equal([]byte(stored), payload[:len(stored)]) {
		t.Error("the stored prefix is not the start of the body")
	}
}

// readBlob returns a stored body's bytes, asserting the blob exists.
func readBlob(t *testing.T, tr *Traffic, hash string) string {
	t.Helper()
	if hash == "" {
		t.Fatal("no blob was stored for the body")
	}
	f, _, err := tr.Blob(hash)
	if err != nil {
		t.Fatalf("opening blob %s: %v", hash, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading blob %s: %v", hash, err)
	}
	return string(b)
}

// TestNoUnrecordedPassthrough proves a proxy-caused failure is recorded and the
// host stays intercepted, instead of being tunneled unrecorded from then on.
func TestNoUnrecordedPassthrough(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			// A response no HTTP parser accepts: the recorder must record the
			// failure, not switch this host to a transparent tunnel.
			c, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			io.WriteString(c, "NOT-HTTP\r\n\r\n")
			c.Close()
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	rec := startRecorder(t, newGatewayHook(t))

	// A malformed origin answer makes the proxy close the client connection, so
	// the client sees a transport error rather than the synthetic 502. What
	// matters is that the attempt is recorded and the host stays intercepted.
	res, err := rec.client.Get(originURL(srv) + "/broken")
	if err == nil {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("first status = %d, want 502 or a transport error", res.StatusCode)
		}
	}

	res2, err := rec.client.Get(originURL(srv) + "/fine")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	body, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	if res2.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("second response = %d %q, want 200 ok", res2.StatusCode, body)
	}

	// Both attempts are in the index: the failure and the success.
	var total int
	if err := rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("recorded exchanges = %d, want 2 (no unrecorded passthrough)", total)
	}
	var failed int
	if err := rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges WHERE status = 502`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Fatalf("recorded failures = %d, want 1", failed)
	}
	var head string
	if err := rec.tr.DB().QueryRow(`SELECT resp_head FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE status = 502)`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(head, gateway.HeaderStage) {
		t.Fatalf("recorded failure does not carry the gateway stage: %q", head)
	}
}

// TestRequestErrorRecordsTheFailure proves a failed attempt is stored with its
// stage, instead of flagging the host for an unrecorded transparent tunnel.
func TestRequestErrorRecordsTheFailure(t *testing.T) {
	tr, err := OpenWithTransport(t.TempDir(), "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })

	f := &mproxy.Flow{Request: &mproxy.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: "target.test", Path: "/x"},
		Proto:  "HTTP/1.1",
		Header: http.Header{"Accept": {"application/json"}},
	}}
	(&sink{t: tr}).RequestError(f, &mproxy.OriginError{Stage: netpolicy.StageTLS, Reason: "bad certificate"})

	var status int
	if err := tr.DB().QueryRow(`SELECT status FROM exchanges WHERE host = 'target.test'`).Scan(&status); err != nil {
		t.Fatalf("the failed attempt was not recorded: %v", err)
	}
	if status != 0 {
		t.Errorf("recorded status = %d, want 0 (no response arrived)", status)
	}
	var head string
	if err := tr.DB().QueryRow(`SELECT resp_head FROM exchange_bodies`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(head, "(no response)") || !strings.Contains(head, netpolicy.StageTLS) {
		t.Errorf("recorded head does not explain the failure: %q", head)
	}
}

// TestNilHookDefaultPath proves Open without a hook keeps the upstream origin
// path working and recording.
func TestNilHookDefaultPath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	rec := startRecorder(t, nil)
	res, err := rec.client.Get(originURL(srv) + "/x")
	if err != nil {
		t.Fatalf("GET through the nil-hook recorder: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", res.StatusCode, body)
	}
	var total int
	if err := rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("recorded exchanges = %d, want 1", total)
	}
}

// TestPolicyRevocationInTunnel proves a policy change stops a request on an
// already-established tunnel: the client gets a classified refusal and the
// origin never sees the request.
func TestPolicyRevocationInTunnel(t *testing.T) {
	var served atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	src := &gatewaySource{st: loopbackPolicy()}
	hook := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(src),
		SessionFor: func(*http.Request) (netpolicy.Session, bool) {
			return netpolicy.Session{ID: "fixture", TaskID: 1, Purpose: netpolicy.PurposeTesting, Revision: 1}, true
		},
		CertException: func(netpolicy.Session, string) bool { return true },
	})
	rec := startRecorder(t, hook)

	first, err := rec.client.Get(originURL(srv) + "/one")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	io.Copy(io.Discard, first.Body)
	first.Body.Close()

	// The operator removes the grant; the revision bump retires the pooled
	// connection and the next authorization reads the new state.
	src.mu.Lock()
	src.st = netpolicy.State{Revision: 2}
	src.mu.Unlock()

	second, err := rec.client.Get(originURL(srv) + "/two")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	body, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked request status = %d %q, want 403", second.StatusCode, body)
	}
	if stage := second.Header.Get(gateway.HeaderStage); stage != netpolicy.StagePolicy {
		t.Fatalf("revoked request stage = %q, want policy", stage)
	}
	if got := served.Load(); got != 1 {
		t.Fatalf("origin served %d requests, want 1 (the revoked one must not reach it)", got)
	}
}

// singleExchange asserts exactly one recorded exchange and returns its method,
// host, status and stored request and response heads.
func singleExchange(t *testing.T, tr *Traffic) (method, host string, status int, reqHead, respHead string) {
	t.Helper()
	var n int
	if err := tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("recorded exchanges = %d, want 1", n)
	}
	if err := tr.DB().QueryRow(`SELECT e.method, e.host, e.status, b.req_head, b.resp_head FROM exchanges e JOIN exchange_bodies b ON b.id = e.id`).
		Scan(&method, &host, &status, &reqHead, &respHead); err != nil {
		t.Fatal(err)
	}
	return method, host, status, reqHead, respHead
}

// TestRefusedConnectIsRecorded proves a CONNECT the gateway refuses before a
// tunnel exists still leaves one row carrying the stage. Without it an HTTPS
// refusal was invisible, while the same refusal on a plain-HTTP target was
// recorded by RequestError.
func TestRefusedConnectIsRecorded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the origin was reached despite the refusal")
	}))
	defer srv.Close()

	// No rules: every destination is refused at the policy stage.
	hook := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(&gatewaySource{st: netpolicy.State{Revision: 1}}),
		SessionFor: func(*http.Request) (netpolicy.Session, bool) {
			return netpolicy.Session{ID: "fixture", TaskID: 1, Purpose: netpolicy.PurposeTesting, Revision: 1}, true
		},
		CertException: func(netpolicy.Session, string) bool { return true },
	})
	rec := startRecorder(t, hook)

	// The credential rides on the proxy URL, so the CONNECT carries
	// Proxy-Authorization: it must never reach the stored request head.
	proxyURL, err := url.Parse("http://user:secret@" + rec.addr)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: rec.pool},
	}}
	if _, err := client.Get(originURL(srv) + "/x"); err == nil {
		t.Fatal("a refused CONNECT succeeded at the client")
	}

	method, host, status, reqHead, respHead := singleExchange(t, rec.tr)
	if method != "CONNECT" || host != "localhost" {
		t.Errorf("recorded %s %s, want CONNECT localhost", method, host)
	}
	if status != http.StatusForbidden {
		t.Errorf("recorded status = %d, want 403", status)
	}
	if !strings.Contains(respHead, netpolicy.StagePolicy) {
		t.Errorf("recorded head does not carry the policy stage: %q", respHead)
	}
	if strings.Contains(strings.ToLower(reqHead), "proxy-authorization") || strings.Contains(reqHead, "dXNlcjpzZWNyZXQ=") {
		t.Errorf("the proxy credential was stored: %q", reqHead)
	}
}

// TestConnectWithoutCredentialIsRecorded proves the 407 challenge is recorded
// too: the client is told to authenticate, and the attempt is still evidence.
func TestConnectWithoutCredentialIsRecorded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the origin was reached without a credential")
	}))
	defer srv.Close()

	hook := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(&gatewaySource{st: loopbackPolicy()}),
		SessionFor: func(*http.Request) (netpolicy.Session, bool) {
			return netpolicy.Session{}, false
		},
		CertException: func(netpolicy.Session, string) bool { return true },
	})
	rec := startRecorder(t, hook)

	if _, err := rec.client.Get(originURL(srv) + "/x"); err == nil {
		t.Fatal("a CONNECT without a credential succeeded at the client")
	}
	method, _, status, _, respHead := singleExchange(t, rec.tr)
	if method != "CONNECT" {
		t.Errorf("recorded method = %q, want CONNECT", method)
	}
	if status != http.StatusProxyAuthRequired {
		t.Errorf("recorded status = %d, want 407", status)
	}
	if !strings.Contains(respHead, netpolicy.StagePolicy) {
		t.Errorf("recorded head does not carry the challenge stage: %q", respHead)
	}
}

// TestStreamRetentionIsBounded proves the recorder bounds what a stream keeps in
// memory: every event still reaches the client and the streamed row is still
// written, while retention stops at the cap.
func TestStreamRetentionIsBounded(t *testing.T) {
	const events = maxStreamEvents * 2
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := range events {
			fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()

	addon := &countingAddon{}
	rec := startRecorder(t, newGatewayHook(t), addon)
	res, err := rec.client.Get(originURL(srv) + "/events")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("reading the stream: %v", err)
	}
	if got := strings.Count(string(body), "data: "); got != events {
		t.Fatalf("client received %d events, want %d", got, events)
	}
	waitFor(t, func() bool { return addon.sseEnd.Load() >= 1 })
	if got := addon.retained.Load(); got < 1 || got > maxStreamEvents {
		t.Fatalf("flow retained %d events, want at most %d", got, maxStreamEvents)
	}
	waitFor(t, func() bool {
		var n int
		rec.tr.DB().QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
		return n == 1
	})
	// The cap bounds the live view only: every event the origin sent is in the
	// stored body, however many the flow was allowed to retain.
	var blob string
	if err := rec.tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(readBlob(t, rec.tr, blob), "data: "); got != events {
		t.Errorf("the stored body holds %d events, want all %d", got, events)
	}
}

// originURL rewrites a fixture URL to a hostname. The recorder mints leaves
// with a DNS SAN, so an IP-literal origin is not verifiable through it; a
// hostname is also what a real deployment uses.
func originURL(srv *httptest.Server) string {
	return "https://localhost:" + portOf(srv.Listener.Addr().String())
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

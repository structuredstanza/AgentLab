package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	// maxBody bounds one buffered request body. Responses are streamed, so a
	// scanner downloading a large file is not cut off at this size: the body
	// is copied to the client as it arrives instead of being assembled first.
	maxBody = 32 << 20

	// maxConnections bounds the client connections served at once. Each one
	// holds a goroutine, a client socket and an upstream connection, and the
	// guest can open them faster than they drain; past the limit the proxy
	// answers 503 and closes instead of queueing without bound.
	maxConnections = 512

	// shutdownGrace bounds how long Serve waits for in-flight handlers once the
	// listener has closed. Closing their connections unblocks the reads they
	// are parked in; the bound covers a handler blocked in a dial, which Close
	// cannot interrupt, and keeps shutdown inside the guest's 10s SIGTERM
	// window.
	shutdownGrace = 2 * time.Second

	// requestTimeout bounds one request/response exchange as seen from the
	// client, including reading the request head. It is what eventually drops
	// an idle keep-alive connection.
	requestTimeout = 5 * time.Minute

	// idleTimeout bounds a single read from the origin or write to the client
	// while a response streams. It is refreshed on every operation, so a slow
	// download that keeps making progress is never cut off, while a stalled one
	// releases its connection slot instead of holding it for the whole request.
	idleTimeout = 2 * time.Minute

	// refuseTimeout bounds the 503 written to a connection accepted while the
	// bound is reached, so a peer that never reads cannot stall the accept loop.
	refuseTimeout = 500 * time.Millisecond
)

// Gate decides whether a request may leave. A nil Gate allows everything, which
// is the right default for a VM with no engagement attached.
type Gate interface {
	// Allow reports whether this request may be forwarded. A refusal is
	// recorded with the same weight as a forwarded request, because a blocked
	// attempt is itself part of the engagement's record.
	Allow(ctx context.Context, host, path string) (bool, string)
}

// Proxy is the engagement's outbound HTTP path.
type Proxy struct {
	CA       *CA
	Identity Identity
	Gate     Gate

	dialer *dialer
	reach  *reachCache
	ln     net.Listener

	// slots is the connection bound, as a counting semaphore: one token per
	// connection being served. A guest that opens connections faster than they
	// drain would otherwise grow a goroutine and two sockets per connection
	// with nothing to stop it.
	slots chan struct{}

	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]context.CancelFunc
	handlers sync.WaitGroup
}

// New returns a proxy bound to addr.
func New(addr string, ca *CA, id Identity, gate Gate) (*Proxy, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		CA: ca, Identity: id, Gate: gate,
		dialer: newDialer(), reach: newReachCache(connectProbeLimit), ln: ln,
		slots: make(chan struct{}, maxConnections),
		conns: map[net.Conn]context.CancelFunc{},
	}, nil
}

// Addr is the address the proxy listens on.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Close stops accepting new connections and drops the ones being served.
//
// Each connection's context is cancelled before its socket is closed, so an
// upstream dial in flight fails promptly instead of running to its timeout, and
// closing the socket unblocks a handler parked in a read.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	cancels := make([]context.CancelFunc, 0, len(p.conns))
	for c, cancel := range p.conns {
		conns = append(conns, c)
		if cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	p.mu.Unlock()
	err := p.ln.Close()
	for _, cancel := range cancels {
		cancel()
	}
	for _, c := range conns {
		c.Close()
	}
	return err
}

// Serve accepts connections until the listener is closed or ctx is cancelled.
//
// The guest sends SIGTERM on stop and waits 10s before SIGKILL, so cancellation
// has to stop the proxy rather than wait out the listener.
func (p *Proxy) Serve(ctx context.Context) error {
	// Closing the listener unblocks Accept. The goroutine exits on ctx too, so a
	// Serve that returns for another reason does not leak it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = p.Close()
		case <-done:
		}
	}()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			// Handlers still running have had their connections closed by
			// Close; wait for them, boundedly, before reporting a clean stop.
			p.drain()
			if closed {
				return nil
			}
			return err
		}
		if !p.acquire() {
			p.refuse(conn)
			continue
		}
		connCtx, cancel := context.WithCancel(ctx)
		untrack := p.track(conn, cancel)
		p.handlers.Add(1)
		go func() {
			defer p.handlers.Done()
			defer cancel()
			defer untrack()
			defer p.release()
			p.handle(connCtx, conn)
		}()
	}
}

// acquire takes a connection slot, reporting whether one was free.
func (p *Proxy) acquire() bool {
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// release returns a connection slot. Every accepted connection returns its
// token exactly once, however the handler exits.
func (p *Proxy) release() { <-p.slots }

// refuse answers a connection accepted while the bound is reached.
//
// The status is written before the close because a peer that only sees a reset
// retries immediately, which deepens the overload; a 503 is HTTP's way of
// saying the request was understood and refused for now. The write is bounded
// and synchronous on purpose: it keeps the number of refusals in flight bounded
// by the accept loop itself, and a peer that never reads costs one short
// timeout rather than a goroutine.
func (p *Proxy) refuse(conn net.Conn) {
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(refuseTimeout))
	io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// track registers a connection so Close can drop it and cancel its context, and
// returns the func that unregisters it.
//
// Upstream connections are tracked too, with a nil cancel: a handler parked in
// a read from the origin only notices a shutdown if that socket is closed.
func (p *Proxy) track(c net.Conn, cancel context.CancelFunc) func() {
	p.mu.Lock()
	p.conns[c] = cancel
	closed := p.closed
	p.mu.Unlock()
	if closed {
		// Close ran between Accept and this registration. Honour it rather
		// than serving a connection the caller believes is gone.
		if cancel != nil {
			cancel()
		}
		c.Close()
	}
	return func() {
		p.mu.Lock()
		delete(p.conns, c)
		p.mu.Unlock()
	}
}

// drain waits, boundedly, for the handlers already running.
//
// Close has cancelled their contexts and closed their sockets, which unblocks
// the reads and dials they are parked in; the bound keeps shutdown inside the
// guest's SIGTERM window even if one is stuck in a syscall.
func (p *Proxy) drain() {
	waited := make(chan struct{})
	go func() {
		p.handlers.Wait()
		close(waited)
	}()
	timer := time.NewTimer(shutdownGrace)
	defer timer.Stop()
	select {
	case <-waited:
	case <-timer.C:
	}
}

// handle serves one client connection, which may carry several requests.
func (p *Proxy) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(requestTimeout))
		method, target, headers, err := readRequestHead(br)
		if err != nil {
			return
		}
		if method == "CONNECT" {
			p.mitm(ctx, conn, br, target)
			// The TLS session owns the connection from here.
			return
		}
		if !p.forwardPlain(ctx, conn, method, target, headers, br) {
			return
		}
	}
}

// mitm terminates the client's TLS with a leaf certificate and forwards the
// plaintext requests inside it, re-encrypting upstream with the browser
// fingerprint.
//
// The target is probed first. A 200 to CONNECT is a promise that the target was
// reached, and the proxy used to make that promise for a host it had never
// dialled: the failure then arrived inside the tunnel as a 502 the client read
// as the site's answer. A probe keeps "the port is open" a fact about the
// target.
func (p *Proxy) mitm(ctx context.Context, conn net.Conn, br *bufio.Reader, authority string) {
	if !p.reachable(ctx, authority) {
		writeEgressFailure(conn, egressDialFailed)
		return
	}
	host := hostFromAddr(authority)
	leaf, err := p.CA.Leaf(host)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// A CONNECT tunnel carries opaque bytes (RFC 9110 9.3.6). The recording
	// proxy always CONNECTs to its upstream - even for an http:// target - so a
	// plaintext request arrives here; terminating TLS on it consumes the request
	// and answers nothing, which is how every plain-HTTP target became a 502.
	// Peek one byte: 0x16 opens a TLS handshake, anything else is relayed.
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 0x16 {
		p.relayTunnel(ctx, conn, br, authority, host)
		return
	}

	tlsConn := tls.Server(&bufferedConn{Conn: conn, r: br}, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	inner := bufio.NewReader(tlsConn)
	for {
		tlsConn.SetDeadline(time.Now().Add(requestTimeout))
		method, target, headers, err := readRequestHead(inner)
		if err != nil {
			return
		}
		if !p.forward(ctx, tlsConn, inner, method, target, headers, authority, true) {
			return
		}
	}
}

// relayTunnel forwards a CONNECT tunnel verbatim, without terminating TLS.
//
// It exists for the proxy-to-proxy hop: the recording proxy CONNECTs to this
// proxy for plaintext targets too, and a TLS handshake there would swallow the
// request. The engagement gate and the reachability probe still apply, so a
// relay is not an unthrottled path to a target, and the connection is logged
// like any other.
func (p *Proxy) relayTunnel(ctx context.Context, conn net.Conn, br *bufio.Reader, authority, host string) {
	started := time.Now()
	if p.Gate != nil {
		if ok, reason := p.Gate.Allow(ctx, host, ""); !ok {
			logEvent(ctx, Event{Time: started, Method: "CONNECT", Host: host,
				Refused: true, Reason: reason, Duration: time.Since(started)})
			body := "blocked by engagement policy: " + reason
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(body), body)
			return
		}
	}
	upstream, err := (&net.Dialer{Timeout: connectProbeTimeout}).DialContext(ctx, "tcp", authority)
	if err != nil {
		logEvent(ctx, Event{Time: started, Method: "CONNECT", Host: host,
			Refused: true, Reason: "dial: " + err.Error(), Duration: time.Since(started)})
		writeEgressFailure(conn, egressDialFailed)
		return
	}
	defer upstream.Close()
	logEvent(ctx, Event{Time: started, Method: "CONNECT", Host: host, Duration: time.Since(started)})

	// A tunnel outlives one request, so the per-request deadline must go; the
	// idle timeout is enforced per copy below instead.
	conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// reachable reports whether authority accepted a TCP connection, dialling once
// per TTL.
//
// The probe dials and closes rather than handing the socket to the request that
// follows: that request re-dials through the uTLS path because its ALPN depends
// on what the origin negotiates, and a successful probe must not leave a socket
// leaking. A cached failure short-circuits the dial entirely, which is what
// keeps a retry loop against a dark host from costing one dial per request.
func (p *Proxy) reachable(ctx context.Context, authority string) bool {
	if ok, cached := p.reach.lookup(authority); cached {
		return ok
	}
	c, err := (&net.Dialer{Timeout: connectProbeTimeout}).DialContext(ctx, "tcp", authority)
	if err == nil {
		c.Close()
	}
	p.reach.put(authority, err == nil)
	return err == nil
}

// writeEgressFailure answers a request the proxy could not complete against the
// target. The header is what makes the failure attributable: without it a
// client inside the tunnel stores the proxy's status as the site's.
func writeEgressFailure(conn net.Conn, reason string) {
	body := "m1nervac0nsole egress: upstream " + reason + "\n"
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n%s: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		HeaderEgress, reason, len(body), body)
}

// forwardPlain forwards a non-CONNECT proxy request, whose target is absolute.
func (p *Proxy) forwardPlain(ctx context.Context, conn net.Conn, method, target string, headers [][2]string, br *bufio.Reader) bool {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return false
	}
	useTLS := u.Scheme == "https"
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return p.forward(ctx, conn, br, method, path, headers, dialAuthority(u), useTLS)
}

// dialAuthority returns host:port for an absolute proxy target, filling in the
// scheme default when the URL omits the port, which a proxy request does.
func dialAuthority(u *url.URL) string {
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return u.Host
	}
	// url.Host keeps the brackets on an IPv6 literal, and JoinHostPort adds its
	// own pair — so strip them first or the address becomes [[2001:db8::1]]:80.
	host := strings.Trim(u.Host, "[]")
	if u.Scheme == "https" {
		return net.JoinHostPort(host, "443")
	}
	return net.JoinHostPort(host, "80")
}

// forward performs one request/response exchange and returns whether the client
// connection can carry another.
func (p *Proxy) forward(ctx context.Context, conn net.Conn, br *bufio.Reader, method, path string, headers [][2]string, authority string, useTLS bool) bool {
	started := time.Now()
	// authority carries the port for dialling; hostOnly is what goes in SNI and
	// in the Host header, where a default port must not appear.
	hostOnly := hostFromAddr(authority)

	if p.Gate != nil {
		if ok, reason := p.Gate.Allow(ctx, hostOnly, path); !ok {
			logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
				Refused: true, Reason: reason, Duration: time.Since(started)})
			body := "blocked by engagement policy: " + reason
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(body), body)
			return false
		}
	}

	body, err := readBody(br, headers)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return false
	}

	var upstream net.Conn
	var negotiated string
	if useTLS {
		upstream, negotiated, err = p.dialer.dial(ctx, authority, hostOnly, alpnFor(true))
	} else {
		// DialContext, not DialTimeout: Close cancels the per-connection
		// context, and a dial in flight must abort with it rather than run to
		// its timeout and hold a slot through shutdown.
		upstream, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", authority)
	}
	if err != nil {
		logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
			Refused: true, Reason: "dial: " + err.Error(), Duration: time.Since(started)})
		writeEgressFailure(conn, egressDialFailed)
		return false
	}
	defer upstream.Close()
	// The origin socket is tracked as well as the client's: a shutdown has to
	// interrupt a handler parked in a read from an origin that has gone quiet.
	untrack := p.track(upstream, nil)
	defer untrack()
	// Every origin read and write refreshes the deadline, so a transfer that
	// keeps making progress is never cut off by an absolute deadline while a
	// stalled one still times out and releases its connection slot.
	origin := &idleConn{Conn: upstream, d: idleTimeout}

	// A server that selected h2 must be spoken to in h2: the uTLS Chrome preset
	// carries its own ALPN extension, so a re-dial to force HTTP/1.1 negotiates
	// h2 again and an HTTP/1.1 request over it is dropped. Speaking h2 on the
	// connection already fingerprinted keeps the fingerprint unchanged.
	var resp *http.Response
	if negotiated == "h2" {
		resp, err = p.forwardH2(ctx, origin, method, path, authority, headers, body)
	} else {
		resp, err = p.forwardH1(origin, method, path, authority, headers, body)
	}
	if err != nil {
		logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
			Refused: true, Reason: "read: " + err.Error(), Duration: time.Since(started)})
		writeEgressFailure(conn, egressReadFailed)
		return false
	}
	// The origin socket is closed before the response body. Closing the body
	// first would drain what is still unread — for a close-delimited body that
	// means waiting for an origin that may never send again, holding the
	// handler and its connection slot until the idle deadline. Closing the
	// socket first makes that drain fail at once.
	defer func() {
		upstream.Close()
		resp.Body.Close()
	}()

	return p.relay(ctx, conn, resp, method, hostOnly, path, started, acceptedEncodings(headers))
}

// forwardH1 sends one HTTP/1.1 request and reads the response head.
//
// http.ReadResponse does the framing: it decides from the status and headers
// whether the body is declared, chunked or close-delimited, and its body reader
// reports a short body as unexpected EOF instead of a clean end. When a message
// declares both a Transfer-Encoding and a Content-Length, the encoding wins and
// the length is dropped, as RFC 9112 requires of an intermediary. The body is
// not read here — relay streams it — so nothing in this path is sized by the
// response.
func (p *Proxy) forwardH1(upstream net.Conn, method, path, authority string, headers [][2]string, body []byte) (*http.Response, error) {
	req := buildRequest(method, path, hostHeader(authority), p.Identity, headers, body)
	if _, err := upstream.Write(req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(upstream)
	// An informational response is not the answer to the request; it must be
	// consumed so the final response is what reaches the client.
	for range 8 {
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 1 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		resp.Body.Close()
	}
	return nil, fmt.Errorf("origin sent too many informational responses")
}

// relay streams resp to the client and reports whether the client connection
// can carry another request.
//
// The head is written by net/http's Response.Write, so the client receives the
// standard library's framing: a declared length stays declared, a chunked body
// is re-chunked, and a length-less body is sent chunked so the connection stays
// reusable and a short body is detectable because its final chunk never comes.
// The body is copied as it arrives, never assembled, so no response size is
// allocated or capped.
//
// The proxy asks the origin for the browser's "gzip, deflate, br", which may
// include a coding the caller did not negotiate. Such a body is decoded here
// (and Content-Encoding/Content-Length dropped) rather than forwarded, because
// the caller would otherwise store compressed bytes as the site's answer. A
// coding that cannot be decoded is answered as a proxy failure, never passed on
// as target content.
//
// Once the head is on the wire nothing else is written on error: the client
// sees an incomplete body and a close, not a second status line.
func (p *Proxy) relay(ctx context.Context, conn net.Conn, resp *http.Response, method, hostOnly, path string, started time.Time, accepted map[string]bool) bool {
	status := resp.StatusCode
	resp.ProtoMajor, resp.ProtoMinor = 1, 1
	resp.Request = &http.Request{Method: method}
	resp.TransferEncoding = nil
	// The origin's own close preference is about the origin connection, which
	// is closed after this exchange. The client side is re-framed here, so a
	// length-less body becomes chunked and keep-alive survives.
	resp.Close = false
	bodyAllowed := responseBodyAllowed(method, status)
	var decoded *decodingBody
	// Only a response with a body can deliver unreadable content. A 304's
	// Content-Encoding describes the cached representation and must survive, so
	// body-less responses are forwarded untouched.
	if codings := contentCodings(resp.Header.Get("Content-Encoding")); bodyAllowed && len(codings) > 0 && !negotiated(codings, accepted) {
		// A 206 is a byte range of the coded representation. Decoding it would
		// invent a partial body its Content-Range no longer describes, and
		// forwarding it hands the caller bytes it never negotiated, so it fails
		// closed instead of either.
		if status == http.StatusPartialContent {
			logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
				Status: http.StatusBadGateway, Refused: true,
				Reason: "decode: partial content in an unaccepted coding", Duration: time.Since(started)})
			writeEgressFailure(conn, egressDecodeFailed)
			return false
		}
		// The headers describe the coded body. Removing the length also makes
		// the client side chunked, since the decoded length is not known yet.
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.Header.Del("Content-MD5")    // computed over the coded bytes
		resp.Header.Del("Content-Digest") // likewise
		resp.ContentLength = -1
		body, err := decodeContent(resp.Body, codings)
		if err != nil {
			logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
				Status: http.StatusBadGateway, Refused: true,
				Reason: "decode: " + err.Error(), Duration: time.Since(started)})
			writeEgressFailure(conn, egressDecodeFailed)
			return false
		}
		decoded = body
		resp.Body = body
	}
	if bodyAllowed && resp.ContentLength < 0 {
		resp.TransferEncoding = []string{"chunked"}
	}
	// Trailers are kept. Response.Write re-emits the declared names and, for a
	// chunked body, the values read from the origin; the writer validates both
	// before writing, so nothing that would break the message gets through.
	// Dropping them would lose part of the response a client may rely on.
	stripHopByHop(resp.Header, status)

	body := &countingBody{rc: resp.Body}
	resp.Body = body

	// The write deadline is refreshed per write, so a slow but progressing
	// download is not cut off by the request deadline while a stalled client
	// still times out and gives its slot back.
	err := resp.Write(idleWriter{c: conn, d: idleTimeout})

	// Log what actually happened. A relay that failed mid-body delivered a
	// short response, so recording it as an ordinary "200, N bytes" would be
	// indistinguishable from a completed exchange.
	reason := ""
	if err != nil && decoded != nil && decoded.err != nil {
		// The head is already on the wire, so the failure can only be a short
		// body; naming decoding in the log keeps it from reading as a
		// truncated target response.
		reason = "decode: " + decoded.err.Error()
	}
	logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
		Status: status, Bytes: body.n, Reason: reason, Duration: time.Since(started), Aborted: err != nil})

	if err != nil {
		return false
	}
	// A HEAD response with no declared length cannot be delimited without
	// closing, and a 101 hands the connection to a protocol this proxy does not
	// tunnel; both end the client connection.
	return status != http.StatusSwitchingProtocols && (bodyAllowed || resp.ContentLength >= 0)
}

// responseBodyAllowed reports whether a response to method may carry a body.
func responseBodyAllowed(method string, status int) bool {
	if method == "HEAD" || status/100 == 1 {
		return false
	}
	return status != http.StatusNoContent && status != http.StatusNotModified
}

// stripHopByHop removes the headers a proxy must not forward, per RFC 7230
// §6.1. A 101 keeps Connection and Upgrade, which are the protocol switch
// itself rather than a hop-by-hop hint.
func stripHopByHop(h http.Header, status int) {
	keepUpgrade := status == http.StatusSwitchingProtocols
	for key := range h {
		lower := strings.ToLower(key)
		if !hopByHop[lower] {
			continue
		}
		if keepUpgrade && (lower == "connection" || lower == "upgrade") {
			continue
		}
		delete(h, key)
	}
}

// countingBody counts the body bytes written to the client, for the traffic
// record. The count is what the client actually received, not what the origin
// declared, so a truncated response is recorded as short.
type countingBody struct {
	rc io.ReadCloser
	n  int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.n += int64(n)
	return n, err
}

func (b *countingBody) Close() error { return b.rc.Close() }

// idleConn refreshes the deadline before every operation, so a transfer that
// keeps making progress is never cut off by an absolute deadline while a
// stalled one still times out and releases its connection slot.
type idleConn struct {
	net.Conn
	d time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.d))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.d))
	return c.Conn.Write(p)
}

// idleWriter refreshes the client's write deadline before each write.
type idleWriter struct {
	c net.Conn
	d time.Duration
}

func (w idleWriter) Write(p []byte) (int, error) {
	w.c.SetWriteDeadline(time.Now().Add(w.d))
	return w.c.Write(p)
}

// hostHeader is the Host value for an authority: the port is omitted when it is
// the scheme default, which is what a browser sends.
//
// An IPv6 literal keeps its brackets even without a port, because that is the
// only form Host accepts; SplitHostPort hands back the bare address.
func hostHeader(authority string) string {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	if port == "80" || port == "443" {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

// buildRequest writes the request with the identity's header set and order.
func buildRequest(method, path, host string, id Identity, in [][2]string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	for _, kv := range canonicalHeaders(id, method, host, path, in) {
		if strings.EqualFold(kv[0], "content-length") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", kv[0], kv[1])
	}
	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// forwardH2 sends one request over an already-dialled h2 connection and returns
// the response head; its body is streamed by relay.
//
// The connection carries the uTLS Chrome handshake, so the TLS fingerprint is
// unchanged; only the HTTP framing differs from the HTTP/1.1 path. Headers come
// from the same canonical set, minus the ones HTTP/2 forbids (Connection and the
// other hop-by-hop names), because a forbidden header makes RoundTrip fail
// rather than being dropped silently.
//
// authority keeps the port, so a nondefault one reaches the origin both in the
// URL and in the :authority pseudo-header; hostOnly would silently redirect
// every https request to port 443.
func (p *Proxy) forwardH2(ctx context.Context, upstream net.Conn, method, path, authority string, headers [][2]string, body []byte) (*http.Response, error) {
	// The transport is per-request because it is bound to this one
	// already-fingerprinted connection. It is not closed here: the response body
	// is still streaming, and the caller closes the connection when the exchange
	// ends, which ends the transport's read loop with it.
	tr := &http2.Transport{
		// Hand back the connection we already fingerprinted instead of dialling
		// again: a second handshake would present a second identity.
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return upstream, nil
		},
	}
	target := "https://" + authority + path
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	host := hostHeader(authority)
	req.Host = host
	for _, kv := range canonicalHeaders(p.Identity, method, host, path, headers) {
		key := strings.ToLower(kv[0])
		if hopByHop[key] || key == "host" || key == "content-length" {
			continue
		}
		req.Header.Set(kv[0], kv[1])
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// readBody consumes a request body according to the headers that declare it.
//
// Transfer-Encoding wins over Content-Length (RFC 7230 §3.3.3), so the headers
// are scanned for both before either is acted on: returning at the first match
// would read the framing bytes as the body when Content-Length came first and
// leave the chunk framing in the buffer to be parsed as the next request.
func readBody(br *bufio.Reader, headers [][2]string) ([]byte, error) {
	var contentLength string
	chunked := false
	for _, kv := range headers {
		switch strings.ToLower(kv[0]) {
		case "content-length":
			contentLength = strings.TrimSpace(kv[1])
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(kv[1]), "chunked") {
				chunked = true
			}
		}
	}
	if chunked {
		if contentLength != "" {
			return nil, fmt.Errorf("both Transfer-Encoding and Content-Length present")
		}
		return readChunked(br)
	}
	if contentLength == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(contentLength)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("bad content-length %q", contentLength)
	}
	if n > maxBody {
		return nil, fmt.Errorf("body exceeds %d bytes", maxBody)
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(br, buf)
	return buf, err
}

// readChunked buffers a chunked body. Request bodies go through here because
// they are replayed to the origin with a Content-Length, which needs the length.
//
// Decoding is httputil's, not this package's: the standard reader already
// rejects a negative or overflowing chunk size, a chunk line over 4096 bytes
// and a stream that ends mid-chunk, and every one of those cases reached a
// custom reader here as a panic or a silently short body.
func readChunked(br *bufio.Reader) ([]byte, error) {
	var out bytes.Buffer
	// maxBody+1 so a body exactly at the cap is accepted and one byte over is
	// detectable rather than silently cut.
	if _, err := io.Copy(&out, io.LimitReader(httputil.NewChunkedReader(br), maxBody+1)); err != nil {
		return nil, err
	}
	if out.Len() > maxBody {
		return nil, fmt.Errorf("chunked body exceeds %d bytes", maxBody)
	}
	if err := discardTrailer(br); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// discardTrailer consumes the trailer section that follows the last chunk.
//
// httputil's chunked reader stops at the zero-length chunk and leaves the
// trailer section — at minimum the final CRLF — in the buffer. On a keep-alive
// connection those bytes belong to this message, so they must be consumed here
// or the next request read treats an empty line as a request line.
//
// The bounds keep a client from streaming trailer lines forever; an origin that
// closes without the final CRLF still ends the message, since the body itself
// was complete.
func discardTrailer(br *bufio.Reader) error {
	const (
		maxTrailerLines = 64
		maxTrailerLine  = 8 << 10
	)
	for range maxTrailerLines {
		line, err := br.ReadString('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(line) > maxTrailerLine {
			return fmt.Errorf("chunked trailer line exceeds %d bytes", maxTrailerLine)
		}
		if trimCRLF(line) == "" {
			return nil
		}
	}
	return fmt.Errorf("chunked trailer section exceeds %d lines", maxTrailerLines)
}

// bufferedConn lets the TLS server read bytes the bufio.Reader already buffered
// before the CONNECT reply was written.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

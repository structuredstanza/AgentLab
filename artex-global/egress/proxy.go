package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxBody bounds one forwarded body. A scanner fetching a large file should be
// truncated rather than allowed to exhaust the guest's memory.
const maxBody = 32 << 20

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
	ln     net.Listener

	mu     sync.Mutex
	closed bool
}

// New returns a proxy bound to addr.
func New(addr string, ca *CA, id Identity, gate Gate) (*Proxy, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Proxy{CA: ca, Identity: id, Gate: gate, dialer: newDialer(), ln: ln}, nil
}

// Addr is the address the proxy listens on.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Close stops accepting new connections.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return p.ln.Close()
}

// Serve accepts connections until the listener is closed.
func (p *Proxy) Serve(ctx context.Context) error {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go p.handle(ctx, conn)
	}
}

// handle serves one client connection, which may carry several requests.
func (p *Proxy) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Minute))
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
func (p *Proxy) mitm(ctx context.Context, conn net.Conn, br *bufio.Reader, authority string) {
	host := hostFromAddr(authority)
	leaf, err := p.CA.Leaf(host)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

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
		tlsConn.SetDeadline(time.Now().Add(5 * time.Minute))
		method, target, headers, err := readRequestHead(inner)
		if err != nil {
			return
		}
		if !p.forward(ctx, tlsConn, inner, method, target, headers, authority, true) {
			return
		}
	}
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
	return p.forward(ctx, conn, br, method, path, headers, u.Host, useTLS)
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
	if useTLS {
		var negotiated string
		upstream, negotiated, err = p.dialer.dial(authority, hostOnly, alpnFor(true))
		if err != nil {
			logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
				Refused: true, Reason: "dial: " + err.Error(), Duration: time.Since(started)})
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return false
		}
		// uTLS negotiated h2 by default; this forwarder speaks HTTP/1.1, so a
		// server that selected h2 is re-dialled offering only http/1.1.
		if negotiated == "h2" {
			upstream.Close()
			upstream, _, err = p.dialer.dial(authority, hostOnly, []string{"http/1.1"})
			if err != nil {
				fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
				return false
			}
		}
	} else {
		upstream, err = net.DialTimeout("tcp", authority, 15e9)
		if err != nil {
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return false
		}
	}
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(5 * time.Minute))

	req := buildRequest(method, path, hostHeader(authority), p.Identity, headers, body)
	if _, err := upstream.Write(req); err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return false
	}

	status, respBody, respHeaders, err := readResponse(bufio.NewReader(upstream), method)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
			Refused: true, Reason: "read: " + err.Error(), Duration: time.Since(started)})
		return false
	}

	out := buildResponse(status, respHeaders, respBody)
	if _, err := conn.Write(out); err != nil {
		return false
	}
	logEvent(ctx, Event{Time: started, Method: method, Host: hostOnly, Path: path,
		Status: status, Bytes: int64(len(respBody)), Duration: time.Since(started)})
	return status != 101
}

// hostHeader is the Host value for an authority: the port is omitted when it is
// the scheme default, which is what a browser sends.
func hostHeader(authority string) string {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	if port == "80" || port == "443" {
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

// buildResponse writes the response with the body length made explicit, so the
// client does not have to decode a transfer-encoding it may not expect.
func buildResponse(status int, headers [][2]string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, statusText(status))
	for _, kv := range headers {
		key := strings.ToLower(kv[0])
		if hopByHop[key] || key == "content-length" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", kv[0], kv[1])
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(body))
	b.Write(body)
	return b.Bytes()
}

// readBody consumes a request body according to the headers that declare it.
func readBody(br *bufio.Reader, headers [][2]string) ([]byte, error) {
	for _, kv := range headers {
		switch strings.ToLower(kv[0]) {
		case "content-length":
			n, err := strconv.Atoi(strings.TrimSpace(kv[1]))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("bad content-length %q", kv[1])
			}
			if n > maxBody {
				return nil, fmt.Errorf("body exceeds %d bytes", maxBody)
			}
			buf := make([]byte, n)
			_, err = io.ReadFull(br, buf)
			return buf, err
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(kv[1]), "chunked") {
				return readChunked(br)
			}
		}
	}
	return nil, nil
}

func readChunked(br *bufio.Reader) ([]byte, error) {
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sizeText := trimCRLF(line)
		if i := strings.IndexByte(sizeText, ';'); i >= 0 {
			sizeText = sizeText[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad chunk size %q", sizeText)
		}
		if size == 0 {
			// Consume the trailer section.
			for {
				trailer, err := br.ReadString('\n')
				if err != nil {
					return out.Bytes(), nil
				}
				if trimCRLF(trailer) == "" {
					return out.Bytes(), nil
				}
			}
		}
		if out.Len()+int(size) > maxBody {
			return nil, fmt.Errorf("chunked body exceeds %d bytes", maxBody)
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, err
		}
		out.Write(chunk)
		// Each chunk is followed by CRLF.
		if _, err := br.ReadString('\n'); err != nil {
			return nil, err
		}
	}
}

// readResponse reads a response head and body, decoding chunked bodies so the
// client receives a plain body with a length.
func readResponse(br *bufio.Reader, method string) (int, []byte, [][2]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, nil, err
	}
	parts := splitSpace(trimCRLF(line))
	if len(parts) < 2 {
		return 0, nil, nil, fmt.Errorf("malformed status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("malformed status %q", parts[1])
	}
	var headers [][2]string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, nil, nil, err
		}
		trimmed := trimCRLF(line)
		if trimmed == "" {
			break
		}
		if k, v, ok := splitHeader(trimmed); ok {
			headers = append(headers, [2]string{k, v})
		}
	}
	if method == "HEAD" || status == 204 || status == 304 {
		return status, nil, headers, nil
	}

	chunked := false
	var length int64 = -1
	for _, kv := range headers {
		switch strings.ToLower(kv[0]) {
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(kv[1]), "chunked") {
				chunked = true
			}
		case "content-length":
			if n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64); err == nil {
				length = n
			}
		}
	}
	if chunked {
		body, err := readChunked(br)
		return status, body, headers, err
	}
	if length >= 0 {
		if length > maxBody {
			length = maxBody
		}
		body := make([]byte, length)
		_, err := io.ReadFull(br, body)
		if err != nil && err != io.ErrUnexpectedEOF {
			return status, body, headers, err
		}
		return status, body, headers, nil
	}
	// No length and no chunking: read until the origin closes.
	body, err := io.ReadAll(io.LimitReader(br, maxBody))
	return status, body, headers, err
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	}
	return "OK"
}

// bufferedConn lets the TLS server read bytes the bufio.Reader already buffered
// before the CONNECT reply was written.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

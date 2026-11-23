package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	for _, addon := range proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	return wc, nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) PeekBuffered() ([]byte, error) {
	return c.r.Peek(c.r.Buffered())
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.Tls {
		c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.ClientConn.Conn.Close()
		}
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Infof("Proxy start listen at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.ServeHTTP",
		"host": req.Host,
	})
	// Add entry proxy authentication
	if e.proxy.authProxy != nil {
		b, err := e.proxy.authProxy(res, req)
		if !b {
			log.Errorf("Proxy authentication failed: %s", err.Error())
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
	}
	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res = helper.NewResponseCheck(res)
		for _, addon := range proxy.Addons {
			addon.AccessProxyServer(req, res)
		}
		if res, ok := res.(*helper.ResponseCheck); ok {
			if !res.Wrote {
				res.WriteHeader(400)
				io.WriteString(res, "此为代理服务器，不能直接发起请求")
			}
		}
		return
	}

	// http proxy
	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.handleConnect",
		"host": req.Host,
	})

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = shouldIntercept
	defer f.finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
	}

	if !shouldIntercept {
		log.Debugf("begin transpond %v", req.Host)
		e.directTransfer(res, req, f)
		return
	}

	// An OriginTransport must dial before the 200 so a denied or unreachable
	// origin is never answered with a forged tunnel, whatever UpstreamCert says.
	if f.ConnContext.ClientConn.UpstreamCert || proxy.originTransport() != nil {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	log.Debugf("begin intercept %v", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		for _, addon := range e.proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		for _, addon := range e.proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	for _, addon := range e.proxy.Addons {
		addon.Responseheaders(f)
	}

	return cconn, nil
}

func (e *entry) directTransfer(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.directTransfer",
		"host": req.Host,
	})

	conn, err := e.dialOrigin(req, f)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		res.WriteHeader(502)
		return
	}
	defer conn.Close()

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		return
	}
	defer cconn.Close()

	transfer(log, conn, cconn)
}

// dialOrigin opens the origin connection for a non-intercepted tunnel. An
// OriginTransport still authorizes it, so a passthrough can never skip policy.
func (e *entry) dialOrigin(req *http.Request, f *Flow) (net.Conn, error) {
	if ot := e.proxy.originTransport(); ot != nil {
		return ot.Dial(req.Context(), f.ConnContext, req)
	}
	return e.proxy.getUpstreamConn(req.Context(), req)
}

// writeOriginError replies to a failed CONNECT. An OriginTransport classifies
// its own failures, so the client sees the stage and reason instead of a bare 502.
func writeOriginError(res http.ResponseWriter, err error) {
	var oe *OriginError
	if !errors.As(err, &oe) {
		res.WriteHeader(502)
		return
	}
	if oe.Stage != "" {
		res.Header().Set("X-M1nervac0nsole-Gateway", oe.Stage)
	}
	for k, vs := range oe.Header {
		res.Header()[k] = vs
	}
	status := oe.Status
	if status == 0 {
		status = 502
	}
	res.WriteHeader(status)
	if oe.Reason != "" {
		_, _ = io.WriteString(res, oe.Reason+"\n")
	}
}

// firstBytesWait bounds the wait for a client's first bytes after CONNECT. A
// server-speaks-first protocol (FTP, SMTP, MySQL) sends nothing until the origin
// banner arrives, so an unbounded peek deadlocks both sides.
const firstBytesWait = 2 * time.Second

// peekFirst peeks the client's first 3 bytes under firstBytesWait. quiet reports
// a timeout: the client is waiting for the server, so the caller relays raw.
// bufio clears its sticky error when Peek returns it, so later reads still work.
func peekFirst(cconn net.Conn) (peek []byte, quiet bool, err error) {
	c := cconn.(*wrapClientConn)
	c.SetReadDeadline(time.Now().Add(firstBytesWait))
	peek, err = c.Peek(3)
	c.SetReadDeadline(time.Time{})
	var ne net.Error
	return peek, errors.As(err, &ne) && ne.Timeout(), err
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialFirstAttack",
		"host": req.Host,
	})

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		for _, addon := range proxy.Addons {
			addon.HTTPConnectError(f, err)
		}
		writeOriginError(res, err)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		return
	}

	peek, quiet, err := peekFirst(cconn)
	if quiet {
		transfer(log, conn, cconn)
		cconn.Close()
		conn.Close()
		return
	}
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}

	if helper.IsTls(peek) {
		f.ConnContext.ClientConn.Tls = true
		proxy.attacker.httpsTlsDial(req.Context(), cconn, conn)
		return
	}

	wsPeek, err := cconn.(*wrapClientConn).PeekBuffered()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}

	if helper.IsWebSocket(wsPeek) {
		err = proxy.webSocketHandler.handle(conn, cconn, f)
		if err != nil {
			log.Errorf("WebSocket handle error: %v", err)
			cconn.Close()
			conn.Close()
		}
		return
	}

	transfer(log, conn, cconn)
	cconn.Close()
	conn.Close()
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialLazyAttack",
		"host": req.Host,
	})

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		log.Error(err)
		return
	}

	peek, quiet, err := peekFirst(cconn)
	if quiet {
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			log.Error(err)
			return
		}
		transfer(log, conn, cconn)
		conn.Close()
		cconn.Close()
		return
	}
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if helper.IsTls(peek) {
		f.ConnContext.ClientConn.Tls = true
		proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
		return
	}

	wsPeek, err := cconn.(*wrapClientConn).PeekBuffered()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if helper.IsWebSocket(wsPeek) {
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			log.Error(err)
			return
		}
		err = proxy.webSocketHandler.handle(conn, cconn, f)
		if err != nil {
			log.Errorf("WebSocket handle error: %v", err)
			cconn.Close()
			conn.Close()
		}
		return
	}

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}
	transfer(log, conn, cconn)
	conn.Close()
	cconn.Close()
}

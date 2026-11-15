package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var wsHandshakeHeaders = map[string]struct{}{
	"Upgrade":                  {},
	"Connection":               {},
	"Sec-Websocket-Key":        {},
	"Sec-Websocket-Version":    {},
	"Sec-Websocket-Extensions": {},
	"Sec-Websocket-Protocol":   {},
}

func cloneHeaderWithoutWSHandshake(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vals := range h {
		if _, skip := wsHandshakeHeaders[http.CanonicalHeaderKey(k)]; skip {
			continue
		}
		if strings.EqualFold(k, "Host") {
			continue
		}
		cloned := make([]string, len(vals))
		copy(cloned, vals)
		out[k] = cloned
	}
	return out
}

type webSocketHandler struct {
	proxy *Proxy
}

func newWebSocketHandler(proxy *Proxy) *webSocketHandler {
	return &webSocketHandler{proxy: proxy}
}

// connResponseWriter 自定义 ResponseWriter，包装 net.Conn
// 用于让 websocket.Upgrader 能够升级连接
type connResponseWriter struct {
	conn        net.Conn
	header      http.Header
	statusCode  int
	wroteHeader bool
}

func newConnResponseWriter(conn net.Conn) *connResponseWriter {
	return &connResponseWriter{
		conn:   conn,
		header: make(http.Header),
	}
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(data)
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	w.wroteHeader = true
	w.statusCode = statusCode
}

// Hijack 劫持连接，返回底层的 net.Conn 和 bufio.ReadWriter
// websocket.Upgrader.Upgrade() 需要调用这个方法
func (w *connResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	buf := bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn))
	return w.conn, buf, nil
}

// handle 处理 WebSocket 连接
// serverConn: 与服务器的连接（已经建立 TCP 连接）
// clientConn: 与客户端的连接（已经完成 CONNECT，客户端发送了 WebSocket 握手请求）
func (h *webSocketHandler) handle(serverConn, clientConn net.Conn, f *Flow) error {
	// 步骤 1: 读取客户端握手请求
	buf := bufio.NewReader(clientConn)
	clientReq, err := http.ReadRequest(buf)
	if err != nil {
		log.Errorf("Failed to read client handshake: %v", err)
		return err
	}

	log.Debugf("Client WebSocket handshake: %s %s", clientReq.Method, clientReq.URL.Path)

	// 步骤 2: 使用 Dialer 连接到服务器
	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return serverConn, nil
		},
		// 使用已有的连接，不需要重新拨号
		HandshakeTimeout: 0,
	}

	serverURL := "ws://" + clientReq.Host + clientReq.URL.RequestURI()
	log.Debugf("Connecting to server: %s", serverURL)

	// Dialer 会自动添加所有必需的 WebSocket 握手头
	// 我们不传递 clientReq.Header，避免重复头的错误
	// The dialer rejects a duplicate Sec-Websocket-Protocol header, so the
	// client's list is re-supplied as its own subprotocol list.
	for _, v := range clientReq.Header.Values("Sec-Websocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				dialer.Subprotocols = append(dialer.Subprotocols, p)
			}
		}
	}
	serverWS, _, err := dialer.Dial(serverURL, nil)
	if err != nil {
		log.Errorf("Failed to dial server: %v", err)
		return err
	}
	defer serverWS.Close()

	log.Debugf("Server WebSocket connected, subprotocol: %s", serverWS.Subprotocol())

	// 步骤 3: 使用 Upgrader 升级客户端连接
	respWriter := newConnResponseWriter(clientConn)

	upgrader := &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // 代理模式下总是允许
		},
	}
	if sub := serverWS.Subprotocol(); sub != "" {
		upgrader.Subprotocols = []string{sub}
	}

	clientWS, err := upgrader.Upgrade(respWriter, clientReq, nil)
	if err != nil {
		log.Errorf("Failed to upgrade client connection: %v", err)
		return err
	}
	defer clientWS.Close()

	log.Debugf("Client WebSocket upgraded successfully")

	wsData := newWebSocketData()
	f.WebScoket = wsData

	for _, addon := range h.proxy.Addons {
		addon.WebSocketStart(f)
	}

	// 步骤 4: 双向转发消息
	return h.forwardMessages(clientWS, serverWS, f)
}

// forwardMessages 双向转发 WebSocket 消息
func (h *webSocketHandler) forwardMessages(clientWS, serverWS *websocket.Conn, f *Flow) error {
	defer func() {
		for _, addon := range h.proxy.Addons {
			addon.WebSocketEnd(f)
		}
	}()

	errChan := make(chan error, 2)

	// 客户端 -> 服务器
	go func() {
		var endErr error
		defer func() {
			// 优雅关闭服务器连接
			serverWS.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			serverWS.Close()
			// The close notification comes before the drain signal, so a recorder
			// that finalizes on WebSocketEnd has seen both closures.
			h.closed(f, true, endErr)
			errChan <- closeErr(endErr) // 正常关闭，不返回错误
		}()

		for {
			msgType, msg, err := clientWS.ReadMessage()
			if err != nil {
				endErr = err
				return
			}

			h.frame(f, f.WebScoket.addMessage(msgType, msg, true, h.proxy.Opts.MaxStreamEvents))

			if err := serverWS.WriteMessage(msgType, msg); err != nil {
				log.Errorf("Client -> Server: Write error: %v", err)
				endErr = err
				return
			}
		}
	}()

	// 服务器 -> 客户端
	go func() {
		var endErr error
		defer func() {
			// 优雅关闭客户端连接
			clientWS.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			clientWS.Close()
			h.closed(f, false, endErr)
			errChan <- closeErr(endErr)
		}()

		for {
			msgType, msg, err := serverWS.ReadMessage()
			if err != nil {
				endErr = err
				return
			}

			h.frame(f, f.WebScoket.addMessage(msgType, msg, false, h.proxy.Opts.MaxStreamEvents))

			if err := clientWS.WriteMessage(msgType, msg); err != nil {
				log.Errorf("Server -> Client: Write error: %v", err)
				endErr = err
				return
			}
		}
	}()

	// Both directions are drained before WebSocketEnd: whichever ends first
	// closes its side, which unblocks the other, and a recorder that finalizes on
	// End must have seen every frame and both closures. The first error is the
	// one reported.
	first := <-errChan
	second := <-errChan
	if first != nil {
		return first
	}
	return second
}

// closeErr maps one direction's terminal error to what forwardMessages returns:
// a normal close is not an error.
func closeErr(err error) error {
	if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return nil
	}
	return err
}

// frame delivers one forwarded message to the addons: the message itself to
// those that implement WebSocketRecorder, before it is forwarded, and the
// existing flow-level notification to every addon.
func (h *webSocketHandler) frame(f *Flow, m *WebSocketMessage) {
	for _, addon := range h.proxy.Addons {
		if rec, ok := addon.(WebSocketRecorder); ok {
			rec.WebSocketFrame(f, m)
		}
		addon.WebSocketMessage(f)
	}
}

// closed tells the addons that implement WebSocketRecorder that one direction
// ended, with the error that ended it (nil for a clean close).
func (h *webSocketHandler) closed(f *Flow, fromClient bool, err error) {
	for _, addon := range h.proxy.Addons {
		if rec, ok := addon.(WebSocketRecorder); ok {
			rec.WebSocketClosed(f, fromClient, err)
		}
	}
}

func (h *webSocketHandler) handleWSS(res http.ResponseWriter, req *http.Request) error {
	// 修复 WebSocket URL，确保包含完整的 scheme 和 host
	serverURL := "wss://" + req.Host + req.URL.RequestURI()
	log.Debugf("Connecting to WSS server: %s", serverURL)
	if parsedURL, err := url.Parse(serverURL); err == nil {
		req.URL = parsedURL
	}

	connCtx := req.Context().Value(connContextKey).(*ConnContext)
	ot := h.proxy.originTransport()

	// Step 1: the CONNECT already dialed and handshook the origin. Reuse that
	// conn: dialing again here leaks it and doubles the TLS handshake.
	var tlsConn net.Conn
	if connCtx.ServerConn != nil {
		tlsConn = connCtx.ServerConn.tlsConn
	}
	if tlsConn == nil {
		var plainConn net.Conn
		var err error
		if ot != nil {
			plainConn, err = ot.Dial(req.Context(), connCtx, req)
		} else {
			plainConn, err = h.proxy.getUpstreamConn(req.Context(), req)
		}
		if err != nil {
			log.Errorf("Failed to get upstream connection: %v", err)
			return err
		}

		// Step 2: create and initialize ServerConn
		serverConn := newServerConn()
		serverConn.Address = req.Host
		serverConn.Conn = &wrapServerConn{
			Conn:    plainConn,
			proxy:   h.proxy,
			connCtx: connCtx,
		}
		connCtx.ServerConn = serverConn

		// Step 3: call the addons' ServerConnected callback
		for _, addon := range connCtx.proxy.Addons {
			addon.ServerConnected(connCtx)
		}

		if ot != nil {
			c, state, err := ot.Handshake(req.Context(), connCtx, serverConn.Conn, req.URL.Hostname())
			if err != nil {
				log.Errorf("Failed to handshake WSS origin: %v", err)
				return err
			}
			serverConn.tlsConn = c
			serverConn.tlsState = &state
			for _, addon := range connCtx.proxy.Addons {
				addon.TlsEstablishedServer(connCtx)
			}
			tlsConn = c
		}
	}

	// Step 4: create the Dialer over the origin conn. NetDialTLSContext tells
	// gorilla the TLS handshake is already done, so it neither re-handshakes
	// nor consults TLSClientConfig.
	dialer := &websocket.Dialer{}
	// cloneHeaderWithoutWSHandshake drops Sec-Websocket-Protocol because the
	// dialer rejects it as a duplicate; re-supply it as the dialer's own
	// subprotocol list so the origin still negotiates one.
	for _, v := range req.Header.Values("Sec-Websocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				dialer.Subprotocols = append(dialer.Subprotocols, p)
			}
		}
	}
	if tlsConn != nil {
		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tlsConn, nil
		}
	} else {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			return connCtx.ServerConn.Conn, nil
		}
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: h.proxy.Opts.SslInsecure,
		}
	}

	upstreamHeader := cloneHeaderWithoutWSHandshake(req.Header)
	serverWS, _, err := dialer.Dial(serverURL, upstreamHeader)
	if err != nil {
		log.Errorf("Failed to dial WSS server: %v", err)
		return err
	}
	defer serverWS.Close()

	upgrader := &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // 代理模式下总是允许
		},
	}
	// Echo the subprotocol the origin chose; without it the client sees a
	// successful upgrade with no negotiated protocol.
	if sub := serverWS.Subprotocol(); sub != "" {
		upgrader.Subprotocols = []string{sub}
	}

	clientWS, err := upgrader.Upgrade(res, req, nil)
	if err != nil {
		log.Errorf("Failed to upgrade client connection: %v", err)
		return err
	}
	defer clientWS.Close()

	log.Debugf("Client WSS upgraded successfully")

	wsData := newWebSocketData()
	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = connCtx
	f.WebScoket = wsData
	defer f.finish()

	for _, addon := range h.proxy.Addons {
		addon.WebSocketStart(f)
	}

	// 双向转发消息
	return h.forwardMessages(clientWS, serverWS, f)
}

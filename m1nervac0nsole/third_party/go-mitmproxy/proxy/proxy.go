package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

type Options struct {
	Debug             int
	Addr              string
	StreamLargeBodies int64 // 当请求或响应体大于此字节时，转为 stream 模式
	SslInsecure       bool
	CaRootPath        string
	NewCaFunc         func() (cert.CA, error) //创建 Ca 的函数
	Upstream          string
	LogFilePath       string // Path to write logs to file

	// OriginTransport replaces the origin side of the proxy: the TCP dial, the
	// TLS handshake and the round trip. Nil keeps the upstream behaviour. The
	// proxy still owns client-side TLS termination, HTTP parsing, addon
	// dispatch and response framing.
	OriginTransport OriginTransport

	// MaxStreamEvents caps how many WebSocket messages and SSE events one flow
	// retains. 0 keeps every event, which grows without bound on a long-lived
	// stream.
	MaxStreamEvents int
}

// OriginTransport is the origin-side seam. Each method receives the connection
// context so an implementation can key its own session state by ConnContext.Id.
type OriginTransport interface {
	// Dial opens the transport connection for the CONNECT authority. It runs
	// before the 200, so its error is what the client sees instead of a false
	// tunnel. req is the CONNECT request (Proxy-Authorization is here).
	Dial(ctx context.Context, connCtx *ConnContext, req *http.Request) (net.Conn, error)

	// Handshake completes the origin TLS handshake over c for serverName and
	// returns the conn that replaces c plus the state reported to addons.
	Handshake(ctx context.Context, connCtx *ConnContext, c net.Conn, serverName string) (net.Conn, tls.ConnectionState, error)

	// RoundTrip sends req and returns the origin response. It owns per-request
	// authorization, pooling, h2 selection and the exit. It must not follow
	// redirects and must strip gateway credentials.
	RoundTrip(ctx context.Context, connCtx *ConnContext, req *http.Request) (*http.Response, error)
}

// OriginError is a classified origin-side failure. An OriginTransport returns
// it from Dial or Handshake so the CONNECT reply carries the stage instead of a
// bare 502, and the recorder can tell infrastructure from target failure.
type OriginError struct {
	Stage  string // policy | dns | dial | tls | transport
	Status int
	Reason string
	// Header is sent with Status, so a refusal can carry what the client
	// needs to answer it (a Proxy-Authenticate challenge).
	Header http.Header
}

func (e *OriginError) Error() string {
	if e.Reason == "" {
		return e.Stage
	}
	return e.Stage + ": " + e.Reason
}

type Proxy struct {
	Opts    *Options
	Version string
	Addons  []Addon

	entry            *entry
	attacker         *attacker
	webSocketHandler *webSocketHandler
	shouldIntercept  func(req *http.Request) bool              // req is received by proxy.server
	upstreamProxy    func(req *http.Request) (*url.URL, error) // req is received by proxy.server, not client request
	authProxy        func(res http.ResponseWriter, req *http.Request) (bool, error)
}

// proxy.server req context key
var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Opts:    opts,
		Version: "1.9.2",
		Addons:  make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	proxy.webSocketHandler = newWebSocketHandler(proxy)

	return proxy, nil
}

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			log.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) Shutdown(ctx context.Context) error {
	return proxy.entry.shutdown(ctx)
}

func (proxy *Proxy) GetCertificate() x509.Certificate {
	return *proxy.attacker.ca.GetRootCA()
}

func (proxy *Proxy) GetCertificateByCN(commonName string) (*tls.Certificate, error) {
	return proxy.attacker.ca.GetCert(commonName)
}

func (proxy *Proxy) SetShouldInterceptRule(rule func(req *http.Request) bool) {
	proxy.shouldIntercept = rule
}

func (proxy *Proxy) SetUpstreamProxy(fn func(req *http.Request) (*url.URL, error)) {
	proxy.upstreamProxy = fn
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyUrl(req)
	}
}

func (proxy *Proxy) getUpstreamProxyUrl(req *http.Request) (*url.URL, error) {
	if proxy.upstreamProxy != nil {
		return proxy.upstreamProxy(req)
	}
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyUrl, err := proxy.getUpstreamProxyUrl(req)
	if err != nil {
		return nil, err
	}
	return DialUpstream(ctx, proxyUrl, helper.CanonicalAddr(req.URL), proxy.Opts.SslInsecure)
}

// DialUpstream opens the origin transport connection for address, through
// proxyUrl when one is set. Exported so an OriginTransport hook reuses the
// maintained http/https/socks5 exit logic instead of copying it.
func DialUpstream(ctx context.Context, proxyUrl *url.URL, address string, sslInsecure bool) (net.Conn, error) {
	if proxyUrl != nil {
		return helper.GetProxyConn(ctx, proxyUrl, address, sslInsecure)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

// originTransport returns the configured origin hook, or nil for the upstream
// behaviour.
func (proxy *Proxy) originTransport() OriginTransport {
	if proxy.Opts == nil {
		return nil
	}
	return proxy.Opts.OriginTransport
}

func (proxy *Proxy) SetAuthProxy(fn func(res http.ResponseWriter, req *http.Request) (bool, error)) {
	proxy.authProxy = fn
}

package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"golang.org/x/net/http2"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// RoundTrip authorizes the request and forwards it to the origin. It never
// follows a redirect and never returns a transport error to the proxy: a
// refusal or a failure becomes a synthetic response carrying HeaderStage, so
// the recorder stores a classified attempt instead of a bare 502.
func (t *Transport) RoundTrip(ctx context.Context, connCtx *mproxy.ConnContext, req *http.Request) (*http.Response, error) {
	s, ok := t.session(req, connCtx)
	if !ok {
		return failErr(req, noSession(req, "no backend-issued session for this request")), nil
	}
	d := requestDestination(req.URL)
	if dec := t.cfg.Authorizer.Authorize(ctx, s, d); !dec.Allow {
		t.dropSession(s.ID)
		return fail(req, dec.Stage, dec.Reason), nil
	}
	// Re-judge the addresses this connection is pinned to: a revoke that lands
	// after the dial still stops the request, and no resolver runs again.
	st := t.state(connCtx)
	if st != nil && strings.EqualFold(st.authority, d.Host) && len(st.addrs) > 0 {
		if dec := t.cfg.Authorizer.AuthorizeResolved(ctx, s, d, st.addrs); !dec.Allow {
			t.dropSession(s.ID)
			return fail(req, dec.Stage, dec.Reason), nil
		}
	}

	up, err := t.upstreamFor(ctx, st, s, d)
	if err != nil {
		return failErr(req, err), nil
	}
	res, err := up.roundTrip(prepare(req))
	if err != nil {
		return failErr(req, err), nil
	}
	return res, nil
}

// upstreamFor returns the origin client for this request: the one bound to the
// intercepted connection when it serves the same authority, otherwise a pooled
// one keyed by session, revision, authority and exit.
func (t *Transport) upstreamFor(ctx context.Context, st *connState, s netpolicy.Session, d netpolicy.Destination) (*upstream, error) {
	if st != nil && st.up != nil && strings.EqualFold(st.authority, d.Host) {
		return st.up, nil
	}
	// A pinned address only applies to the authority it was resolved for.
	var pinned []net.IP
	if st != nil && strings.EqualFold(st.authority, d.Host) {
		pinned = st.addrs
	}
	return t.pooled(ctx, s, d, pinned)
}

// poolKey is the identity a pooled connection belongs to. The TLS profile is
// not a dimension: it is fixed at build time, so it cannot vary in a process.
// Neither is the ALPN: an entry's transport is fixed by the protocol its first
// handshake negotiated, and every redial must negotiate the same one, so a
// single entry can never serve two protocols.
type poolKey struct {
	session   string
	revision  int64
	authority string
	exit      string
}

// poolEntry is one pooled origin client, created on first use.
type poolEntry struct {
	mu sync.Mutex
	up *upstream
}

// pooled returns the pooled origin client for a destination, dialing and
// handshaking once to learn the ALPN the origin negotiates.
func (t *Transport) pooled(ctx context.Context, s netpolicy.Session, d netpolicy.Destination, pinned []net.IP) (*upstream, error) {
	key := poolKey{
		session:   s.ID,
		revision:  s.Revision,
		authority: net.JoinHostPort(d.Host, strconv.Itoa(d.Port)),
		exit:      t.Exit().ProxyURL,
	}
	t.mu.Lock()
	e := t.pool[key]
	if e == nil {
		e = &poolEntry{}
		t.pool[key] = e
	}
	t.mu.Unlock()

	// A failed first use leaves no client behind, so drop the placeholder
	// instead of keeping one map entry per destination that never worked.
	drop := func(err error) (*upstream, error) {
		t.mu.Lock()
		if t.pool[key] == e {
			delete(t.pool, key)
		}
		t.mu.Unlock()
		return nil, err
	}

	e.mu.Lock()
	if e.up != nil {
		e.mu.Unlock()
		return e.up, nil
	}
	e.mu.Unlock()

	// Authorization runs outside the entry lock: a refusal drops the session's
	// pooled entries, which takes their locks, so holding this one deadlocks.
	addrs := pinned
	if len(addrs) == 0 {
		var err error
		if addrs, err = t.authorizeResolved(ctx, s, d); err != nil {
			return drop(err)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.up != nil {
		return e.up, nil
	}
	conn, err := t.dialPinned(ctx, addrs, d.Port)
	if err != nil {
		return drop(err)
	}
	// A plaintext destination has no handshake and therefore no ALPN.
	if d.Scheme == "http" {
		e.up = newUpstream("", conn, t.redialFor(s, d, addrs))
		return e.up, nil
	}
	c, state, err := t.handshake(ctx, s, d.Host, conn)
	if err != nil {
		conn.Close()
		return drop(err)
	}
	e.up = newUpstream(state.NegotiatedProtocol, c, t.redialFor(s, d, addrs))
	return e.up, nil
}

// authorizeResolved resolves a destination no CONNECT pinned and judges the
// answers, so a pooled connection is authorized exactly like a dialed one.
func (t *Transport) authorizeResolved(ctx context.Context, s netpolicy.Session, d netpolicy.Destination) ([]net.IP, error) {
	addrs, err := t.resolve(ctx, d.Host)
	if err != nil {
		return nil, err
	}
	if dec := t.cfg.Authorizer.AuthorizeResolved(ctx, s, d, addrs); !dec.Allow {
		t.dropSession(s.ID)
		return nil, originError(dec)
	}
	return addrs, nil
}

// redialFor returns the dialer a pooled origin client uses for another
// connection to the same destination: same session, same pinned addresses.
func (t *Transport) redialFor(s netpolicy.Session, d netpolicy.Destination, addrs []net.IP) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.dialPinned(ctx, addrs, d.Port)
		if err != nil {
			return nil, err
		}
		if d.Scheme == "http" {
			return conn, nil
		}
		c, _, err := t.handshake(ctx, s, d.Host, conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return c, nil
	}
}

// upstream is one origin client identity. It owns the h2 or h1 transport and,
// when the CONNECT already handshook the origin, the connection to hand out
// first so the origin never sees a second handshake.
type upstream struct {
	seed   net.Conn
	dial   func(context.Context) (net.Conn, error)
	seedMu sync.Mutex
	h2     *http2.Transport
	h1     *http.Transport
}

func newUpstream(alpn string, seed net.Conn, dial func(context.Context) (net.Conn, error)) *upstream {
	u := &upstream{seed: seed, dial: dial}
	if alpn == "h2" {
		// http.Transport cannot select h2 over a uTLS conn on the pinned
		// toolchain (golang/go#78201), so h2 is explicit.
		u.h2 = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return u.take(ctx)
			},
			DisableCompression: true, // keep the origin's content encoding
		}
		return u
	}
	u.h1 = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return u.take(ctx)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return u.take(ctx)
		},
		ForceAttemptHTTP2:  false,
		DisableCompression: true, // keep the origin's content encoding
	}
	return u
}

// take hands out the seeded connection once, then dials fresh ones.
func (u *upstream) take(ctx context.Context) (net.Conn, error) {
	u.seedMu.Lock()
	c := u.seed
	u.seed = nil
	u.seedMu.Unlock()
	if c != nil {
		return c, nil
	}
	return u.dial(ctx)
}

func (u *upstream) roundTrip(req *http.Request) (*http.Response, error) {
	if u.h2 != nil {
		return u.h2.RoundTrip(req)
	}
	return u.h1.RoundTrip(req)
}

func (u *upstream) closeIdle() {
	if u.h2 != nil {
		u.h2.CloseIdleConnections()
	}
	if u.h1 != nil {
		u.h1.CloseIdleConnections()
	}
}

// hopByHop are the RFC 7230 section 6.1 headers plus the proxy credentials. The
// gateway is the only proxy hop, so they are consumed here and never reach the
// origin.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// prepare clones the request for the origin: gateway credentials and
// hop-by-hop headers are removed, everything else (duplicate headers, Accept,
// Cookie, Authorization, content encoding) is forwarded as the client sent it.
func prepare(req *http.Request) *http.Request {
	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.Header = cleanHeader(req.Header)
	return out
}

func cleanHeader(h http.Header) http.Header {
	out := h.Clone()
	// Connection names further headers that apply to this hop only.
	for _, v := range out.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				out.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		out.Del(name)
	}
	return out
}

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Dial authorizes the CONNECT authority, resolves it, checks every answer and
// opens the transport connection to the pinned address. It runs before the
// proxy answers 200, so a refusal is what the client sees instead of a tunnel
// that was never opened.
func (t *Transport) Dial(ctx context.Context, connCtx *mproxy.ConnContext, req *http.Request) (net.Conn, error) {
	s, ok := t.session(req, connCtx)
	if !ok {
		return nil, noSession(req, "no backend-issued session for this connection")
	}
	d := dialDestination(req)
	if dec := t.cfg.Authorizer.Authorize(ctx, s, d); !dec.Allow {
		t.dropSession(s.ID)
		return nil, originError(dec)
	}
	addrs, err := t.resolve(ctx, d.Host)
	if err != nil {
		return nil, &mproxy.OriginError{Stage: netpolicy.StageDNS, Status: http.StatusBadGateway, Reason: err.Error()}
	}
	if dec := t.cfg.Authorizer.AuthorizeResolved(ctx, s, d, addrs); !dec.Allow {
		t.dropSession(s.ID)
		return nil, originError(dec)
	}
	conn, err := t.dialPinned(ctx, addrs, d.Port)
	if err != nil {
		return nil, &mproxy.OriginError{Stage: netpolicy.StageDial, Status: http.StatusBadGateway, Reason: err.Error()}
	}

	key := connCtx.Id().String()
	t.putState(connCtx, &connState{session: s, authority: d.Host, port: d.Port, addrs: addrs})
	// The proxy closes the origin connection when the client connection ends;
	// dropping the state there keeps the map bounded by live connections.
	return &trackedConn{Conn: conn, onClose: func() { t.dropState(key) }}, nil
}

// trackedConn reports the close of the origin connection so the per-connection
// state does not outlive it.
type trackedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

// resolve returns the addresses a destination name resolves to. A literal is
// its own single answer, so no resolver can change it.
func (t *Transport) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	r := t.cfg.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolving %s: no address", host)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// dialPinned opens the transport connection to one of the already-authorized
// addresses, through the operator exit when one is set. Every address passed
// here has been judged, so trying them in order cannot widen the grant.
func (t *Transport) dialPinned(ctx context.Context, addrs []net.IP, port int) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no authorized address to dial")
	}
	exit, err := t.exitURL()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range addrs {
		conn, err := mproxy.DialUpstream(ctx, exit, net.JoinHostPort(ip.String(), strconv.Itoa(port)), false)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// exitURL parses the operator exit. An unset exit means direct; an unparsable
// or unsupported one fails instead of silently dialing direct.
func (t *Transport) exitURL() (*url.URL, error) {
	raw := strings.TrimSpace(t.Exit().ProxyURL)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("operator exit %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("operator exit %q: unsupported scheme %q", raw, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("operator exit %q: no host", raw)
	}
	return u, nil
}

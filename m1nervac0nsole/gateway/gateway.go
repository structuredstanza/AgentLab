// Package gateway is the origin side of the recording proxy. It implements
// mproxy.OriginTransport, so one place owns what the network boundary plan
// (docs/design/network-boundary-implementation-plan.md, section C) requires of
// every origin connection:
//
//   - authorization before any dial, from a backend-issued session rather than
//     anything the client sent;
//   - the address the name resolved to is checked and then pinned, so a second
//     answer cannot redirect the dial;
//   - the operator exit is applied, never a hidden direct route;
//   - the origin TLS handshake is a Chrome uTLS profile with strict
//     verification unless an explicit, session-scoped exception exists;
//   - requests keep their HTTP semantics (duplicate headers, Accept, Cookie,
//     Authorization) and are pooled per session, revision, authority, ALPN and
//     exit, so no connection or header crosses a session boundary.
//
// Failures the gateway produces are synthetic responses carrying HeaderStage,
// so the recorder can tell a policy refusal from a target answer.
package gateway

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	utls "github.com/refraction-networking/utls"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// HeaderStage marks a response the gateway produced instead of the origin. Its
// value is a netpolicy stage, so the recorder classifies the attempt without
// guessing from the status code.
const HeaderStage = "X-M1nervac0nsole-Gateway"

// Config wires the transport. Authorizer and SessionFor are required: a nil one
// refuses every request rather than falling back to an unauthorized dial.
type Config struct {
	// Authorizer answers both policy stages (before and after resolution).
	Authorizer *netpolicy.Store
	// SessionFor resolves the backend-issued session for one proxied request.
	// It runs on the CONNECT request, whose Proxy-Authorization carries the
	// session the backend issued; a tool argument never reaches it.
	SessionFor func(*http.Request) (netpolicy.Session, bool)
	// CertException reports whether the operator approved skipping origin
	// certificate verification for this session and authority. Nil is strict
	// everywhere.
	CertException func(netpolicy.Session, string) bool
	// Resolver resolves origin names. Nil uses net.DefaultResolver.
	Resolver *net.Resolver
	// HostsFor returns addresses the session's task recorded for a hostname
	// DNS may not know (vhosts). A mapping replaces DNS, but each address must
	// be independently authorized; exclusions on the name or an address still
	// bind. Returned addresses are pinned, so they must not be mutated.
	// Nil means no mapping.
	HostsFor func(s netpolicy.Session, host string) []net.IP
	// KeyLogWriter receives origin TLS secrets. Nil reads SSLKEYLOGFILE.
	KeyLogWriter io.Writer
	// MaskFor picks the header masking level for a session. Nil is MaskUA:
	// recorded traffic never announces a tool User-Agent.
	MaskFor func(netpolicy.Session) MaskLevel
}

// Transport is the origin transport hook.
type Transport struct {
	cfg    Config
	keyLog io.Writer

	exit atomic.Pointer[netpolicy.Exit]

	mu    sync.Mutex
	conns map[string]*connState // by proxy ConnContext id
	pool  map[poolKey]*poolEntry
}

// connState is what one client connection established: the session it was
// issued, the authority the dial was authorized for, the pinned addresses and,
// once the handshake has run, the origin client bound to that connection.
type connState struct {
	session   netpolicy.Session
	authority string
	port      int
	addrs     []net.IP
	recorded  bool
	up        *upstream
}

// New returns a transport for cfg.
func New(cfg Config) *Transport {
	t := &Transport{
		cfg:    cfg,
		keyLog: cfg.KeyLogWriter,
		conns:  make(map[string]*connState),
		pool:   make(map[poolKey]*poolEntry),
	}
	if t.keyLog == nil {
		t.keyLog = keyLogWriter()
	}
	return t
}

// Exit reports the operator upstream exit this transport applies. The
// supervisor reads it to configure the session's packet boundary.
func (t *Transport) Exit() netpolicy.Exit {
	if e := t.exit.Load(); e != nil {
		return *e
	}
	return netpolicy.Exit{}
}

// SetExit replaces the operator exit. Pooled connections belong to the old exit
// and are dropped, so a change takes effect on the next request instead of
// reusing a route the operator no longer selected.
func (t *Transport) SetExit(e netpolicy.Exit) {
	t.exit.Store(&e)
	t.CloseIdleConnections()
}

// CloseIdleConnections drops every pooled origin connection. The supervisor
// calls it when a session ends or its policy changes.
func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	pool := t.pool
	t.pool = make(map[poolKey]*poolEntry)
	t.mu.Unlock()
	for _, e := range pool {
		e.closeIdle()
	}
}

// dropSession closes the pooled connections of one session, so a refusal ends
// the connections it was already using instead of only blocking new requests.
func (t *Transport) dropSession(id string) {
	t.mu.Lock()
	dropped := make([]*poolEntry, 0, 1)
	for k, e := range t.pool {
		if k.session == id {
			delete(t.pool, k)
			dropped = append(dropped, e)
		}
	}
	t.mu.Unlock()
	for _, e := range dropped {
		e.closeIdle()
	}
}

// state returns the connection state for a proxy connection, or nil.
func (t *Transport) state(connCtx *mproxy.ConnContext) *connState {
	if connCtx == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conns[connCtx.Id().String()]
}

func (t *Transport) putState(connCtx *mproxy.ConnContext, st *connState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[connCtx.Id().String()] = st
}

func (t *Transport) dropState(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, id)
}

// session returns the session a request runs under. A request inside an
// intercepted tunnel uses the session its CONNECT was issued, so a later header
// cannot switch identity; anything else must resolve one from the request.
func (t *Transport) session(req *http.Request, connCtx *mproxy.ConnContext) (netpolicy.Session, bool) {
	if st := t.state(connCtx); st != nil {
		return st.session, true
	}
	if t.cfg.SessionFor == nil {
		return netpolicy.Session{}, false
	}
	return t.cfg.SessionFor(req)
}

// TaskID reports the engagement task the request runs under, or 0 when it runs
// under no task: an unbound conversation's session, or no session at all. It is
// the same resolution the origin side authorizes with, so a caller that
// attributes a request cannot disagree with the policy that admitted it. It is
// read-only and never fails: an unknown session is 0, not an error.
func (t *Transport) TaskID(connCtx *mproxy.ConnContext, req *http.Request) int64 {
	s, ok := t.session(req, connCtx)
	if !ok {
		return 0
	}
	return s.TaskID
}

// originError turns a refusal into the error the CONNECT reply reports.
func originError(dec netpolicy.Decision) error {
	status := http.StatusBadGateway
	if dec.Stage == netpolicy.StagePolicy || dec.Stage == netpolicy.StageDNS {
		status = http.StatusForbidden
	}
	return &mproxy.OriginError{Stage: dec.Stage, Status: status, Reason: dec.Reason}
}

// proxyChallenge asks for the run's session credential, which the client sends
// as the Proxy-Authorization user part.
const proxyChallenge = `Basic realm="m1nervac0nsole"`

// noSession is the refusal for a request that resolved no session. A client
// that sent no proxy credential at all is challenged, because a browser sends
// Proxy-Authorization only after a 407, so a 403 would leave it unable to
// authenticate. A credential that resolved nothing keeps the 403, or the
// browser would retry the same dead credential forever.
func noSession(req *http.Request, reason string) *mproxy.OriginError {
	oe := &mproxy.OriginError{Stage: netpolicy.StagePolicy, Status: http.StatusForbidden, Reason: reason}
	if req.Header.Get("Proxy-Authorization") == "" {
		oe.Status = http.StatusProxyAuthRequired
		oe.Header = http.Header{"Proxy-Authenticate": {proxyChallenge}}
	}
	return oe
}

// fail builds the synthetic response the client and the recorder see instead of
// a target answer.
func fail(req *http.Request, stage, reason string) *http.Response {
	status := http.StatusForbidden
	if stage != netpolicy.StagePolicy && stage != netpolicy.StageDNS {
		status = http.StatusBadGateway
	}
	body := reason + "\n"
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			HeaderStage:    {stage},
			"Content-Type": {"text/plain; charset=utf-8"},
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// failErr builds the synthetic response for an origin-side failure, keeping the
// stage the gateway classified it with instead of reporting every failure as
// transport.
func failErr(req *http.Request, err error) *http.Response {
	var oe *mproxy.OriginError
	if errors.As(err, &oe) && oe.Stage != "" {
		res := fail(req, oe.Stage, oe.Error())
		if oe.Status != 0 {
			res.StatusCode = oe.Status
			res.Status = fmt.Sprintf("%d %s", oe.Status, http.StatusText(oe.Status))
		}
		for k, vs := range oe.Header {
			res.Header[k] = vs
		}
		return res
	}
	return fail(req, netpolicy.StageTransport, err.Error())
}

// dialDestination is the destination a CONNECT or upgrade request asks for. The
// proxy always intercepts, so the origin is TLS even though Go normalizes a
// CONNECT request line to an http URL.
func dialDestination(req *http.Request) netpolicy.Destination {
	protocol, defPort := "http", 443
	switch strings.ToLower(req.URL.Scheme) {
	case "ws":
		protocol, defPort = "ws", 80
	case "wss":
		protocol, defPort = "ws", 443
	}
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	host, port := splitAuthority(authority, defPort)
	return netpolicy.Destination{Scheme: "https", Host: host, Port: port, Protocol: protocol}
}

// requestDestination is the destination of a request already inside a tunnel.
func requestDestination(u *url.URL) netpolicy.Destination {
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	protocol, defPort := "http", 80
	switch scheme {
	case "https":
		defPort = 443
	case "ws":
		protocol = "ws"
	case "wss":
		protocol, defPort = "ws", 443
	}
	port := defPort
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return netpolicy.Destination{Scheme: scheme, Host: u.Hostname(), Port: port, Protocol: protocol}
}

// splitAuthority splits host:port, defaulting the port and accepting a
// bracketed IPv6 literal without one.
func splitAuthority(authority string, defPort int) (string, int) {
	if h, p, err := net.SplitHostPort(authority); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return h, n
		}
		return h, defPort
	}
	return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), defPort
}

// originState copies a uTLS connection state into the standard one the proxy
// reports to addons. utls.ConnectionState is a separate struct, so the copy is
// explicit; only the exported fields are meaningful to a reader.
func originState(uc *utls.UConn) tls.ConnectionState {
	s := uc.ConnectionState()
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
		ECHAccepted:                 s.ECHAccepted,
	}
}

package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	utls "github.com/refraction-networking/utls"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Handshake completes the origin TLS handshake over the connection Dial opened.
// It is a Chrome uTLS profile offering h2 and http/1.1, verified strictly
// unless the operator approved an exception for this session and authority.
func (t *Transport) Handshake(ctx context.Context, connCtx *mproxy.ConnContext, c net.Conn, serverName string) (net.Conn, tls.ConnectionState, error) {
	st := t.state(connCtx)
	if st == nil {
		return nil, tls.ConnectionState{}, &mproxy.OriginError{
			Stage:  netpolicy.StagePolicy,
			Status: http.StatusForbidden,
			Reason: "origin handshake without an authorized dial",
		}
	}
	// The client chooses the SNI, so it must not widen the grant the dial was
	// checked against: a different name is authorized on its own or refused.
	if serverName != "" && !strings.EqualFold(serverName, st.authority) {
		d := netpolicy.Destination{Scheme: "https", Host: serverName, Port: st.port, Protocol: "http"}
		if dec := t.cfg.Authorizer.Authorize(ctx, st.session, d); !dec.Allow {
			t.dropSession(st.session.ID)
			return nil, tls.ConnectionState{}, originError(dec)
		}
	}
	conn, state, err := t.handshake(ctx, st.session, serverName, c)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}
	st.up = newUpstream(state.NegotiatedProtocol, conn, t.redial(st))
	return conn, state, nil
}

// handshake runs the uTLS client over an already-dialed connection. The name to
// verify is the SNI when present, otherwise the authorized authority.
func (t *Transport) handshake(ctx context.Context, s netpolicy.Session, serverName string, c net.Conn) (net.Conn, tls.ConnectionState, error) {
	cfg := &utls.Config{ServerName: serverName, KeyLogWriter: t.keyLog}
	if t.cfg.CertException != nil && t.cfg.CertException(s, serverName) {
		cfg.InsecureSkipVerify = true
	}
	uc := utls.UClient(c, cfg, utls.HelloChrome_Auto)
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, tls.ConnectionState{}, &mproxy.OriginError{
			Stage:  netpolicy.StageTLS,
			Status: http.StatusBadGateway,
			Reason: err.Error(),
		}
	}
	return uc, originState(uc), nil
}

// redial returns the dialer a pooled origin client uses when it needs another
// connection: same session, same pinned addresses, same authority.
func (t *Transport) redial(st *connState) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.dialPinned(ctx, st.addrs, st.port)
		if err != nil {
			return nil, err
		}
		c, _, err := t.handshake(ctx, st.session, st.authority, conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return c, nil
	}
}

var (
	keyLogOnce sync.Once
	keyLogSink io.Writer
)

// keyLogWriter opens SSLKEYLOGFILE once, so origin secrets land in the same file
// the proxy's client-side handshakes write to.
func keyLogWriter() io.Writer {
	keyLogOnce.Do(func() {
		path := os.Getenv("SSLKEYLOGFILE")
		if path == "" {
			return
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		keyLogSink = f
	})
	return keyLogSink
}

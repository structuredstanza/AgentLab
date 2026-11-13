package egress

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// warnHostLimit bounds the set of hosts that have already produced an
// unverified-upstream warning. An engagement can reach tens of thousands of
// hosts, so the set is a bounded FIFO rather than a map that grows with them.
const warnHostLimit = 4096

// upstreamTimeout bounds one upstream TCP connect and TLS handshake. It matches
// the deadline the proxy already applies to the request that follows, and keeps
// a host that stalls its handshake from pinning a goroutine indefinitely.
const upstreamTimeout = 15 * time.Second

// maxHostLogLen bounds the host text put in a warning. A DNS name cannot be
// longer than this, so a longer value is a malformed authority and is cut
// rather than logged whole.
const maxHostLogLen = 253

// dialer is the TLS client the proxy uses to reach an origin. It speaks the
// uTLS Chrome preset, because the TLS fingerprint comes from the handshake
// rather than from any header the proxy could set.
type dialer struct {
	profile utls.ClientHelloID

	// roots is the system trust store, loaded once. A nil pool means the host
	// has no usable roots, in which case every upstream is reported unverified.
	rootsOnce sync.Once
	roots     *x509.CertPool

	// warned records hosts already reported unverified, oldest first, so a
	// scan of one host logs one line rather than one line per request.
	mu       sync.Mutex
	warned   map[string]struct{}
	warnFIFO []string
}

// newDialer returns a dialer presenting the Chrome profile this build pins.
//
// The profile is fixed rather than rotated: an engagement holds one identity,
// and a ClientHello that changes between requests is a stronger signal than any
// single fingerprint would be.
func newDialer() *dialer {
	return &dialer{profile: utls.HelloChrome_Auto, warned: map[string]struct{}{}}
}

// dial opens a TLS connection to addr and returns it with the negotiated
// protocol and any negotiated ALPN recorded.
//
// The handshake itself does not verify the peer: engagement targets routinely
// present self-signed certificates, and refusing them would make the proxy
// useless against exactly the hosts it exists for. Instead the presented chain
// is checked against the system roots after the handshake and a mismatch is
// reported once per host. That keeps the connection usable and still leaves a
// record that this origin could not be authenticated — which is a fact about
// the target, not proof that anything intercepted the traffic.
//
// Both the TCP connect and the handshake are bounded by upstreamTimeout and
// cancellable through ctx, so a target that accepts a connection and then never
// finishes its handshake cannot hold a proxy goroutine — or a rate-limit
// permit — for the life of the process.
func (d *dialer) dial(ctx context.Context, addr, serverName string, alpn []string) (net.Conn, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	hsCtx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()

	raw, err := (&net.Dialer{Timeout: upstreamTimeout}).DialContext(hsCtx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // the engagement's targets have self-signed certs
		NextProtos:         alpn,
	}
	conn := utls.UClient(raw, cfg, d.profile)
	if err := conn.HandshakeContext(hsCtx); err != nil {
		raw.Close()
		return nil, "", err
	}
	state := conn.ConnectionState()
	d.checkUpstream(ctx, serverName, state.PeerCertificates)
	return conn, state.NegotiatedProtocol, nil
}

// checkUpstream verifies the origin's chain and hostname against the system
// roots, and reports the first failure per host through the context logger.
//
// The check never fails the request: it only decides whether to warn. Nothing
// from the peer certificate is logged — not the subject, not the PEM, not the
// fingerprint — because that text is attacker-controlled and is not needed to
// act on the warning.
func (d *dialer) checkUpstream(ctx context.Context, serverName string, peer []*x509.Certificate) {
	if len(peer) == 0 || peer[0] == nil || serverName == "" {
		return
	}
	err := d.verifyUpstream(serverName, peer)
	if err == nil {
		return
	}
	host := normalizeWarnHost(serverName)
	if !d.markWarned(host) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	logEvent(ctx, Event{TLSWarning: fmt.Sprintf(
		"upstream certificate for %s is unverified (%s); the request is still forwarded because engagement targets may use self-signed certificates — this alone is not evidence of interception",
		host, verifyReason(err))})
}

// verifyUpstream checks a presented chain against the system roots under the
// name the client asked for.
func (d *dialer) verifyUpstream(serverName string, peer []*x509.Certificate) error {
	roots := d.systemRoots()
	if roots == nil {
		return errors.New("no system trust store")
	}
	intermediates := x509.NewCertPool()
	for _, c := range peer[1:] {
		if c != nil {
			intermediates.AddCert(c)
		}
	}
	// DNSName also matches IP literals against the certificate's IP SANs, so a
	// target addressed by address is verified the same way.
	_, err := peer[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// systemRoots returns the host's trust store, loaded once. On a host without
// one, the result stays nil and every upstream is reported unverified.
//
// A caller that has already set roots (tests, or a build with a pinned bundle)
// keeps them: the load only fills an empty field.
func (d *dialer) systemRoots() *x509.CertPool {
	d.rootsOnce.Do(func() {
		if d.roots != nil {
			return
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			return
		}
		d.roots = pool
	})
	return d.roots
}

// markWarned records host and reports whether this call is the first for it.
//
// The set is bounded: when it is full the oldest host is dropped, so a scan
// that walks a large address space cannot make it grow without limit.
func (d *dialer) markWarned(host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.warned == nil {
		d.warned = map[string]struct{}{}
	}
	if _, ok := d.warned[host]; ok {
		return false
	}
	for len(d.warnFIFO) >= warnHostLimit {
		oldest := d.warnFIFO[0]
		d.warnFIFO = d.warnFIFO[1:]
		delete(d.warned, oldest)
	}
	d.warned[host] = struct{}{}
	d.warnFIFO = append(d.warnFIFO, host)
	return true
}

// normalizeWarnHost reduces a name to the key used for deduplication and for
// the warning text: no port, no IPv6 brackets, lower case, no trailing root
// dot, no control characters, bounded length. Two spellings of the same host
// must not produce two warnings, and nothing from the wire may reach a log line
// verbatim.
func normalizeWarnHost(name string) string {
	host := hostFromAddr(name)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSuffix(host, ".")
	host = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, host)
	if len(host) > maxHostLogLen {
		host = host[:maxHostLogLen]
	}
	return strings.ToLower(host)
}

// verifyReason classifies a verification error into a fixed token. Only the
// class is reported, never the error text, which can quote the peer's
// certificate. The tokens are stable so an operator can grep them.
func verifyReason(err error) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &hostname):
		return "hostname_mismatch"
	case errors.As(err, &unknown):
		return "unknown_authority"
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return "expired"
		}
		return "unusable_certificate"
	}
	return "verification_failed"
}

// alpnFor returns the ALPN list a Chrome build of this vintage offers. The order
// is part of the fingerprint: h2 first, then http/1.1.
func alpnFor(useTLS bool) []string {
	if !useTLS {
		return nil
	}
	return []string{"h2", "http/1.1"}
}

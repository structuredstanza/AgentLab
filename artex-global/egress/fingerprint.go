package egress

import (
	"net"

	utls "github.com/refraction-networking/utls"
)

// dialer is the TLS client the proxy uses to reach an origin. It is a real
// browser's ClientHello, replayed byte for byte, because the fingerprint is
// computed from the handshake rather than from any header the proxy could set.
type dialer struct {
	profile utls.ClientHelloID
}

// newDialer returns a dialer presenting the Chrome profile this build pins.
//
// The profile is fixed rather than rotated: an engagement holds one identity,
// and a ClientHello that changes between requests is a stronger signal than any
// single fingerprint would be.
func newDialer() *dialer {
	return &dialer{profile: utls.HelloChrome_Auto}
}

// dial opens a TLS connection to addr and returns it with the negotiated
// protocol and any negotiated ALPN recorded.
func (d *dialer) dial(addr, serverName string, alpn []string) (net.Conn, string, error) {
	raw, err := net.DialTimeout("tcp", addr, 15e9)
	if err != nil {
		return nil, "", err
	}
	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // the engagement's targets have self-signed certs
		NextProtos:         alpn,
	}
	conn := utls.UClient(raw, cfg, d.profile)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}

// alpnFor returns the ALPN list a Chrome build of this vintage offers. The order
// is part of the fingerprint: h2 first, then http/1.1.
func alpnFor(useTLS bool) []string {
	if !useTLS {
		return nil
	}
	return []string{"h2", "http/1.1"}
}

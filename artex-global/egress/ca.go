// Package egress is the engagement's single outbound path for HTTP traffic.
//
// Why a proxy rather than a flag on each tool: a tool's own User-Agent is the
// smallest of its tells. curl sends three headers and a curl-shaped TLS
// ClientHello; a browser sends twelve headers and a Chrome-shaped one. Setting
// -A on curl produces the worst of both worlds, a Chrome User-Agent attached to
// an unmistakably non-browser handshake. The only way to present one coherent
// identity is to own the connection, so the proxy terminates the tool's TLS,
// re-dials the origin with a browser fingerprint, and normalises the headers it
// forwards.
//
// This also gives the engagement one place to enforce its rules: a request that
// the policy refuses never leaves the guest, whatever tool asked for it.
package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is the engagement's certificate authority. It exists so the proxy can
// present a certificate the tools trust; it is never trusted by anything but
// this guest, and its key never leaves the VM.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// LoadOrCreateCA reads the CA from dir, generating one on first use.
//
// Regenerating on every boot would invalidate every trust store the guest has
// already been given, so the CA persists for the life of the VM.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			ca, err := parseCA(certPEM, keyPEM)
			if err == nil {
				return ca, nil
			}
		}
	}
	ca, err := newCA()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.pem, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

func newCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// A name that reads as ordinary internal tooling rather than as this
			// product, so a certificate inspection does not name the backend.
			CommonName:   "Local Inspection Root",
			Organization: []string{"Local"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:  cert,
		key:   key,
		pem:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leafs: map[string]*tls.Certificate{},
	}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("ca.pem or ca.key is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, pem: certPEM, leafs: map[string]*tls.Certificate{}}, nil
}

// PEM returns the CA certificate, for installing into a trust store.
func (c *CA) PEM() []byte { return c.pem }

// Leaf returns a certificate for host, minted on first use and cached.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.leafs[host]; ok {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	c.leafs[host] = cert
	return cert, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// hostFromAddr strips a port from an authority, keeping IPv6 brackets intact.
func hostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// readRequestHead reads one request line and its headers, so the proxy can
// decide what to do before any body is consumed.
func readRequestHead(r *bufio.Reader) (method, target string, headers [][2]string, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", "", nil, err
	}
	parts := splitSpace(line)
	if len(parts) < 2 {
		return "", "", nil, fmt.Errorf("malformed request line %q", line)
	}
	method, target = parts[0], parts[1]
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", "", nil, err
		}
		trimmed := trimCRLF(line)
		if trimmed == "" {
			break
		}
		if k, v, ok := splitHeader(trimmed); ok {
			headers = append(headers, [2]string{k, v})
		}
	}
	return method, target, headers, nil
}

func splitSpace(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func splitHeader(line string) (string, string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == ':' {
			return line[:i], trimLeadingSpace(line[i+1:]), true
		}
	}
	return "", "", false
}

func trimLeadingSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}

// ctxKey is the proxy's own context key type.
type ctxKey struct{}

// WithLogger attaches a request logger to the context.
func WithLogger(ctx context.Context, fn func(Event)) context.Context {
	return context.WithValue(ctx, ctxKey{}, fn)
}

// Event is one forwarded request, for the engagement's traffic record.
type Event struct {
	Time     time.Time
	Method   string
	Host     string
	Path     string
	Status   int
	Bytes    int64
	Tool     string
	Refused  bool
	Reason   string
	Duration time.Duration
}

func logEvent(ctx context.Context, e Event) {
	if fn, ok := ctx.Value(ctxKey{}).(func(Event)); ok && fn != nil {
		fn(e)
	}
}

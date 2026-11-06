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

const (
	// leafCacheLimit bounds the minted-leaf cache. A scan can touch tens of
	// thousands of hosts; an unbounded map would grow with every one of them for
	// the life of the process.
	leafCacheLimit = 4096

	// leafLifetime is how long a minted leaf is valid. The cache re-mints on
	// expiry instead of serving a certificate that clients will reject.
	leafLifetime = 7 * 24 * time.Hour

	// leafRenewBefore is how close to expiry a cached leaf may get before it is
	// replaced, so a certificate handed to a client is never one that expires
	// mid-session.
	leafRenewBefore = time.Hour
)

// leafEntry is one cached leaf and the moment it stops being usable.
type leafEntry struct {
	cert     *tls.Certificate
	notAfter time.Time
}

// leafCall is one in-progress mint for a host. Concurrent callers for the same
// host wait for it instead of each generating a key and certificate.
type leafCall struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// CA is the engagement's certificate authority. It exists so the proxy can
// present a certificate the tools trust; it is never trusted by anything but
// this guest, and its key never leaves the VM.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte

	mu       sync.Mutex
	leafs    map[string]leafEntry
	leafFIFO []string // insertion order, for bounded FIFO eviction
	inflight map[string]*leafCall
	// leafLimit is the cache bound; zero means leafCacheLimit. Tests lower it
	// rather than minting thousands of certificates.
	leafLimit int
}

// LoadOrCreateCA reads the CA from dir, generating one on first use.
//
// Regenerating on every boot would invalidate every trust store the guest has
// already been given, so the CA persists for the life of the VM.
//
// An existing but unreadable or mismatched pair is an error, not a reason to
// mint a new one. The guest points SSL_CERT_FILE / CURL_CA_BUNDLE / curl /
// python / node at ca.pem, so overwriting it leaves every tool failing
// verification against a certificate the guest no longer trusts — and destroys
// the only copy of the key, with nothing in the log to say why.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	switch {
	case certErr == nil && keyErr == nil:
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("the existing CA in %s cannot be used (%w); refusing to replace it, because every tool in the guest trusts the current certificate — repair or remove both files deliberately", dir, err)
		}
		return ca, nil
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		// First use: nothing to preserve.
	case os.IsNotExist(certErr) != os.IsNotExist(keyErr):
		// One half is missing: a partial write or a partial restore. Same
		// reasoning as above — do not paper over it.
		return nil, fmt.Errorf("the CA in %s is incomplete (ca.pem: %v, ca.key: %v); refusing to replace it, because the guest trust store may still pin it", dir, certErr, keyErr)
	default:
		return nil, fmt.Errorf("cannot read the CA in %s (ca.pem: %v, ca.key: %v); refusing to replace it, because every tool in the guest trusts the current certificate", dir, certErr, keyErr)
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
		leafs: map[string]leafEntry{},
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
	// A mismatched pair (a key restored from a different CA, a half-copied
	// backup) parses cleanly and then signs leaves the client cannot verify,
	// which surfaces as "unknown authority" at every tool instead of a clear
	// startup error. x509.CreateCertificate does not check that the signer key
	// belongs to the parent certificate, so check it here.
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("ca.key does not match ca.pem")
	}
	// A matching pair that cannot sign a usable leaf is just as broken, and
	// fails later as "unknown authority" at every tool. Check what minting
	// depends on: the certificate must be a CA allowed to sign server leaves,
	// and it must still be valid now.
	if !cert.IsCA {
		return nil, fmt.Errorf("ca.pem is not a CA certificate (basic constraints CA=false), so leaves it signs are rejected")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("ca.pem does not permit certificate signing (keyUsage lacks keyCertSign)")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("ca.pem is not valid now (valid %s to %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return &CA{cert: cert, key: key, pem: certPEM, leafs: map[string]leafEntry{}}, nil
}

// PEM returns the CA certificate, for installing into a trust store.
func (c *CA) PEM() []byte { return c.pem }

// Leaf returns a certificate for host, minted on first use and cached.
//
// The cache is bounded and evicts in insertion order. Eviction never breaks a
// live connection: the handshake copies the certificate it was given, so a
// connection already using an evicted leaf keeps working; only the next
// connection to that host pays for a fresh mint.
//
// Minting happens outside the lock. A P-256 keygen and a signature take long
// enough that holding the mutex through them would serialise every new host
// behind the slowest one — which is exactly what a scan against many hosts
// does. Concurrent callers for the same host share one mint instead of each
// generating a key, so a burst cannot produce several certificates for one
// name.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	if cert, ok := c.cachedLeafLocked(host); ok {
		c.mu.Unlock()
		return cert, nil
	}
	if call, ok := c.inflight[host]; ok {
		c.mu.Unlock()
		<-call.done
		return call.cert, call.err
	}
	call := &leafCall{done: make(chan struct{})}
	if c.inflight == nil {
		c.inflight = map[string]*leafCall{}
	}
	c.inflight[host] = call
	c.mu.Unlock()

	cert, err := c.mintLeaf(host)

	c.mu.Lock()
	call.cert, call.err = cert, err
	delete(c.inflight, host)
	if err == nil {
		c.storeLeafLocked(host, cert)
	}
	c.mu.Unlock()
	close(call.done)
	return cert, err
}

// cachedLeafLocked returns a usable cached leaf, or reports that one must be
// minted. The caller holds c.mu.
func (c *CA) cachedLeafLocked(host string) (*tls.Certificate, bool) {
	entry, ok := c.leafs[host]
	if !ok {
		return nil, false
	}
	// A leaf close to expiry is re-minted rather than served: a cached
	// certificate that expires mid-engagement fails verification at the client
	// with no way to recover short of a restart.
	if time.Now().Add(leafRenewBefore).After(entry.notAfter) {
		c.dropLeafLocked(host)
		return nil, false
	}
	return entry.cert, true
}

// storeLeafLocked records a freshly minted leaf, evicting the oldest when the
// cache is at its bound.
func (c *CA) storeLeafLocked(host string, cert *tls.Certificate) {
	limit := c.leafLimit
	if limit <= 0 {
		limit = leafCacheLimit
	}
	if c.leafs == nil {
		c.leafs = map[string]leafEntry{}
	}
	if _, exists := c.leafs[host]; !exists {
		for len(c.leafFIFO) >= limit {
			oldest := c.leafFIFO[0]
			c.leafFIFO = c.leafFIFO[1:]
			delete(c.leafs, oldest)
		}
		c.leafFIFO = append(c.leafFIFO, host)
	}
	c.leafs[host] = leafEntry{cert: cert, notAfter: leafNotAfter(cert)}
}

// dropLeafLocked forgets one host, keeping the insertion order in step.
func (c *CA) dropLeafLocked(host string) {
	delete(c.leafs, host)
	for i, h := range c.leafFIFO {
		if h == host {
			c.leafFIFO = append(c.leafFIFO[:i], c.leafFIFO[i+1:]...)
			return
		}
	}
}

// leafNotAfter reads the expiry back out of a minted certificate. Falling back
// to the minting time plus the lifetime keeps the entry usable if the DER ever
// fails to parse, which cannot happen for a certificate we just built.
func leafNotAfter(cert *tls.Certificate) time.Time {
	if len(cert.Certificate) == 0 {
		return time.Now().Add(leafLifetime)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Now().Add(leafLifetime)
	}
	return parsed.NotAfter
}

// mintLeaf generates a key and a certificate for host. It touches no shared
// state, so it runs without the mutex.
func (c *CA) mintLeaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
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
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
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

	// TLSWarning is set only on a deduplicated upstream-certificate warning,
	// which is not a request: the remaining fields are zero. It carries the
	// host and a fixed reason class, never certificate text, headers, payload
	// or key material.
	TLSWarning string

	// Aborted marks a response whose relay failed after the head was written:
	// the client received a short body. Status and Bytes still describe what
	// was sent, but the exchange is not a completed one, and an operator
	// reading the log must be able to tell the difference.
	Aborted bool
}

func logEvent(ctx context.Context, e Event) {
	if fn, ok := ctx.Value(ctxKey{}).(func(Event)); ok && fn != nil {
		fn(e)
	}
}

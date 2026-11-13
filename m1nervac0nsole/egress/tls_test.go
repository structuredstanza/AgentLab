package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventSink collects the events a request would log, so a test can assert what
// an operator would actually see.
type eventSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *eventSink) add(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *eventSink) warnings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, ev := range s.events {
		if ev.TLSWarning != "" {
			out = append(out, ev.TLSWarning)
		}
	}
	return out
}

// all returns a copy of every event the proxy logged.
func (s *eventSink) all() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// startTLSOrigin serves TLS with the given certificate until the test ends and
// returns the address to dial.
func startTLSOrigin(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Complete the handshake so the client side is exercised, then drop
			// the connection: these tests are about the TLS layer, not HTTP.
			if tc, ok := conn.(*tls.Conn); ok {
				tc.SetDeadline(time.Now().Add(5 * time.Second))
				tc.Handshake()
			}
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// rootsFor returns a pool holding exactly the given CA.
func rootsFor(t *testing.T, ca *CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PEM()) {
		t.Fatal("CA is not a valid PEM certificate")
	}
	return pool
}

// cacheKeys lists the hosts currently cached, for failure messages.
func cacheKeys(ca *CA) []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	keys := make([]string, 0, len(ca.leafs))
	for host := range ca.leafs {
		keys = append(keys, host)
	}
	return keys
}

// The reported reason is a fixed token per failure class, never the error text
// or anything the origin chose.
func TestVerifyReasonClassifiesFailures(t *testing.T) {
	host := &x509.Certificate{DNSNames: []string{"expected.test"}}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"unknown authority", x509.UnknownAuthorityError{Cert: host}, "unknown_authority"},
		{"hostname", x509.HostnameError{Certificate: host, Host: "other.test"}, "hostname_mismatch"},
		{"expired", x509.CertificateInvalidError{Cert: host, Reason: x509.Expired}, "expired"},
		{"other invalid", x509.CertificateInvalidError{Cert: host, Reason: x509.NotAuthorizedToSign}, "unusable_certificate"},
		{"unclassified", fmt.Errorf("something else"), "verification_failed"},
	}
	for _, tc := range cases {
		if got := verifyReason(tc.err); got != tc.want {
			t.Errorf("%s: verifyReason = %q, want %q", tc.name, got, tc.want)
		}
	}
	// A hostname error names the host that was asked for and the certificate's
	// own names; neither may reach the log through the reason token.
	token := verifyReason(x509.HostnameError{Certificate: host, Host: "other.test"})
	if strings.Contains(token, "other.test") || strings.Contains(token, "expected.test") {
		t.Fatalf("reason token leaks certificate or host text: %q", token)
	}
}

// The dedup key and the logged host are stripped of a port, IPv6 brackets, a
// trailing root dot, case differences and control characters, and are bounded
// in length, so nothing from the wire reaches a log line verbatim.
func TestNormalizeWarnHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":             "example.com",
		"example.com:8443":        "example.com",
		"example.com.":            "example.com",
		"[2001:db8::1]:443":       "2001:db8::1",
		"10.0.0.1":                "10.0.0.1",
		"bad\r\nInjected: header": "badinjected",
		strings.Repeat("a", 300):  strings.Repeat("a", maxHostLogLen),
	}
	for in, want := range cases {
		if got := normalizeWarnHost(in); got != want {
			t.Errorf("normalizeWarnHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// A target that accepts TCP and then never answers must not hold the caller:
// the dial and the handshake both honour ctx, so a cancelled engagement stops
// waiting on a hostile or wedged origin instead of pinning the goroutine.
func TestDialHonoursContextDuringStalledHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			conn.Close()
		}
	})

	d := newDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	started := time.Now()
	conn, _, err := d.dial(ctx, ln.Addr().String(), "stalled.test", []string{"http/1.1"})
	elapsed := time.Since(started)
	if err == nil {
		conn.Close()
		t.Fatal("a stalled handshake was reported as successful")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("dial waited %s for a stalled handshake, want it bounded by the context", elapsed)
	}
}

// A target whose chain is signed by a root the host trusts must not warn: the
// warning is reserved for origins that could not be authenticated.
func TestUpstreamTrustedBySystemRootsDoesNotWarn(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("target.test")
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSOrigin(t, *leaf)

	d := newDialer()
	d.roots = rootsFor(t, ca)
	sink := &eventSink{}
	ctx := WithLogger(context.Background(), sink.add)

	conn, proto, err := d.dial(ctx, addr, "target.test", []string{"http/1.1"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if proto != "http/1.1" {
		t.Errorf("negotiated %q, want http/1.1", proto)
	}
	if got := sink.warnings(); len(got) != 0 {
		t.Fatalf("a verifiable upstream produced warnings: %v", got)
	}
}

// Self-signed targets must stay reachable — that is the whole reason the
// handshake does not verify — but the origin must be reported unverified, and
// only once per host however many requests hit it.
func TestSelfSignedUpstreamWarnsOnceAndStaysReachable(t *testing.T) {
	serverCA, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := serverCA.Leaf("self.signed.test")
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSOrigin(t, *leaf)

	d := newDialer()
	d.roots = x509.NewCertPool() // nothing trusted: the chain cannot verify
	sink := &eventSink{}
	ctx := WithLogger(context.Background(), sink.add)

	for i := range 3 {
		conn, _, err := d.dial(ctx, addr, "self.signed.test", []string{"http/1.1"})
		if err != nil {
			t.Fatalf("dial %d: a self-signed origin must remain reachable: %v", i, err)
		}
		conn.Close()
	}

	warnings := sink.warnings()
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want exactly one per host: %v", len(warnings), warnings)
	}
	w := warnings[0]
	if !strings.Contains(w, "self.signed.test") {
		t.Errorf("warning does not name the host: %q", w)
	}
	if !strings.Contains(w, "unverified") {
		t.Errorf("warning does not say the connection is unverified: %q", w)
	}
	if !strings.Contains(w, "not evidence of interception") {
		t.Errorf("warning reads as proof of interception: %q", w)
	}
	if !strings.Contains(w, "unknown_authority") {
		t.Errorf("warning does not classify the failure: %q", w)
	}
	// Nothing from the certificate or the connection may be logged.
	for _, leak := range []string{"BEGIN CERTIFICATE", "Local Inspection Root", "EC PRIVATE KEY"} {
		if strings.Contains(w, leak) {
			t.Errorf("warning leaked certificate material %q: %q", leak, w)
		}
	}
	// The warning must not masquerade as a forwarded request: the command's
	// logger branches on this field before it reads Method/Path/Status.
	for _, ev := range sink.all() {
		if ev.TLSWarning == "" {
			continue
		}
		if ev.Method != "" || ev.Path != "" || ev.Status != 0 || ev.Bytes != 0 || ev.Refused {
			t.Fatalf("warning event carries request fields: %+v", ev)
		}
	}
}

// A certificate that verifies but names a different host is a distinct failure
// from an unknown authority, and the certificate's own names must not be
// echoed: they are chosen by the origin.
func TestHostnameMismatchWarnsWithoutEchoingCertificateNames(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("internal-only.example")
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSOrigin(t, *leaf)

	d := newDialer()
	d.roots = rootsFor(t, ca)
	sink := &eventSink{}
	ctx := WithLogger(context.Background(), sink.add)

	conn, _, err := d.dial(ctx, addr, "target.test", []string{"http/1.1"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	warnings := sink.warnings()
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want one: %v", len(warnings), warnings)
	}
	w := warnings[0]
	if !strings.Contains(w, "hostname_mismatch") {
		t.Errorf("warning does not classify a name mismatch: %q", w)
	}
	if !strings.Contains(w, "target.test") {
		t.Errorf("warning does not name the host that was asked for: %q", w)
	}
	if strings.Contains(w, "internal-only.example") {
		t.Errorf("warning echoed the certificate's own name: %q", w)
	}
}

// Deduplication keys on the normalized host, so a trailing dot or different
// case does not buy a second log line.
func TestWarningDedupUsesNormalizedHost(t *testing.T) {
	serverCA, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := serverCA.Leaf("dup.test")
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSOrigin(t, *leaf)

	d := newDialer()
	d.roots = x509.NewCertPool()
	sink := &eventSink{}
	ctx := WithLogger(context.Background(), sink.add)

	for _, name := range []string{"dup.test", "DUP.test", "dup.test."} {
		conn, _, err := d.dial(ctx, addr, name, []string{"http/1.1"})
		if err != nil {
			t.Fatalf("dial %q: %v", name, err)
		}
		conn.Close()
	}
	if got := sink.warnings(); len(got) != 1 {
		t.Fatalf("three spellings of one host produced %d warnings: %v", len(got), got)
	}
}

// The dedup set must be bounded: it is fed by however many hosts an engagement
// reaches, so it cannot grow for the life of the process.
func TestWarningDedupIsBounded(t *testing.T) {
	d := newDialer()
	for i := range warnHostLimit {
		if !d.markWarned(fmt.Sprintf("host%d.test", i)) {
			t.Fatalf("host%d.test was already marked", i)
		}
	}
	if d.markWarned("host0.test") {
		t.Fatal("a host already warned was warned again")
	}
	// One more distinct host pushes the oldest out, which is what keeps the set
	// bounded; the evicted host may then warn again.
	d.markWarned("overflow.test")
	if len(d.warned) > warnHostLimit {
		t.Fatalf("dedup set grew to %d, above the %d bound", len(d.warned), warnHostLimit)
	}
	if len(d.warnFIFO) > warnHostLimit {
		t.Fatalf("dedup order grew to %d, above the %d bound", len(d.warnFIFO), warnHostLimit)
	}
	if !d.markWarned("host0.test") {
		t.Fatal("the oldest host was never evicted, so the dedup set is not a bounded FIFO")
	}
}

// The leaf cache is bounded, and eviction drops the oldest host only.
func TestLeafCacheIsBoundedAndEvictsOldest(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca.leafLimit = 4
	for i := range 8 {
		if _, err := ca.Leaf(fmt.Sprintf("host%d.test", i)); err != nil {
			t.Fatalf("Leaf(host%d.test): %v", i, err)
		}
	}
	if len(ca.leafs) != 4 {
		t.Fatalf("cache holds %d leaves, want the bound of 4", len(ca.leafs))
	}
	for i := range 4 {
		if _, ok := ca.leafs[fmt.Sprintf("host%d.test", i)]; ok {
			t.Errorf("host%d.test should have been evicted", i)
		}
	}
	for i := 4; i < 8; i++ {
		if _, ok := ca.leafs[fmt.Sprintf("host%d.test", i)]; !ok {
			t.Errorf("host%d.test should still be cached", i)
		}
	}

	// An evicted host is still served, by minting a fresh leaf, and the cache
	// stays at its bound.
	leaf, err := ca.Leaf("host0.test")
	if err != nil {
		t.Fatalf("Leaf after eviction: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: rootsFor(t, ca), DNSName: "host0.test"}); err != nil {
		t.Fatalf("re-minted leaf does not verify: %v", err)
	}
	if len(ca.leafs) != 4 {
		t.Fatalf("cache grew to %d after re-mint, want 4", len(ca.leafs))
	}
}

// Evicting a leaf must not disturb a connection that is already using it: the
// cache only decides what to hand out next, and the handshake has already taken
// its own copy of the certificate.
func TestEvictionDoesNotBreakAnEstablishedConnection(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca.leafLimit = 2
	live, err := ca.Leaf("live.test")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*live},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err != nil {
			srvErr <- err
			return
		}
		line, err := bufio.NewReader(tc).ReadString('\n')
		if err != nil {
			srvErr <- err
			return
		}
		if _, err := io.WriteString(tc, "echo:"+line); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    rootsFor(t, ca),
		ServerName: "live.test",
	})
	if err != nil {
		t.Fatalf("client could not connect to the live leaf: %v", err)
	}
	defer client.Close()

	// Evict the certificate the connection is using, then prove the connection
	// still carries traffic.
	for _, host := range []string{"one.test", "two.test"} {
		if _, err := ca.Leaf(host); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := ca.leafs["live.test"]; ok {
		t.Fatal("live.test was not evicted; the test is not exercising eviction")
	}

	if _, err := io.WriteString(client, "ping\n"); err != nil {
		t.Fatalf("write after eviction failed: %v", err)
	}
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("read after eviction failed: %v", err)
	}
	if reply != "echo:ping\n" {
		t.Fatalf("reply = %q, want %q", reply, "echo:ping\n")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// A cached certificate near expiry must be replaced, not handed to a client
// that would then reject it.
func TestLeafCacheRemintsExpiredEntry(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	host := "stale.test"
	fresh, err := ca.Leaf(host)
	if err != nil {
		t.Fatal(err)
	}
	ca.mu.Lock()
	ca.leafs[host] = leafEntry{cert: fresh, notAfter: time.Now().Add(-time.Minute)}
	ca.mu.Unlock()

	renewed, err := ca.Leaf(host)
	if err != nil {
		t.Fatal(err)
	}
	if renewed == fresh {
		t.Fatal("an expired cached leaf was served again")
	}
	parsed, err := x509.ParseCertificate(renewed.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.NotAfter.After(time.Now()) {
		t.Fatalf("re-minted leaf expires at %s, already past", parsed.NotAfter)
	}
}

// Concurrent callers for one host must share a single mint: several
// certificates for one name would mean the client can see a different leaf on
// each connection.
func TestLeafConcurrentSameHostSharesOneCertificate(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	certs := make([]*tls.Certificate, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			certs[i], errs[i] = ca.Leaf("shared.test")
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if certs[i] != certs[0] {
			t.Fatalf("goroutine %d received a different certificate for the same host", i)
		}
	}
	if len(ca.leafs) != 1 {
		t.Fatalf("cache holds %d entries for one host", len(ca.leafs))
	}
}

// Minting happens outside the CA mutex, so many new hosts must proceed in
// parallel without corrupting the cache or losing entries.
func TestLeafConcurrentDistinctHosts(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca.leafLimit = 16
	const n = 64
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = ca.Leaf(fmt.Sprintf("parallel%d.test", i))
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	if len(ca.leafs) > ca.leafLimit {
		t.Fatalf("cache grew to %d, above the bound of %d", len(ca.leafs), ca.leafLimit)
	}
	if len(ca.leafFIFO) != len(ca.leafs) {
		t.Fatalf("insertion order has %d entries for %d cached leaves", len(ca.leafFIFO), len(ca.leafs))
	}
}

// The CA is still signed by the same key after caching work: a leaf from the
// cache and a fresh one must both verify under the CA certificate.
func TestCachedAndFreshLeavesVerify(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := rootsFor(t, ca)
	hosts := []string{"a.test", "b.test", "10.0.0.9"}
	for pass := range 2 { // second pass is served from cache
		for _, host := range hosts {
			leaf, err := ca.Leaf(host)
			if err != nil {
				t.Fatalf("pass %d Leaf(%q): %v", pass, host, err)
			}
			parsed, err := x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
				t.Fatalf("pass %d leaf for %q does not verify: %v", pass, host, err)
			}
		}
	}
}

// An IPv6 authority keeps its brackets for the Host header but the cache and
// the certificate must use the bare literal.
func TestLeafIPv6LiteralCachesUnderBareAddress(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf(hostFromAddr("[2001:db8::1]:443"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ca.leafs["2001:db8::1"]; !ok {
		t.Fatalf("leaf not cached under the bare address; cache keys = %v", cacheKeys(ca))
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.IPAddresses) != 1 || parsed.IPAddresses[0].String() != "2001:db8::1" {
		t.Fatalf("leaf IP SANs = %v, want 2001:db8::1", parsed.IPAddresses)
	}
}

// A dialer whose host has no trust store must still connect, and must report
// the upstream as unverified rather than staying silent.
func TestDialerWithoutRootsStillConnectsAndWarns(t *testing.T) {
	serverCA, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := serverCA.Leaf("noroots.test")
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSOrigin(t, *leaf)

	d := newDialer()
	d.rootsOnce.Do(func() {}) // pin the roots as absent, as on a host without a trust store
	sink := &eventSink{}
	ctx := WithLogger(context.Background(), sink.add)

	conn, _, err := d.dial(ctx, addr, "noroots.test", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if got := sink.warnings(); len(got) != 1 {
		t.Fatalf("got %d warnings, want one: %v", len(got), got)
	}
}

package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	uuid "github.com/satori/go.uuid"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// testSource is a policy source that returns one fixed state.
type testSource struct {
	mu sync.Mutex
	st netpolicy.State
}

func (s *testSource) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, nil
}

func (s *testSource) set(st netpolicy.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st = st
}

// loopbackState authorizes the loopback fixture addresses only.
func loopbackState() netpolicy.State {
	return netpolicy.State{
		Revision: 1,
		Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "127.0.0.1/32", Protocol: "any", Authorized: true},
			{ID: 2, Effect: "include", Pattern: "::1/128", Protocol: "any", Authorized: true},
		},
	}
}

func testSession() netpolicy.Session {
	return netpolicy.Session{ID: "session-a", TaskID: 1, Purpose: netpolicy.PurposeTesting, Revision: 1}
}

// newTestTransport builds a transport whose origin certificates are accepted
// through the explicit exception, since every fixture is self-signed.
func newTestTransport(t *testing.T, src netpolicy.Source, opts ...func(*Config)) *Transport {
	t.Helper()
	cfg := Config{
		Authorizer: netpolicy.NewAuthorizer(src),
		SessionFor: func(*http.Request) (netpolicy.Session, bool) { return testSession(), true },
		CertException: func(netpolicy.Session, string) bool {
			return true
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	return New(cfg)
}

// testConnContext is a proxy connection identity with no dialed state, which is
// what a request outside a CONNECT tunnel has.
func testConnContext() *mproxy.ConnContext {
	return &mproxy.ConnContext{ClientConn: &mproxy.ClientConn{Id: uuid.NewV4()}}
}

func connectRequest(t *testing.T, authority string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodConnect, "http://"+authority, nil)
	req.Host = authority
	return req
}

// TestTaskIDReportsTheResolvedSession is the recorder's attribution seam: the
// task of the session the gateway authorized the request with, and 0 for a
// request that resolves none. Reading it must not change either outcome.
func TestTaskIDReportsTheResolvedSession(t *testing.T) {
	ln, _ := countingListener(t)
	tr := newTestTransport(t, &testSource{st: loopbackState()})
	ctx := testConnContext()
	req := connectRequest(t, ln.Addr().String())

	// Before the dial, the request's own credential resolves the session.
	if got := tr.TaskID(ctx, req); got != testSession().TaskID {
		t.Fatalf("TaskID before dial = %d, want %d", got, testSession().TaskID)
	}
	conn, err := tr.Dial(context.Background(), ctx, req)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	// Inside the tunnel the connection's session answers, even though a request
	// there carries no credential of its own.
	if got := tr.TaskID(ctx, nil); got != testSession().TaskID {
		t.Fatalf("TaskID for the tunnel = %d, want %d", got, testSession().TaskID)
	}

	none := newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) {
		c.SessionFor = func(*http.Request) (netpolicy.Session, bool) { return netpolicy.Session{}, false }
	})
	if got := none.TaskID(testConnContext(), connectRequest(t, ln.Addr().String())); got != 0 {
		t.Fatalf("TaskID with no session = %d, want 0", got)
	}
	if _, err := none.Dial(context.Background(), testConnContext(), connectRequest(t, ln.Addr().String())); err == nil {
		t.Fatal("a request that resolved no session was dialed")
	}
}

func TestPolicyDenialBeforeDial(t *testing.T) {
	var accepts atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()

	src := &testSource{st: netpolicy.State{Revision: 1}} // no authorized rule
	tr := newTestTransport(t, src)

	_, err = tr.Dial(context.Background(), testConnContext(), connectRequest(t, ln.Addr().String()))
	var oe *mproxy.OriginError
	if !errors.As(err, &oe) {
		t.Fatalf("Dial error = %v, want an OriginError", err)
	}
	if oe.Stage != netpolicy.StagePolicy || oe.Status != http.StatusForbidden {
		t.Fatalf("refusal = stage %q status %d, want policy/403", oe.Stage, oe.Status)
	}
	// The listener is up and would accept instantly; a dial would be visible.
	time.Sleep(50 * time.Millisecond)
	if got := accepts.Load(); got != 0 {
		t.Fatalf("origin accepted %d connections before authorization", got)
	}
}

// TestOriginHandshakeIsUTLSChrome proves the origin sees a Chrome ClientHello,
// not the Go one, and that it offers h2 before http/1.1.
func TestOriginHandshakeIsUTLSChrome(t *testing.T) {
	var mu sync.Mutex
	var hellos []*tls.ClientHelloInfo
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			hellos = append(hellos, chi)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()})
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	uc, state, err := tr.Handshake(context.Background(), connCtx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	defer uc.Close()

	// Baseline: what crypto/tls sends to the same server.
	raw, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	std := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1"})
	if err := std.Handshake(); err != nil {
		t.Fatalf("crypto/tls baseline handshake: %v", err)
	}
	std.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(hellos) != 2 {
		t.Fatalf("captured %d ClientHellos, want 2", len(hellos))
	}
	chrome, golang := hellos[0], hellos[1]

	if want := []string{"h2", "http/1.1"}; !slices.Equal(chrome.SupportedProtos, want) {
		t.Errorf("Chrome ALPN = %v, want %v", chrome.SupportedProtos, want)
	}
	if !slices.Contains(chrome.SupportedVersions, uint16(tls.VersionTLS13)) {
		t.Errorf("Chrome supported versions = %v, want TLS 1.3", chrome.SupportedVersions)
	}
	if slices.Equal(chrome.SignatureSchemes, golang.SignatureSchemes) {
		t.Errorf("Chrome signature schemes match crypto/tls (%v); the uTLS profile is not applied", chrome.SignatureSchemes)
	}
	if state.NegotiatedProtocol != "http/1.1" {
		// StartTLS pins the fixture to http/1.1; the ALPN offer above is what
		// the profile controls.
		t.Logf("negotiated %q", state.NegotiatedProtocol)
	}
	if !state.HandshakeComplete {
		t.Error("handshake state is not complete")
	}
}

// TestStrictVerificationRefusesUnknownOrigin proves the default is strict: with
// no exception callback the self-signed fixture is refused at the tls stage.
func TestStrictVerificationRefusesUnknownOrigin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) { c.CertException = nil })
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_, _, err = tr.Handshake(context.Background(), connCtx, conn, "127.0.0.1")
	var oe *mproxy.OriginError
	if !errors.As(err, &oe) || oe.Stage != netpolicy.StageTLS {
		t.Fatalf("Handshake error = %v, want a tls-stage OriginError", err)
	}
}

// TestH2Fidelity proves an h2 origin receives the request as the client sent it.
func TestH2Fidelity(t *testing.T) {
	type seen struct {
		proto  int
		dup    []string
		accept string
		cookie string
		proxy  string
		digest string
	}
	got := make(chan seen, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		got <- seen{
			proto:  r.ProtoMajor,
			dup:    r.Header.Values("X-Dup"),
			accept: r.Header.Get("Accept"),
			cookie: r.Header.Get("Cookie"),
			proxy:  r.Header.Get("Proxy-Authorization"),
			digest: fmt.Sprintf("%x", sum),
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()})
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	uc, state, err := tr.Handshake(context.Background(), connCtx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	defer uc.Close()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("origin ALPN = %q, want h2", state.NegotiatedProtocol)
	}

	const payload = "duplicate-header-body"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/x", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Dup", "one")
	req.Header.Add("X-Dup", "two")
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Cookie", "a=1; b=2")
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")

	res, err := tr.RoundTrip(context.Background(), connCtx, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if stage := res.Header.Get(HeaderStage); stage != "" {
		t.Fatalf("gateway stage header on a successful response: %q", stage)
	}

	s := <-got
	if s.proto != 2 {
		t.Errorf("origin saw HTTP/%d, want 2", s.proto)
	}
	if want := []string{"one", "two"}; !slices.Equal(s.dup, want) {
		t.Errorf("duplicate X-Dup = %v, want %v", s.dup, want)
	}
	if s.accept != "application/vnd.api+json" {
		t.Errorf("Accept = %q", s.accept)
	}
	if s.cookie != "a=1; b=2" {
		t.Errorf("Cookie = %q", s.cookie)
	}
	if s.proxy != "" {
		t.Errorf("gateway credentials reached the origin: %q", s.proxy)
	}
	sum := sha256.Sum256([]byte(payload))
	if s.digest != fmt.Sprintf("%x", sum) {
		t.Errorf("request body digest changed")
	}
}

// TestH1Fidelity proves an http/1.1-only origin keeps duplicate headers and the
// request semantics the client sent.
func TestH1Fidelity(t *testing.T) {
	type seen struct {
		proto int
		dup   []string
		auth  string
	}
	got := make(chan seen, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{proto: r.ProtoMajor, dup: r.Header.Values("X-Dup"), auth: r.Header.Get("Authorization")}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()})
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	uc, state, err := tr.Handshake(context.Background(), connCtx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	defer uc.Close()
	if state.NegotiatedProtocol == "h2" {
		t.Fatalf("fixture negotiated h2; it is meant to be http/1.1 only")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Dup", "one")
	req.Header.Add("X-Dup", "two")
	req.Header.Set("Authorization", "Bearer target-token")
	req.Header.Set("Connection", "keep-alive, X-Drop-Me")
	req.Header.Set("X-Drop-Me", "1")

	res, err := tr.RoundTrip(context.Background(), connCtx, req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()

	s := <-got
	if s.proto != 1 {
		t.Errorf("origin saw HTTP/%d, want 1", s.proto)
	}
	if want := []string{"one", "two"}; !slices.Equal(s.dup, want) {
		t.Errorf("duplicate X-Dup = %v, want %v", s.dup, want)
	}
	if s.auth != "Bearer target-token" {
		t.Errorf("Authorization = %q", s.auth)
	}
}

// TestPooledReuseIsSessionBound proves the pool is keyed by session and that a
// refusal ends the connections the session was already using.
func TestPooledReuseIsSessionBound(t *testing.T) {
	var handshakes atomic.Int32
	var mu sync.Mutex
	tokensByConn := map[string][]string{}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokensByConn[r.RemoteAddr] = append(tokensByConn[r.RemoteAddr], r.Header.Get("Authorization"))
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			handshakes.Add(1)
			return nil, nil
		},
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	src := &testSource{st: loopbackState()}
	tr := newTestTransport(t, src, func(c *Config) {
		c.SessionFor = func(req *http.Request) (netpolicy.Session, bool) {
			s := testSession()
			s.ID = req.Header.Get("X-Session")
			return s, true
		}
	})

	get := func(t *testing.T, session, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Session", session)
		req.Header.Set("Authorization", token)
		res, err := tr.RoundTrip(context.Background(), testConnContext(), req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res
	}

	get(t, "session-a", "token-a") // dial + handshake #1
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("handshakes after the first request = %d, want 1", got)
	}
	get(t, "session-a", "token-a") // pooled reuse
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("handshakes after a pooled reuse = %d, want 1", got)
	}
	get(t, "session-b", "token-b") // different session, own connection
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("handshakes after a second session = %d, want 2", got)
	}

	mu.Lock()
	for addr, tokens := range tokensByConn {
		if len(slices.Compact(slices.Sorted(slices.Values(tokens)))) > 1 {
			t.Errorf("connection %s carried headers from more than one session: %v", addr, tokens)
		}
	}
	mu.Unlock()

	// A refusal must drop the session's pooled connections, so restoring the
	// grant cannot resume them. A policy change bumps the task revision, which
	// the pool key carries, so no connection from the old policy is reused.
	src.set(netpolicy.State{Revision: 2})
	res := get(t, "session-a", "token-a")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("denied request status = %d, want 403", res.StatusCode)
	}
	if stage := res.Header.Get(HeaderStage); stage != netpolicy.StagePolicy {
		t.Fatalf("denied request stage = %q, want policy", stage)
	}
	restored := loopbackState()
	restored.Revision = 3
	src.set(restored)
	get(t, "session-a", "token-a")
	if got := handshakes.Load(); got != 3 {
		t.Fatalf("handshakes after a revoke = %d, want 3 (the pool must not resume)", got)
	}
}

// TestCancellationAbortsOrigin proves a cancelled request stops the origin
// exchange instead of leaving it running.
func TestCancellationAbortsOrigin(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	defer srv.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()})
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/stall", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *http.Response, 1)
	go func() {
		res, err := tr.RoundTrip(ctx, testConnContext(), req)
		if err != nil {
			t.Errorf("RoundTrip: %v", err)
			done <- nil
			return
		}
		done <- res
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never received the request")
	}
	cancel()

	select {
	case res := <-done:
		if res == nil {
			return
		}
		defer res.Body.Close()
		if stage := res.Header.Get(HeaderStage); stage != netpolicy.StageTransport {
			t.Fatalf("cancelled request stage = %q, want transport", stage)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip did not return after cancellation")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("origin request context was not cancelled")
	}
}

// TestOriginKeyLog proves the origin handshake writes its secrets to the key
// log, which is what makes a captured trace decryptable.
func TestOriginKeyLog(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	var buf syncBuffer
	tr := newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) { c.KeyLogWriter = &buf })
	connCtx := testConnContext()
	conn, err := tr.Dial(context.Background(), connCtx, connectRequest(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	uc, _, err := tr.Handshake(context.Background(), connCtx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	defer uc.Close()

	if got := buf.String(); !strings.Contains(got, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") {
		t.Fatalf("key log has no origin client secret: %q", got)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestDialCancellationStopsTheDial proves a cancelled request never completes
// the origin dial.
func TestDialCancellationStopsTheDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tr := newTestTransport(t, &testSource{st: loopbackState()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tr.Dial(ctx, testConnContext(), connectRequest(t, ln.Addr().String()))
	var oe *mproxy.OriginError
	if !errors.As(err, &oe) {
		t.Fatalf("Dial error = %v, want an OriginError", err)
	}
	if oe.Stage != netpolicy.StageDial {
		t.Fatalf("stage = %q, want dial", oe.Stage)
	}
}

// TestExitIsApplied proves the operator exit carries the origin connection: the
// origin sees the exit's address, never the gateway's own route.
func TestExitIsApplied(t *testing.T) {
	var viaExit atomic.Bool
	exitLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer exitLn.Close()
	go func() {
		for {
			c, err := exitLn.Accept()
			if err != nil {
				return
			}
			viaExit.Store(true)
			c.Close()
		}
	}()

	tr := newTestTransport(t, &testSource{st: loopbackState()})
	tr.SetExit(netpolicy.Exit{ProxyURL: "http://" + exitLn.Addr().String()})

	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	_, err = tr.Dial(context.Background(), testConnContext(), connectRequest(t, origin.Addr().String()))
	if err == nil {
		t.Log("dial through the stub exit succeeded")
	}
	if !viaExit.Load() {
		t.Fatal("the origin dial bypassed the operator exit")
	}
	if got := tr.Exit().ProxyURL; !strings.Contains(got, exitLn.Addr().String()) {
		t.Fatalf("Exit() = %q, want the configured exit", got)
	}
}

// TestPlainHTTPDNSRefusalReachesTheClient pins that a plain-HTTP request the
// policy refuses at the dns stage returns the synthetic 403 instead of hanging:
// the refusal runs on the pooled path, which must not hold the entry lock while
// the refusal drops the session's entries.
func TestPlainHTTPDNSRefusalReachesTheClient(t *testing.T) {
	var accepts atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()

	// The name is authorized and every address it can resolve to is excluded,
	// so the refusal is the dns stage and no dial may follow it.
	src := &testSource{st: netpolicy.State{
		Revision: 1,
		Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "localhost", Protocol: "any", Authorized: true},
			{ID: 2, Effect: "exclude", Pattern: "127.0.0.1/32", Protocol: "any", Authorized: true},
			{ID: 3, Effect: "exclude", Pattern: "::1/128", Protocol: "any", Authorized: true},
		},
	}}
	tr := newTestTransport(t, src)

	port := ln.Addr().(*net.TCPAddr).Port
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/x", port), nil)

	type result struct {
		res *http.Response
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := tr.RoundTrip(context.Background(), testConnContext(), req)
		done <- result{res, err}
	}()

	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip did not return: the dns refusal was lost")
	}
	if got.err != nil {
		t.Fatalf("RoundTrip: %v", got.err)
	}
	defer got.res.Body.Close()
	if got.res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got.res.StatusCode)
	}
	if stage := got.res.Header.Get(HeaderStage); stage != netpolicy.StageDNS {
		t.Fatalf("stage = %q, want dns", stage)
	}
	if n := accepts.Load(); n != 0 {
		t.Fatalf("origin accepted %d connections after a dns refusal", n)
	}
}

// countingListener listens on loopback and counts accepted connections, so a
// test can prove a refusal never dialled.
func countingListener(t *testing.T) (net.Listener, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()
	return ln, &accepts
}

// noSessionTransport is a transport whose credential never resolves a session.
func noSessionTransport(t *testing.T) *Transport {
	t.Helper()
	return newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) {
		c.SessionFor = func(*http.Request) (netpolicy.Session, bool) { return netpolicy.Session{}, false }
	})
}

// TestConnectNoCredentialIsChallenged proves a CONNECT carrying no proxy
// credential is challenged instead of refused, so a browser can send the
// session credential it sends only after a 407. The origin is never dialed.
func TestConnectNoCredentialIsChallenged(t *testing.T) {
	ln, accepts := countingListener(t)
	tr := noSessionTransport(t)

	_, err := tr.Dial(context.Background(), testConnContext(), connectRequest(t, ln.Addr().String()))
	var oe *mproxy.OriginError
	if !errors.As(err, &oe) {
		t.Fatalf("Dial error = %v, want an OriginError", err)
	}
	if oe.Stage != netpolicy.StagePolicy || oe.Status != http.StatusProxyAuthRequired {
		t.Fatalf("refusal = stage %q status %d, want policy/407", oe.Stage, oe.Status)
	}
	if got := oe.Header.Get("Proxy-Authenticate"); got != proxyChallenge {
		t.Fatalf("challenge = %q, want %q", got, proxyChallenge)
	}
	time.Sleep(50 * time.Millisecond)
	if got := accepts.Load(); got != 0 {
		t.Fatalf("origin accepted %d connections without a credential", got)
	}
}

// TestConnectUnknownCredentialIsRefused proves a credential that resolves no
// session keeps the refusal: a challenge there would make a browser retry the
// same dead credential forever.
func TestConnectUnknownCredentialIsRefused(t *testing.T) {
	ln, accepts := countingListener(t)
	tr := noSessionTransport(t)
	req := connectRequest(t, ln.Addr().String())
	req.Header.Set("Proxy-Authorization", "Basic c3RhbGU=")

	_, err := tr.Dial(context.Background(), testConnContext(), req)
	var oe *mproxy.OriginError
	if !errors.As(err, &oe) {
		t.Fatalf("Dial error = %v, want an OriginError", err)
	}
	if oe.Stage != netpolicy.StagePolicy || oe.Status != http.StatusForbidden {
		t.Fatalf("refusal = stage %q status %d, want policy/403", oe.Stage, oe.Status)
	}
	if got := oe.Header.Get("Proxy-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none for a credential that resolved nothing", got)
	}
	if got := accepts.Load(); got != 0 {
		t.Fatalf("origin accepted %d connections for an unknown credential", got)
	}
}

// TestPlainHTTPNoCredentialIsChallenged proves the plain-HTTP path answers the
// same way: no credential is challenged, a credential that resolves nothing is
// refused, and a resolving one is unaffected.
func TestPlainHTTPNoCredentialIsChallenged(t *testing.T) {
	var served atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	cases := []struct {
		name      string
		cred      string
		session   bool
		status    int
		challenge bool
	}{
		{name: "no credential", status: http.StatusProxyAuthRequired, challenge: true},
		{name: "unknown credential", cred: "Basic c3RhbGU=", status: http.StatusForbidden},
		{name: "resolved credential", cred: "Basic c2Vzc2lvbg==", session: true, status: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTestTransport(t, &testSource{st: loopbackState()}, func(c *Config) {
				c.SessionFor = func(*http.Request) (netpolicy.Session, bool) { return testSession(), tc.session }
			})
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.cred != "" {
				req.Header.Set("Proxy-Authorization", tc.cred)
			}
			res, err := tr.RoundTrip(context.Background(), testConnContext(), req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.status)
			}
			if got := res.Header.Get("Proxy-Authenticate"); (got != "") != tc.challenge {
				t.Fatalf("challenge = %q, want present=%v", got, tc.challenge)
			}
			stage := res.Header.Get(HeaderStage)
			if tc.status == http.StatusOK {
				if stage != "" {
					t.Fatalf("authorized request carries the gateway stage %q", stage)
				}
				return
			}
			if stage != netpolicy.StagePolicy {
				t.Fatalf("stage = %q, want policy", stage)
			}
		})
	}
	if got := served.Load(); got != 1 {
		t.Fatalf("origin served %d requests, want 1 (only the resolved credential)", got)
	}
}

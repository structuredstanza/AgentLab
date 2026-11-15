package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// gatewayAddr is the recorder's address as ProxyAddr returns it.
const gatewayAddr = "http://127.0.0.1:8788"

// credentialSession is one issued session with the credential the gateway
// resolves it from.
func credentialSession() netpolicy.Session {
	return netpolicy.Session{
		ID: "credential-run", TaskID: 7, ConversationID: 3,
		Purpose: netpolicy.PurposeTesting, Revision: 1, Credential: "cred-0123456789abcdef",
	}
}

// proxyServer is a Server whose manager reports the gateway address, so the
// tool-facing proxy construction can be driven without a recorder.
func proxyServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{m: &Manager{dir: t.TempDir(), globalProxy: gatewayAddr}}
	return s
}

// TestNoToolFacingProxyURLIsBare is the startup assertion for the network
// boundary: the gateway accepts no anonymous request, so every place that hands a
// tool a proxy URL must carry the credential of the run's own session. A bare
// address here is a request the gateway refuses at the policy stage, which is
// exactly the failure this test exists to catch before it reaches a run.
//
// It walks the construction sites: the manifest renderer's {{ proxy }} and
// {{ proxyhost }}, the manifest child's environment, Chromium's --proxy-server,
// and the custom http tool's transport. The agent Bash env is the same helper and
// is covered by agent.TestRunProxyURLCarriesTheRunSessionCredential.
func TestNoToolFacingProxyURLIsBare(t *testing.T) {
	sess := credentialSession()
	ctx := execbox.WithSession(context.Background(), sess)
	want := "http://" + sess.Credential + "@127.0.0.1:8788"
	s := proxyServer(t)
	proxy := s.m.ToolProxyURL(sess)
	if proxy != want {
		t.Fatalf("ToolProxyURL = %q, want %q", proxy, want)
	}

	// 1. The manifest renderer: both placeholder forms carry the credential.
	m := &manifest.Manifest{
		ID:      "credential-proxy",
		Name:    "credential proxy",
		Command: manifest.Command{Program: "tool", Args: []string{"--proxy", "{{ proxy }}", "--proxy-host", "{{ proxyhost }}"}},
	}
	args, err := m.Resolve("example.test", nil, proxy)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantArgs := []string{"--proxy", want, "--proxy-host", strings.TrimPrefix(want, "http://")}
	if strings.Join(args, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("argv %v, want %v: both placeholder forms carry the credential", args, wantArgs)
	}

	// 2. The manifest child's environment: a tool that ignores its flag still
	//    reaches the gateway with this run's credential.
	f := installFakeClient(t)
	f.stdout = "a.example\n"
	ms, _ := fixtureServer(t, fixtureManifestTOML)
	ms.m.globalProxy = gatewayAddr
	callRunTool(t, ms, ctx, "fixture-run", "example.com")
	spec, got, ok := f.last()
	if !ok {
		t.Fatal("the manifest tool never reached the execution boundary")
	}
	if got.Credential != sess.Credential {
		t.Errorf("the child ran under %q, want the run's own session", got.ID)
	}
	env := strings.Join(spec.Env, " ")
	for _, key := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "http_proxy="} {
		if !strings.Contains(env, key+want) {
			t.Errorf("child env is missing %s%s: %v", key, want, spec.Env)
		}
	}
	if strings.Contains(env, "="+gatewayAddr) {
		t.Errorf("child env carries a bare proxy address: %v", spec.Env)
	}

	// 3. Chromium's --proxy-server: the browser launches under a session of its
	//    own, so the address goes out bare and that session's credential is
	//    answered over CDP, because Chromium ignores credentials here.
	browserSess := netpolicy.Session{
		ID: "browser-launch", TaskID: sess.TaskID,
		Purpose: netpolicy.PurposeTesting, Credential: "browser-credential",
	}
	s.m.sessMu.Lock()
	s.m.sessions = map[string]netpolicy.Session{browserSess.Credential: browserSess}
	s.m.sessMu.Unlock()
	opts := browserLaunchOptions(s, execbox.WithSession(context.Background(), browserSess), "7")
	if opts.ProxyServer != gatewayAddr {
		t.Errorf("Chromium --proxy-server = %q, want the bare %q", opts.ProxyServer, gatewayAddr)
	}
	if opts.ProxyUser != browserSess.Credential || opts.ProxyPass != "" {
		t.Errorf("Chromium proxy credential = %q/%q, want the launch session's credential", opts.ProxyUser, opts.ProxyPass)
	}
	authReq, _ := http.NewRequest(http.MethodGet, gatewayAddr, nil)
	authReq.Header.Set("Proxy-Authorization", "Bearer "+opts.ProxyUser)
	if _, ok := s.m.gatewaySession(authReq); !ok {
		t.Error("Chromium's proxy credential does not resolve a live gateway session")
	}

	// 4. The custom http tool's transport.
	tr, err := s.httpProxyTransport(ctx, httpExec{UseRecordingProxy: true})
	if err != nil {
		t.Fatalf("httpProxyTransport: %v", err)
	}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "api.example.com"}}
	pu, err := tr.Proxy(req)
	if err != nil || pu == nil {
		t.Fatalf("transport proxy = %v, %v", pu, err)
	}
	if got := pu.String(); got != want {
		t.Errorf("http tool proxy = %q, want %q", got, want)
	}
}

// A run with no session gets no proxy at all: an address without a credential is
// a request the gateway refuses, so rendering one would only produce a failure
// that looks like a target-side block.
func TestNoSessionMeansNoToolFacingProxy(t *testing.T) {
	s := proxyServer(t)
	ctx := context.Background()

	if got := s.m.ToolProxyURL(netpolicy.Session{}); got != "" {
		t.Fatalf("ToolProxyURL with no session = %q, want no proxy", got)
	}
	if got := browserLaunchOptions(s, ctx, "7").ProxyServer; got != "" {
		t.Errorf("Chromium --proxy-server = %q with no session", got)
	}
	if _, err := s.httpProxyTransport(ctx, httpExec{UseRecordingProxy: true}); err == nil {
		t.Error("the http tool accepted use_recording_proxy with no session; it must refuse rather than go direct")
	}
	m := &manifest.Manifest{ID: "no-session", Name: "no session", Command: manifest.Command{Program: "tool", Args: []string{"-u", "{{ target.value }}", "{{ proxy | --proxy }}"}}}
	args, err := m.Resolve("example.test", nil, execbox.ProxyURL(ctx, gatewayAddr))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"-u", "example.test"}; strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v with no session, want %v: no proxy flag at all", args, want)
	}
}

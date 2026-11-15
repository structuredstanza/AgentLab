package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

// stateSource answers every session with one fixed policy state.
type stateSource struct {
	mu sync.Mutex
	st netpolicy.State
}

func (s *stateSource) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, nil
}

// startGatewayRecorder runs a real recorder over a real gateway for one test and
// returns its proxy address.
func startGatewayRecorder(t *testing.T, sess netpolicy.Session, st netpolicy.State) string {
	t.Helper()
	gw := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(&stateSource{st: st}),
		SessionFor: func(req *http.Request) (netpolicy.Session, bool) {
			if gatewayCredential(req) != sess.Credential {
				return netpolicy.Session{}, false
			}
			return sess, true
		},
	})
	addr := freeAddr(t)
	tr, err := traffic.OpenWithTransport(t.TempDir(), addr, gw)
	if err != nil {
		t.Fatalf("OpenWithTransport: %v", err)
	}
	go func() { _ = tr.Start() }()
	t.Cleanup(func() {
		tr.Close()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the recorder never listened on %s", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return tr.ProxyAddr()
}

// freeAddr returns a loopback address nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// portOf returns the port of an httptest server's URL.
func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// TestKernelWorkerBashReachesTheGateway is the guest proof for the Bash path: a
// worker-shaped call runs inside a real session, its environment carries the
// proxy URL with the run's credential, and the gateway accepts the request for an
// authorized destination and refuses an unauthorized one at the policy stage.
//
// It is the counterpart of TestKernelRunToolReachesOnlyTheGateway: that one
// proves the packet boundary, this one proves the credential the boundary cannot
// supply. Without it every request a worker makes is a policy refusal, which
// looks like a target-side block rather than a missing credential.
func TestKernelWorkerBashReachesTheGateway(t *testing.T) {
	requireExecboxKernel(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("BLOCKED: curl is not installed, so a worker-shaped HTTP call cannot be made")
	}

	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("allowed-origin"))
	}))
	defer allowed.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("target-origin"))
	}))
	defer target.Close()
	allowedPort := portOf(t, allowed.URL)

	sess := credentialSession()
	// Only the allowed origin's port is authorized; the target server is a
	// destination the operator never granted.
	proxyAddr := startGatewayRecorder(t, sess, netpolicy.State{
		Revision: 1,
		Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "127.0.0.1/32", Protocol: "any", Ports: []int{allowedPort}, Authorized: true},
		},
	})
	proxy := netpolicy.ProxyURL(sess, proxyAddr)
	if proxy == "" {
		t.Fatal("the run's proxy URL carries no credential")
	}

	client := startExecboxSupervisor(t, strings.TrimPrefix(proxyAddr, "http://"))
	execbox.Install(client)
	t.Cleanup(func() { execbox.Install(nil) })

	// A worker-shaped Bash call: the same environment the Bash tool gets, then a
	// request to the authorized origin.
	script := fmt.Sprintf(`curl -sS -D - -o /dev/null -w 'status=%%{http_code}' %s/`, allowed.URL)
	out, err := runInSession(t, client, sess, proxy, script)
	if err != nil {
		t.Fatalf("the authorized call did not run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "status=200") {
		t.Fatalf("authorized call = %q, want the origin's 200", out)
	}

	// The same call to a destination the policy does not cover: the gateway
	// refuses it at the policy stage, before any dial.
	script = fmt.Sprintf(`curl -sS -D - -o /dev/null -w 'status=%%{http_code}' %s/`, target.URL)
	out, err = runInSession(t, client, sess, proxy, script)
	if err != nil {
		t.Fatalf("the unauthorized call did not run: %v\n%s", err, out)
	}
	for _, want := range []string{"status=403", gateway.HeaderStage + ": " + netpolicy.StagePolicy} {
		if !strings.Contains(out, want) {
			t.Errorf("unauthorized call = %q, want %q", out, want)
		}
	}
	if strings.Contains(out, "target-origin") {
		t.Errorf("the unauthorized destination answered: %q", out)
	}

	// The credential is what makes the difference: the same call with the bare
	// address is refused before the policy is even asked.
	out, err = runInSession(t, client, sess, proxyAddr, script)
	if err != nil {
		t.Fatalf("the bare-address call did not run: %v\n%s", err, out)
	}
	if strings.Contains(out, "status=200") || strings.Contains(out, "target-origin") {
		t.Errorf("a request with no credential was accepted: %q", out)
	}
}

// runInSession runs one bash command inside the session with the run's proxy
// environment, the way the Bash tool does.
func runInSession(t *testing.T, client execbox.Client, sess netpolicy.Session, proxy, script string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := client.RunOnce(ctx, sess, execbox.Spec{
		Argv: []string{"bash", "-c", script},
		Dir:  "/tmp",
		Env:  agent.ProxyEnv(proxy, ""),
	})
	return string(res.Output), err
}

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

// outField returns the value of the "key=value" line in a session's output.
func outField(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// startTLSRecorder is startGatewayRecorder with the origin certificate check
// under the test's control: while trusted is false the gateway verifies origins
// strictly, so the httptest origin (a certificate no system root signed) is a
// bad origin; once true the operator exception admits it. The recorder's own
// store, CA included, is a real traffic tree, and its CA path is returned.
func startTLSRecorder(t *testing.T, sess netpolicy.Session, st netpolicy.State, trusted *atomic.Bool) (proxyAddr, caPath string) {
	t.Helper()
	gw := gateway.New(gateway.Config{
		Authorizer: netpolicy.NewAuthorizer(&stateSource{st: st}),
		SessionFor: func(req *http.Request) (netpolicy.Session, bool) {
			if gatewayCredential(req) != sess.Credential {
				return netpolicy.Session{}, false
			}
			return sess, true
		},
		CertException: func(netpolicy.Session, string) bool { return trusted.Load() },
	})
	addr := freeAddr(t)
	tr, err := traffic.OpenWithTransport(filepath.Join(t.TempDir(), "traffic"), addr, gw)
	if err != nil {
		t.Fatalf("OpenWithTransport: %v", err)
	}
	go func() { _ = tr.Start() }()
	t.Cleanup(func() { tr.Close() })
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
	return tr.ProxyAddr(), tr.CACertPath()
}

// TestKernelRecorderCAServesEveryIsolatedClient is the guest proof for the
// recorder CA, with no database: a real recorder over a real gateway, a real
// supervisor configured with the recorder's CACert, and clients inside real
// sessions. It shows that
//   - the certificate is readable at the path ProxyEnv hands out, the signing key
//     and the rest of the traffic tree are not there, and it cannot be written;
//   - HTTPS through the recorder verifies for Bash/curl, Python urllib and
//     requests, Node and Obscura when installed, using only that file;
//   - a client without the file fails verification (no trust bypass);
//   - an origin the gateway rejects fails at CONNECT with the gateway's status.
//
// Clients that are not installed in the guest are logged as absent, not passed.
func TestKernelRecorderCAServesEveryIsolatedClient(t *testing.T) {
	requireExecboxKernel(t)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("good-origin"))
	}))
	defer origin.Close()
	// By name, not by IP: the recorder re-signs for the requested host, and its
	// generated leaf carries a DNS name, so an IP URL fails on the name, not on
	// trust. localhost resolves to the origin without leaving the guest.
	url := "https://localhost:" + fmt.Sprint(portOf(t, origin.URL)) + "/"

	sess := credentialSession()
	var trusted atomic.Bool
	proxyAddr, caPath := startTLSRecorder(t, sess, netpolicy.State{
		Revision: 1,
		Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "127.0.0.1/32", Protocol: "any", Ports: []int{portOf(t, origin.URL)}, Authorized: true},
			{ID: 2, Effect: "include", Pattern: "localhost", Protocol: "any", Ports: []int{portOf(t, origin.URL)}, Authorized: true},
		},
	}, &trusted)
	proxy := netpolicy.ProxyURL(sess, proxyAddr)
	client, _ := startExecboxSupervisorWithWorkspace(t, strings.TrimPrefix(proxyAddr, "http://"),
		func(c *execbox.Config) { c.CACert = caPath })
	execbox.Install(client)
	t.Cleanup(func() { execbox.Install(nil) })

	run := func(env []string, script string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		res, err := client.RunOnce(ctx, sess, execbox.Spec{Argv: []string{"bash", "-c", script}, Dir: "/tmp", Env: env})
		if err != nil {
			t.Fatalf("session did not run: %v\n%s", err, res.Output)
		}
		return string(res.Output)
	}
	env := agent.ProxyEnv(proxy, caPath) // exactly what Bash, tools and the research browser get
	curl := `curl -sS -o /tmp/body -w 'http=%{http_code} connect=%{http_connect} verify=%{ssl_verify_result}\n' ` + url + `; echo rc=$?; cat /tmp/body 2>/dev/null`

	// 1. The certificate, and only the certificate, is in the session.
	want, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(want)
	trafficDir := filepath.Dir(filepath.Dir(caPath))
	out := run(env, fmt.Sprintf(`echo sha=$(sha256sum %[1]s | cut -d' ' -f1)
echo caDir=$(ls %[2]s | tr '\n' ,)
echo trafficDir=$(ls %[3]s | tr '\n' ,)
echo key=$( (cat %[2]s/mitmproxy-ca.pem >/dev/null 2>&1 && echo visible) || echo hidden)
echo index=$( (ls %[3]s/_index >/dev/null 2>&1 && echo visible) || echo hidden)
echo write=$( (echo x >> %[1]s) 2>/dev/null && echo allowed || echo refused)`, caPath, filepath.Dir(caPath), trafficDir))
	t.Logf("mount checks:\n%s", out)
	for k, v := range map[string]string{
		"sha": hex.EncodeToString(sum[:]), "caDir": "mitmproxy-ca-cert.pem,", "trafficDir": "_ca,",
		"key": "hidden", "index": "hidden", "write": "refused",
	} {
		if got := outField(out, k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	// 2. A bad origin: the gateway rejects its certificate at CONNECT, and no
	// body reaches the client.
	out = run(env, curl)
	t.Logf("bad origin:\n%s", out)
	if strings.Contains(out, "good-origin") || strings.Contains(out, "http=200") || strings.Contains(out, "rc=0") {
		t.Errorf("a bad origin was served or tunnelled: %q", out)
	}

	// 3. No CA, no trust: the same request from a client that was not given the
	// file fails verification (curl exit 60).
	trusted.Store(true)
	out = run(agent.ProxyEnv(proxy, ""), curl)
	t.Logf("no CA:\n%s", out)
	if strings.Contains(out, "good-origin") || !strings.Contains(out, "rc=60") {
		t.Errorf("a client without the recorder CA was not refused: %q", out)
	}

	// 4. Every client trusts the recorder through the mounted file.
	check := func(name, script string) {
		t.Helper()
		out := run(env, script)
		t.Logf("%s:\n%s", name, out)
		if !strings.Contains(out, "good-origin") {
			t.Errorf("%s did not read the origin through the recorder: %q", name, out)
		}
	}
	check("curl", curl)
	if strings.Contains(run(env, "command -v python3 >/dev/null && echo yes"), "yes") {
		check("python urllib", `python3 -c "import urllib.request as u; print(u.urlopen('`+url+`', timeout=30).read().decode())"`)
		if strings.Contains(run(env, `python3 -c "import requests" 2>&1 && echo yes`), "yes") {
			check("python requests", `python3 -c "import requests; print(requests.get('`+url+`', timeout=30).text)"`)
		} else {
			t.Log("python requests is not installed in this guest; not exercised")
		}
	} else {
		t.Log("python3 is not installed in this guest; not exercised")
	}
	if v := run(env, "node -p 'process.versions.node.split(\".\")[0]' 2>/dev/null"); strings.TrimSpace(v) >= "24" && len(strings.TrimSpace(v)) == 2 {
		check("node fetch", `node -e "fetch('`+url+`').then(r=>r.text()).then(console.log)"`)
	} else {
		t.Logf("node >= 24 is not installed in this guest (%q); not exercised", strings.TrimSpace(v))
	}
	// The research browser takes the gateway as --proxy and the CA in
	// SSL_CERT_FILE only, as researchServer launches it.
	if strings.Contains(run(env, "command -v obscura >/dev/null && echo yes"), "yes") {
		// The fixture origin is loopback, which the browser's own SSRF guard
		// refuses; a real research target is public and needs no such flag.
		check("obscura", fmt.Sprintf(`SSL_CERT_FILE=%s obscura fetch --allow-private-network --proxy %s --dump text %s 2>&1`, caPath, proxy, url))
	} else {
		t.Log("obscura is not installed in this guest; not exercised")
	}
}

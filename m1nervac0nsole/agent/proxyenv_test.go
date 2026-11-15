package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

func TestProxyEnvEmptyIsNil(t *testing.T) {
	if env := ProxyEnv("", ""); env != nil {
		t.Fatalf("ProxyEnv(\"\", \"\") = %v, want nil (direct)", env)
	}
}

func TestProxyEnvSetsAllProxyForSocks5(t *testing.T) {
	// Capture-off egress path: a socks5 proxy, no MITM CA. ALL_PROXY must be set
	// (curl reads socks5 only from there), and no CA vars should appear.
	env := ProxyEnv("socks5://10.0.0.1:1080", "")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "all_proxy="} {
		if !has(want) {
			t.Errorf("ProxyEnv missing %s: %v", want, env)
		}
	}
	if has("SSL_CERT_FILE=") || has("CURL_CA_BUNDLE=") {
		t.Errorf("ProxyEnv without CA must not inject CA vars: %v", env)
	}
}

func TestProxyEnvInjectsCAWhenRecording(t *testing.T) {
	env := ProxyEnv("http://127.0.0.1:8788", "/data/ca.pem")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"SSL_CERT_FILE=", "CURL_CA_BUNDLE=", "REQUESTS_CA_BUNDLE=", "NODE_EXTRA_CA_CERTS="} {
		if !has(want) {
			t.Errorf("ProxyEnv with CA missing %s: %v", want, env)
		}
	}
}

// The proxy a run's tools are handed is the gateway address with that run's
// session credential: the gateway accepts no anonymous request, so a bare
// address can only be refused at the policy stage.
func TestRunProxyURLCarriesTheRunSessionCredential(t *testing.T) {
	sess := netpolicy.Session{ID: "run", TaskID: 7, Purpose: netpolicy.PurposeTesting, Revision: 1, Credential: "cred-abc"}
	ctx := execbox.WithSession(context.Background(), sess)

	got := runProxyURL(ctx, "http://127.0.0.1:8788")
	if want := "http://cred-abc@127.0.0.1:8788"; got != want {
		t.Fatalf("runProxyURL = %q, want %q", got, want)
	}
	// A run with no session gets no proxy at all rather than the bare address.
	if got := runProxyURL(context.Background(), "http://127.0.0.1:8788"); got != "" {
		t.Fatalf("runProxyURL with no session = %q, want no proxy", got)
	}
}

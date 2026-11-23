package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// TestHostsForMapsAVhostToARecordedAddress pins that a name DNS does not know
// reaches the origin through the task-recorded address, judged as an address.
func TestHostsForMapsAVhostToARecordedAddress(t *testing.T) {
	var gotHost string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotHost = r.Host }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port := u.Port()

	hosts := func(_ netpolicy.Session, h string) []net.IP {
		if h == "vhost.test" {
			return []net.IP{net.ParseIP("127.0.0.1")}
		}
		return nil
	}
	do := func(t *testing.T, st netpolicy.State, host string) *http.Response {
		t.Helper()
		tr := newTestTransport(t, &testSource{st: st}, func(c *Config) { c.HostsFor = hosts })
		req := httptest.NewRequest(http.MethodGet, "https://"+host+":"+port+"/", nil)
		res, err := tr.RoundTrip(context.Background(), testConnContext(), req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { res.Body.Close() })
		return res
	}

	res := do(t, loopbackState(), "vhost.test")
	if res.StatusCode != http.StatusOK || gotHost != "vhost.test:"+port {
		t.Fatalf("mapped vhost: status %d host %q", res.StatusCode, gotHost)
	}

	if res := do(t, netpolicy.State{Revision: 1}, "vhost.test"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized address: status %d, want 403", res.StatusCode)
	}

	excl := loopbackState()
	excl.Rules = append(excl.Rules, netpolicy.Rule{ID: 9, Effect: "exclude", Pattern: "127.0.0.1/32", Protocol: "any", Authorized: true})
	if res := do(t, excl, "vhost.test"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("excluded address: status %d, want 403", res.StatusCode)
	}

	// No mapping: the name is judged pre-DNS, and an IP-only rule refuses it.
	if res := do(t, loopbackState(), "other.test"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("unmapped name: status %d, want 403", res.StatusCode)
	}
}

func TestMappedHostRequiresAddressGrant(t *testing.T) {
	srv := newMappedHTTPServer(t)
	authority := net.JoinHostPort("vhost.test", strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port))
	st := loopbackState()
	st.Rules = append(st.Rules, netpolicy.Rule{Effect: "include", Pattern: "vhost.test", Authorized: true})
	tr := newTestTransport(t, &testSource{st: st}, func(c *Config) {
		c.HostsFor = func(netpolicy.Session, string) []net.IP {
			return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}
		}
	})
	t.Cleanup(tr.CloseIdleConnections)

	t.Run("CONNECT", func(t *testing.T) {
		conn, err := tr.Dial(t.Context(), testConnContext(), connectRequest(t, authority))
		if conn != nil {
			conn.Close()
		}
		var oe *mproxy.OriginError
		if !errors.As(err, &oe) || oe.Status != http.StatusForbidden || oe.Stage != netpolicy.StageDNS {
			t.Fatalf("Dial error = %v, want an address policy refusal", err)
		}
	})
	t.Run("plain HTTP", func(t *testing.T) {
		res := mappedHTTP(t, tr, authority)
		if stage := res.Header.Get(HeaderStage); res.StatusCode != http.StatusForbidden || stage != netpolicy.StageDNS {
			t.Fatalf("status = %d, stage = %q, want 403/dns", res.StatusCode, stage)
		}
	})
}

func TestMappedPlainHTTPRechecksPolicy(t *testing.T) {
	allow := netpolicy.Rule{Effect: "include", Pattern: "127.0.0.1", Authorized: true}
	revoke := allow
	revoke.Authorized = false
	tests := []struct {
		name  string
		rules []netpolicy.Rule
	}{
		{"excluded", []netpolicy.Rule{allow, {Effect: "exclude", Pattern: "127.0.0.1"}}},
		{"revoked", []netpolicy.Rule{revoke, {Effect: "include", Pattern: "vhost.test", Authorized: true}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newMappedHTTPServer(t)
			authority := net.JoinHostPort("vhost.test", strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port))
			src := &testSource{st: netpolicy.State{Revision: 1, Rules: []netpolicy.Rule{allow}}}
			tr := newTestTransport(t, src, func(c *Config) {
				c.HostsFor = func(netpolicy.Session, string) []net.IP {
					return []net.IP{net.ParseIP("127.0.0.1")}
				}
			})
			t.Cleanup(tr.CloseIdleConnections)
			if res := mappedHTTP(t, tr, authority); res.StatusCode != http.StatusNoContent {
				t.Fatalf("first status = %d, want 204", res.StatusCode)
			}

			src.set(netpolicy.State{Revision: 2, Rules: tc.rules})
			res := mappedHTTP(t, tr, authority)
			if stage := res.Header.Get(HeaderStage); res.StatusCode != http.StatusForbidden || stage != netpolicy.StageDNS {
				t.Fatalf("second status = %d, stage = %q, want 403/dns", res.StatusCode, stage)
			}
			if n := len(tr.pool); n != 0 {
				t.Fatalf("%d pooled entries remain after refusal, want 0", n)
			}
		})
	}
}

func TestMappedPlainHTTPReplacesOutdatedPool(t *testing.T) {
	var opened atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(noContent))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	authority := net.JoinHostPort("vhost.test", strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port))
	src := &testSource{st: loopbackState()}
	recorded := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	tr := newTestTransport(t, src, func(c *Config) {
		c.HostsFor = func(netpolicy.Session, string) []net.IP { return recorded }
	})
	t.Cleanup(tr.CloseIdleConnections)
	if res := mappedHTTP(t, tr, authority); res.StatusCode != http.StatusNoContent {
		t.Fatalf("first status = %d, want 204", res.StatusCode)
	}

	recorded = recorded[:1]
	st := loopbackState()
	st.Rules[1].Authorized = false
	st.Revision++
	src.set(st)
	if res := mappedHTTP(t, tr, authority); res.StatusCode != http.StatusNoContent {
		t.Fatalf("second status = %d, want 204", res.StatusCode)
	}
	if n := opened.Load(); n != 2 {
		t.Fatalf("opened %d connections, want a new one for the changed mapping", n)
	}
}

func noContent(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func newMappedHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(noContent))
	t.Cleanup(srv.Close)
	return srv
}

func mappedHTTP(t *testing.T, tr *Transport, authority string) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+authority+"/", nil)
	res, err := tr.RoundTrip(t.Context(), testConnContext(), req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	res.Body.Close()
	return res
}

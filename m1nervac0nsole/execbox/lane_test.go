package execbox

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

func laneFixture() *DirectLane {
	return &DirectLane{
		Egress: "tun0",
		Deny:   []string{"10.98.0.0/16", "192.168.122.1"},
		Policy: netpolicy.State{Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "203.0.113.7", Protocol: "tcp", Ports: []int{80, 443}, Authorized: true},
			{ID: 2, Effect: "include", Pattern: "198.51.100.0/24", Protocol: "any", Authorized: true},
			{ID: 3, Effect: "exclude", Pattern: "198.51.100.128/25", Protocol: "any"},
			{ID: 4, Effect: "include", Pattern: "app.example.com", Protocol: "tcp", Ports: []int{8080}, Authorized: true},
			{ID: 5, Effect: "include", Pattern: "192.0.2.0/24", Protocol: "tcp", Authorized: false},
		}},
	}
}

const laneGolden = `*filter
:EB-F-h - [0:0]
-F EB-F-h
-A EB-F-h -s 10.98.1.2 -o tun0 -d 127.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A EB-F-h -i tun0 -d 10.98.1.2 -s 127.0.0.0/8 -j DROP
-A EB-F-h -s 10.98.1.2 -o tun0 -d 10.98.0.0/16 -j REJECT --reject-with icmp-admin-prohibited
-A EB-F-h -i tun0 -d 10.98.1.2 -s 10.98.0.0/16 -j DROP
-A EB-F-h -s 10.98.1.2 -o tun0 -d 192.168.122.1/32 -j REJECT --reject-with icmp-admin-prohibited
-A EB-F-h -i tun0 -d 10.98.1.2 -s 192.168.122.1/32 -j DROP
-A EB-F-h -s 10.98.1.2 -o tun0 -d 198.51.100.128/25 -j REJECT --reject-with icmp-admin-prohibited
-A EB-F-h -i tun0 -d 10.98.1.2 -s 198.51.100.128/25 -j DROP
-A EB-F-h -s 10.98.1.2 -o tun0 -d 203.0.113.7/32 -p tcp -m multiport --dports 80,443 -j ACCEPT
-A EB-F-h -i tun0 -d 10.98.1.2 -s 203.0.113.7/32 -p tcp -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A EB-F-h -i tun0 -d 10.98.1.2 -s 203.0.113.7/32 -p icmp -m conntrack --ctstate RELATED -j ACCEPT
-A EB-F-h -s 10.98.1.2 -o tun0 -d 198.51.100.0/24 -j ACCEPT
-A EB-F-h -i tun0 -d 10.98.1.2 -s 198.51.100.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A EB-F-h -s 10.98.1.2 -o tun0 -d 192.0.2.9/32 -p tcp -m multiport --dports 8080 -j ACCEPT
-A EB-F-h -i tun0 -d 10.98.1.2 -s 192.0.2.9/32 -p tcp -m multiport --sports 8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A EB-F-h -i tun0 -d 10.98.1.2 -s 192.0.2.9/32 -p icmp -m conntrack --ctstate RELATED -j ACCEPT
COMMIT
`

func TestCompileLaneGolden(t *testing.T) {
	l := laneFixture()
	dyn := []dynEntry{{Name: "app.example.com", Addr: netip.MustParseAddr("192.0.2.9"), Rule: l.Policy.Rules[3]}}
	got, err := compileLane("EB-F-h", "10.98.1.2", l, dyn)
	if err != nil {
		t.Fatal(err)
	}
	if got != laneGolden {
		t.Fatalf("compiled chain differs\n--- got\n%s--- want\n%s", got, laneGolden)
	}
	// Refusals precede every accept: an include never covers an exclusion.
	firstAccept, lastRefuse := -1, -1
	for i, line := range strings.Split(got, "\n") {
		if strings.HasSuffix(line, "ACCEPT") && firstAccept < 0 {
			firstAccept = i
		}
		if strings.HasSuffix(line, "DROP") || strings.Contains(line, "REJECT") {
			lastRefuse = i
		}
	}
	if lastRefuse > firstAccept {
		t.Fatalf("a refusal (line %d) comes after an accept (line %d)", lastRefuse, firstAccept)
	}
	// The unauthorized include and the hostname rule are never compiled to
	// addresses by themselves.
	if strings.Contains(got, "192.0.2.0/24") {
		t.Fatal("an unauthorized include was compiled")
	}
}

func TestCompileLaneRevocation(t *testing.T) {
	l := laneFixture()
	l.Policy.Rules = append(l.Policy.Rules[:0:0], l.Policy.Rules[1:]...) // rule 1 removed
	got, err := compileLane("EB-F-h", "10.98.1.2", l, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "203.0.113.7") {
		t.Fatalf("a revoked rule is still in the chain:\n%s", got)
	}
	if !strings.Contains(got, "198.51.100.0/24 -j ACCEPT") {
		t.Fatalf("the surviving rule is gone:\n%s", got)
	}
}

func TestCompileLaneNilIsEmptyChain(t *testing.T) {
	got, err := compileLane("EB-F-h", "10.98.1.2", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "*filter\n:EB-F-h - [0:0]\n-F EB-F-h\nCOMMIT\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCompileLaneRefusesMalformedInput(t *testing.T) {
	l := laneFixture()
	l.Deny = []string{"not-a-cidr"}
	if _, err := compileLane("EB-F-h", "10.98.1.2", l, nil); err == nil {
		t.Fatal("a malformed deny entry must be refused, not skipped")
	}
	l = laneFixture()
	l.Egress = "tun0; reboot"
	if _, err := compileLane("EB-F-h", "10.98.1.2", l, nil); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("an unsafe interface name must be refused, got %v", err)
	}
}

func TestCompileLaneSplitsLongPortLists(t *testing.T) {
	ports := make([]int, 20)
	for i := range ports {
		ports[i] = 1000 + i
	}
	l := &DirectLane{Egress: "tun0", Policy: netpolicy.State{Rules: []netpolicy.Rule{
		{ID: 1, Effect: "include", Pattern: "203.0.113.7", Protocol: "tcp", Ports: ports, Authorized: true},
	}}}
	got, _ := compileLane("EB-F-h", "10.98.1.2", l, nil)
	if n := strings.Count(got, "--dports"); n != 2 {
		t.Fatalf("want 2 multiport rules for 20 ports, got %d", n)
	}
}

func TestGrantedPorts(t *testing.T) {
	host := netpolicy.Rule{ID: 4, Effect: "include", Pattern: "*.example.com", Protocol: "tcp", Ports: []int{80, 443}, Authorized: true}
	st := netpolicy.State{Rules: []netpolicy.Rule{host}}
	ip := netip.MustParseAddr("192.0.2.9")

	if ports, ok := grantedPorts(st, host, "api.example.com", ip); !ok || len(ports) != 2 {
		t.Fatalf("plain answer: ports=%v ok=%v", ports, ok)
	}
	if _, ok := grantedPorts(st, host, "other.test", ip); ok {
		t.Fatal("a name the rule does not cover must not be granted")
	}
	// An exclusion for one port narrows the entry.
	st.Rules = append(st.Rules, netpolicy.Rule{ID: 9, Effect: "exclude", Pattern: "api.example.com", Protocol: "tcp", Ports: []int{443}})
	if ports, ok := grantedPorts(st, host, "api.example.com", ip); !ok || len(ports) != 1 || ports[0] != 80 {
		t.Fatalf("port exclusion: ports=%v ok=%v", ports, ok)
	}
	// An excluded answer address is never granted.
	st.Rules = []netpolicy.Rule{host, {ID: 10, Effect: "exclude", Pattern: "192.0.2.0/24", Protocol: "any"}}
	if _, ok := grantedPorts(st, host, "api.example.com", ip); ok {
		t.Fatal("an excluded answer was granted")
	}
	// Another include must not vouch for this rule's name.
	other := netpolicy.Rule{ID: 11, Effect: "include", Pattern: "x.other.test", Protocol: "tcp", Authorized: true}
	st = netpolicy.State{Rules: []netpolicy.Rule{other, host}}
	if _, ok := grantedPorts(st, host, "x.other.test", ip); ok {
		t.Fatal("a rule was granted on the strength of another rule")
	}
}

func TestHostnameExclusionsCannotWidenThroughTransportAlias(t *testing.T) {
	for _, ports := range [][]int{nil, {80, 443}} {
		r := netpolicy.Rule{ID: 1, Effect: "include", Pattern: "*.example.com", Protocol: "any", Ports: ports, Authorized: true}
		x := netpolicy.Rule{Effect: "exclude", Pattern: "api.example.com", Protocol: "http", Ports: []int{443}}
		got, ok := grantedPorts(netpolicy.State{Rules: []netpolicy.Rule{r, x}}, r, "api.example.com", netip.MustParseAddr("192.0.2.9"))
		if ports == nil {
			if ok {
				t.Fatal("a portless grant bypassed a hostname exclusion")
			}
		} else if !ok || len(got) != 1 || got[0] != 80 {
			t.Fatalf("ports = %v allowed = %v; want only 80", got, ok)
		}
	}
}

func TestApplyLaneSkipsUnchangedRules(t *testing.T) {
	// With no iptables-restore binary available, trying to apply the same
	// rules again would fail instead of updating the in-memory state.
	t.Setenv("PATH", t.TempDir())
	s := &session{handle: "test"}
	text, err := compileLane(laneChain(s.handle), s.sessIP, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	ls := &laneState{applied: text, jumped: true, timer: timer}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if err := s.applyLane(ls, nil, map[dynKey]dynEntry{}); err != nil {
		t.Fatal(err)
	}
	if ls.dyn == nil || ls.timer != nil {
		t.Fatal("unchanged rules did not update dynamic state and expiry")
	}
}

func TestObserveDNSRefreshesUnchangedGrant(t *testing.T) {
	const name = "app.lane.test"
	ip := netip.MustParseAddr("192.0.2.9")
	r := netpolicy.Rule{ID: 1, Effect: "include", Pattern: name, Protocol: "tcp", Ports: []int{80}, Authorized: true}
	k := dynKey{r.ID, ip, name}
	oldExpiry := time.Now().Add(10 * time.Minute)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	// The empty egress makes any attempt to replace kernel rules fail.
	ls := &laneState{
		cur:   &DirectLane{Policy: netpolicy.State{Rules: []netpolicy.Rule{r}}},
		dyn:   map[dynKey]dynEntry{k: {Name: name, Addr: ip, Rule: r, Expires: oldExpiry}},
		timer: timer,
	}
	s := &session{lane: ls, cfg: Config{Logf: t.Logf}}
	m := new(dns.Msg)
	m.SetQuestion(name+".", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   ip.AsSlice(),
	}}
	reply, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	s.observeDNS(reply)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.timer != nil {
		ls.timer.Stop()
	}
	if ls.closed {
		t.Fatal("TTL-only refresh tried to reapply the lane")
	}
	if !ls.dyn[k].Expires.After(oldExpiry) || ls.timer == nil || ls.timer == timer {
		t.Fatal("TTL-only refresh did not renew the grant and reschedule expiry")
	}
}

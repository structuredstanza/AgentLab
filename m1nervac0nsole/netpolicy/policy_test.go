package netpolicy

import (
	"net"
	"strings"
	"testing"
)

func addrs(values ...string) []net.IP {
	out := make([]net.IP, 0, len(values))
	for _, v := range values {
		out = append(out, net.ParseIP(v))
	}
	return out
}

func include(pattern string) Rule {
	return Rule{Effect: "include", Pattern: pattern, Protocol: "any", Authorized: true}
}

func exclude(pattern string) Rule {
	return Rule{Effect: "exclude", Pattern: pattern, Protocol: "any", Authorized: true}
}

// TestDecideTesting is the allow/deny matrix for the purposes judged by explicit
// grants: host, wildcard, CIDR, IPv4/IPv6, port, protocol, exclusion precedence,
// empty and unauthorized rules, and mixed DNS answers.
func TestDecideTesting(t *testing.T) {
	tests := []struct {
		name    string
		purpose Purpose
		state   State
		dest    Destination
		addrs   []net.IP
		allow   bool
		stage   string
		reason  string
	}{
		{
			name:  "hostname grant",
			state: State{Rules: []Rule{include("api.example.com")}},
			dest:  Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "hostname grant is case and trailing-dot insensitive",
			state: State{Rules: []Rule{include("api.example.com")}},
			dest:  Destination{Scheme: "https", Host: "API.Example.COM.", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "host:port in the destination is split",
			state: State{Rules: []Rule{include("api.example.com")}},
			dest:  Destination{Scheme: "https", Host: "api.example.com:8443", Port: 8443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "wildcard covers a subdomain",
			state: State{Rules: []Rule{include("*.example.com")}},
			dest:  Destination{Scheme: "https", Host: "a.example.com", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "wildcard covers the apex",
			state: State{Rules: []Rule{include("*.example.com")}},
			dest:  Destination{Scheme: "https", Host: "example.com", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:   "no rules denies",
			state:  State{},
			dest:   Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name:   "an unauthorized rule authorizes nothing",
			state:  State{Rules: []Rule{{Effect: "include", Pattern: "api.example.com", Protocol: "any"}}},
			dest:   Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name: "an unauthorized exclusion binds",
			state: State{Rules: []Rule{
				include("api.example.com"),
				{Effect: "exclude", Pattern: "api.example.com", Protocol: "any"},
			}},
			dest:   Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "excluded by api.example.com",
		},
		{
			name: "an unauthorized exclusion over a resolved address binds",
			state: State{Rules: []Rule{
				include("*.corp.example"),
				{Effect: "exclude", Pattern: "10.0.0.0/8", Protocol: "any"},
			}},
			dest:   Destination{Scheme: "https", Host: "api.corp.example", Port: 443, Protocol: "http"},
			addrs:  addrs("10.1.2.3"),
			stage:  StageDNS,
			reason: "excluded by 10.0.0.0/8",
		},
		{
			name:   "host outside the grant denies",
			state:  State{Rules: []Rule{include("api.example.com")}},
			dest:   Destination{Scheme: "https", Host: "other.example.com", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name:  "cidr grant covers a name that resolves inside it",
			state: State{Rules: []Rule{include("10.0.0.0/8")}},
			dest:  Destination{Scheme: "https", Host: "app.internal.example", Port: 443, Protocol: "http"},
			addrs: addrs("10.1.2.3"),
			allow: true, stage: StageDNS,
		},
		{
			name:   "cidr grant does not cover an unresolved name",
			state:  State{Rules: []Rule{include("10.0.0.0/8")}},
			dest:   Destination{Scheme: "https", Host: "app.internal.example", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name:   "cidr grant denies a name resolving outside it",
			state:  State{Rules: []Rule{include("10.0.0.0/8")}},
			dest:   Destination{Scheme: "https", Host: "app.internal.example", Port: 443, Protocol: "http"},
			addrs:  addrs("192.0.2.9"),
			stage:  StageDNS,
			reason: "not all authorized",
		},
		{
			name:   "mixed answers deny",
			state:  State{Rules: []Rule{include("10.0.0.0/8")}},
			dest:   Destination{Scheme: "https", Host: "app.internal.example", Port: 443, Protocol: "http"},
			addrs:  addrs("10.1.2.3", "192.0.2.9"),
			stage:  StageDNS,
			reason: "not all authorized",
		},
		{
			name:   "exclusion beats a broader include",
			state:  State{Rules: []Rule{include("10.0.0.0/8"), exclude("10.1.0.0/16")}},
			dest:   Destination{Scheme: "http", Host: "10.1.2.3", Port: 80, Protocol: "http"},
			stage:  StagePolicy,
			reason: "excluded by 10.1.0.0/16",
		},
		{
			name:   "exclusion over a resolved address beats a hostname grant",
			state:  State{Rules: []Rule{include("*.corp.example"), exclude("10.0.0.0/8")}},
			dest:   Destination{Scheme: "https", Host: "api.corp.example", Port: 443, Protocol: "http"},
			addrs:  addrs("10.1.2.3"),
			stage:  StageDNS,
			reason: "resolved address 10.1.2.3 is excluded by 10.0.0.0/8",
		},
		{
			name:  "hostname grant allows an address no rule names",
			state: State{Rules: []Rule{include("api.example.com")}},
			dest:  Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("192.0.2.9"),
			allow: true, stage: StagePolicy,
		},
		{
			name:  "port in the grant matches",
			state: State{Rules: []Rule{{Effect: "include", Pattern: "10.0.0.0/8", Protocol: "any", Ports: []int{443}, Authorized: true}}},
			dest:  Destination{Scheme: "https", Host: "10.0.0.1", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:   "port outside the grant denies",
			state:  State{Rules: []Rule{{Effect: "include", Pattern: "10.0.0.0/8", Protocol: "any", Ports: []int{443}, Authorized: true}}},
			dest:   Destination{Scheme: "http", Host: "10.0.0.1", Port: 80, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name: "an exclusion written for one port does not judge another",
			state: State{Rules: []Rule{
				{Effect: "include", Pattern: "10.0.0.0/8", Protocol: "any", Ports: []int{443}, Authorized: true},
				{Effect: "exclude", Pattern: "10.0.0.0/8", Protocol: "any", Ports: []int{80}, Authorized: true},
			}},
			dest:  Destination{Scheme: "https", Host: "10.0.0.1", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "protocol in the grant matches",
			state: State{Rules: []Rule{{Effect: "include", Pattern: "10.0.0.0/8", Protocol: "http", Authorized: true}}},
			dest:  Destination{Scheme: "https", Host: "10.0.0.1", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:   "protocol outside the grant denies",
			state:  State{Rules: []Rule{{Effect: "include", Pattern: "10.0.0.0/8", Protocol: "http", Authorized: true}}},
			dest:   Destination{Host: "10.0.0.1", Port: 22, Protocol: "tcp"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name:  "ipv6 cidr grant",
			state: State{Rules: []Rule{include("2001:db8::/32")}},
			dest:  Destination{Scheme: "https", Host: "[2001:db8::1]:443", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:   "ipv6 cidr grant does not cover ipv4",
			state:  State{Rules: []Rule{include("2001:db8::/32")}},
			dest:   Destination{Scheme: "https", Host: "192.0.2.1", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name:  "bare address grant",
			state: State{Rules: []Rule{include("10.0.0.1")}},
			dest:  Destination{Scheme: "https", Host: "10.0.0.1", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:   "bare address grant covers no neighbour",
			state:  State{Rules: []Rule{include("10.0.0.1")}},
			dest:   Destination{Scheme: "https", Host: "10.0.0.2", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no authorized rule",
		},
		{
			name:  "bare ipv6 address grant",
			state: State{Rules: []Rule{include("2001:db8::1")}},
			dest:  Destination{Scheme: "https", Host: "2001:db8::1", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:   "bare address exclusion",
			state:  State{Rules: []Rule{include("10.0.0.0/8"), exclude("10.0.0.1")}},
			dest:   Destination{Scheme: "https", Host: "10.0.0.1", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "excluded by 10.0.0.1",
		},
		{
			name:    "unknown purpose denies",
			purpose: Purpose("bogus"),
			state:   State{Rules: []Rule{include("api.example.com")}},
			dest:    Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			stage:   StagePolicy,
			reason:  "unknown purpose",
		},
		{
			name:   "empty host denies",
			state:  State{Rules: []Rule{include("api.example.com")}},
			dest:   Destination{Scheme: "https", Port: 443, Protocol: "http"},
			stage:  StagePolicy,
			reason: "no host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.purpose
			if p == "" {
				p = PurposeTesting
			}
			dec := Decide(p, tc.state, tc.dest, tc.addrs)
			if dec.Allow != tc.allow {
				t.Fatalf("allow=%v, want %v (stage %q reason %q)", dec.Allow, tc.allow, dec.Stage, dec.Reason)
			}
			if dec.Stage != tc.stage {
				t.Fatalf("stage=%q, want %q (reason %q)", dec.Stage, tc.stage, dec.Reason)
			}
			if tc.reason != "" && !strings.Contains(dec.Reason, tc.reason) {
				t.Fatalf("reason=%q, want it to contain %q", dec.Reason, tc.reason)
			}
		})
	}
}

// TestDecideResearch is the research boundary: public material is readable, and
// the host, its neighbours, cloud metadata and every live task target are not.
func TestDecideResearch(t *testing.T) {
	tests := []struct {
		name   string
		state  State
		dest   Destination
		addrs  []net.IP
		allow  bool
		stage  string
		reason string
	}{
		{
			name:  "public name",
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "public name with a public answer",
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("93.184.216.34"),
			allow: true, stage: StagePolicy,
		},
		{
			name: "localhost name", dest: Destination{Host: "localhost", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "local host localhost",
		},
		{
			name: "localhost subdomain", dest: Destination{Host: "app.localhost", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "local host",
		},
		{
			name: "metadata name", dest: Destination{Host: "metadata.google.internal", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "local host",
		},
		{
			name: "loopback literal", dest: Destination{Host: "127.0.0.1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "loopback address 127.0.0.1",
		},
		{
			name: "ipv6 loopback literal", dest: Destination{Host: "::1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "loopback address ::1",
		},
		{
			name: "ipv4-mapped loopback", dest: Destination{Host: "::ffff:127.0.0.1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "loopback address",
		},
		{
			name: "private literal", dest: Destination{Host: "10.0.0.5", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "private address 10.0.0.5",
		},
		{
			name: "link-local metadata", dest: Destination{Host: "169.254.169.254", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "link-local address",
		},
		{
			name: "carrier-grade NAT", dest: Destination{Host: "100.64.0.1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "carrier-grade NAT address",
		},
		{
			name: "multicast", dest: Destination{Host: "224.0.0.1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "multicast address",
		},
		{
			name: "this-network", dest: Destination{Host: "0.0.0.0", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "this-network address",
		},
		{
			name: "unique-local", dest: Destination{Host: "fd00::1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "unique-local address",
		},
		{
			name: "ipv6 link-local", dest: Destination{Host: "fe80::1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "link-local address",
		},
		{
			name:  "public name resolving to a private address",
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("10.0.0.5"), stage: StageDNS, reason: "private address 10.0.0.5",
		},
		{
			name:  "public name resolving to metadata",
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("169.254.169.254"), stage: StageDNS, reason: "link-local address",
		},
		{
			name:  "public name with a mixed answer set",
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("93.184.216.34", "127.0.0.1"), stage: StageDNS, reason: "loopback address",
		},
		{
			name:  "a task target host",
			state: State{Targets: []string{"api.target.example"}},
			dest:  Destination{Scheme: "https", Host: "api.target.example", Port: 443, Protocol: "http"},
			stage: StagePolicy, reason: "task target (api.target.example)",
		},
		{
			name:  "a task target wildcard",
			state: State{Targets: []string{"*.target.example"}},
			dest:  Destination{Scheme: "https", Host: "a.target.example", Port: 443, Protocol: "http"},
			stage: StagePolicy, reason: "task target (*.target.example)",
		},
		{
			name:  "an answer inside a task target network",
			state: State{Targets: []string{"203.0.113.0/24"}},
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("203.0.113.5"), stage: StageDNS, reason: "task target (203.0.113.0/24) at 203.0.113.5",
		},
		{
			name:  "an answer equal to a task target address",
			state: State{Targets: []string{"203.0.113.5"}},
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: addrs("203.0.113.5"), stage: StageDNS, reason: "task target (203.0.113.5) at 203.0.113.5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := Decide(PurposeResearch, tc.state, tc.dest, tc.addrs)
			if dec.Allow != tc.allow {
				t.Fatalf("allow=%v, want %v (stage %q reason %q)", dec.Allow, tc.allow, dec.Stage, dec.Reason)
			}
			if dec.Stage != tc.stage {
				t.Fatalf("stage=%q, want %q (reason %q)", dec.Stage, tc.stage, dec.Reason)
			}
			if tc.reason != "" && !strings.Contains(dec.Reason, tc.reason) {
				t.Fatalf("reason=%q, want it to contain %q", dec.Reason, tc.reason)
			}
		})
	}
}

// TestDecideInstall is the install boundary: an install session may download
// from the public web, and may not reach the host, its neighbours, cloud
// metadata or an engagement target. It is deliberately not judged by a task's
// rules, so an install cannot inherit an engagement's target grants.
func TestDecideInstall(t *testing.T) {
	tests := []struct {
		name   string
		state  State
		dest   Destination
		addrs  []net.IP
		allow  bool
		stage  string
		reason string
	}{
		{
			name:  "public download",
			dest:  Destination{Scheme: "https", Host: "github.com", Port: 443, Protocol: "http"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "public name with a public answer",
			dest:  Destination{Scheme: "https", Host: "github.com", Port: 443, Protocol: "http"},
			addrs: addrs("140.82.121.4"),
			allow: true, stage: StagePolicy,
		},
		{
			name: "loopback", dest: Destination{Scheme: "http", Host: "127.0.0.1", Port: 8788, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach loopback address 127.0.0.1",
		},
		{
			name: "localhost name", dest: Destination{Scheme: "http", Host: "localhost", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach local host localhost",
		},
		{
			name: "private address", dest: Destination{Scheme: "http", Host: "10.1.2.3", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach private address 10.1.2.3",
		},
		{
			name: "metadata address", dest: Destination{Scheme: "http", Host: "169.254.169.254", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach link-local address",
		},
		{
			name: "ipv6 link-local", dest: Destination{Scheme: "http", Host: "fe80::1", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach link-local address",
		},
		{
			name:  "public name resolving to a private address",
			dest:  Destination{Scheme: "https", Host: "github.com", Port: 443, Protocol: "http"},
			addrs: addrs("192.168.1.5"), stage: StageDNS, reason: "install cannot reach private address 192.168.1.5",
		},
		{
			name:  "mixed answer set",
			dest:  Destination{Scheme: "https", Host: "github.com", Port: 443, Protocol: "http"},
			addrs: addrs("140.82.121.4", "127.0.0.1"), stage: StageDNS, reason: "install cannot reach loopback address",
		},
		{
			name:  "an engagement target",
			state: State{Targets: []string{"api.target.example"}},
			dest:  Destination{Scheme: "https", Host: "api.target.example", Port: 443, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach a task target (api.target.example)",
		},
		{
			name:  "an answer inside an engagement target network",
			state: State{Targets: []string{"203.0.113.0/24"}},
			dest:  Destination{Scheme: "https", Host: "github.com", Port: 443, Protocol: "http"},
			addrs: addrs("203.0.113.9"), stage: StageDNS, reason: "install cannot reach a task target (203.0.113.0/24)",
		},
		{
			// The rules are the session task's own grants. An install must not be
			// judged by them, so a rule that would authorize a private host does
			// not widen an install.
			name: "a task grant does not authorize an install",
			state: State{
				Rules:   []Rule{include("10.0.0.0/8"), include("127.0.0.1")},
				Targets: []string{"10.0.0.0/8"},
			},
			dest:  Destination{Scheme: "http", Host: "10.0.0.7", Port: 80, Protocol: "http"},
			stage: StagePolicy, reason: "install cannot reach private address 10.0.0.7",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := Decide(PurposeInstall, tc.state, tc.dest, tc.addrs)
			if dec.Allow != tc.allow {
				t.Fatalf("allow=%v, want %v (stage %q reason %q)", dec.Allow, tc.allow, dec.Stage, dec.Reason)
			}
			if dec.Stage != tc.stage {
				t.Fatalf("stage=%q, want %q (reason %q)", dec.Stage, tc.stage, dec.Reason)
			}
			if tc.reason != "" && !strings.Contains(dec.Reason, tc.reason) {
				t.Fatalf("reason=%q, want it to contain %q", dec.Reason, tc.reason)
			}
		})
	}
}

func TestValidateRule(t *testing.T) {
	valid := []Rule{
		{Effect: "include", Pattern: "api.example.com"},
		{Effect: "exclude", Pattern: "*.example.com", Protocol: "any"},
		{Effect: "include", Pattern: "10.0.0.0/8", Protocol: "tcp", Ports: []int{22, 443}},
		{Effect: "include", Pattern: "2001:db8::/32", Protocol: "http"},
		{Effect: "include", Pattern: "10.0.0.1"},
	}
	for _, r := range valid {
		if err := ValidateRule(r); err != nil {
			t.Fatalf("ValidateRule(%+v) = %v, want nil", r, err)
		}
	}
	invalid := []Rule{
		{Effect: "allow", Pattern: "api.example.com"},
		{Effect: "include", Pattern: ""},
		{Effect: "include", Pattern: "*"},
		{Effect: "include", Pattern: "https://api.example.com/admin"},
		{Effect: "include", Pattern: "api.example.com", Protocol: "https"},
		{Effect: "include", Pattern: "api.example.com", Ports: []int{0}},
		{Effect: "include", Pattern: "api.example.com", Ports: []int{70000}},
	}
	for _, r := range invalid {
		if err := ValidateRule(r); err == nil {
			t.Fatalf("ValidateRule(%+v) = nil, want an error", r)
		}
	}
}

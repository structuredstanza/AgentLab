package netpolicy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

// Decide judges one destination against the state, with the addresses the
// caller resolved for it. It is pure: no clock, no resolver, no database.
//
// Before DNS the gateway calls Store.Authorize without addresses; after DNS
// it calls Store.AuthorizeResolved with every A/AAAA answer. The latter is
// mandatory even if the name itself was allowed. Task-recorded addresses are
// not DNS answers and are checked separately by Store.AuthorizeRecorded.
//
// Research and install share the public-destination rule and are never judged by
// a task's rules: an install is operator/curator-initiated, so it must not
// inherit an engagement's target grants. Testing is the only purpose a grant
// authorizes.
func Decide(p Purpose, st State, d Destination, addrs []net.IP) Decision {
	return decide(p, st, d, addrs, false)
}

func decide(p Purpose, st State, d Destination, addrs []net.IP, recorded bool) Decision {
	host := normalizeHost(d.Host)
	if host == "" {
		return refuse(StagePolicy, "destination has no host")
	}
	d.Host = host
	if recorded && p != PurposeTesting {
		return refuse(StagePolicy, "only testing sessions may use task-recorded addresses")
	}
	switch p {
	case PurposeResearch, PurposeInstall:
		if dec, denied := publicRefusal(p, st, host, addrs); denied {
			return dec
		}
		reason := "public destination"
		if len(addrs) == 0 && net.ParseIP(host) == nil {
			reason = "public destination; its resolved addresses must still pass the dns stage"
		}
		return allow(StagePolicy, reason)
	case PurposeTesting:
		return decideRules(st, d, addrs, recorded)
	default:
		return refuse(StagePolicy, fmt.Sprintf("unknown purpose %q", string(p)))
	}
}

// decideRules applies exclusions before deciding which includes can authorize.
func decideRules(st State, d Destination, addrs []net.IP, recorded bool) Decision {
	applicable := applicableRules(st.Rules, d)
	if len(applicable) == 0 {
		return refuse(StagePolicy, "no authorized rule covers "+describe(d))
	}

	hostVerdict := scope.Evaluate(scope.ParseAsset(d.Host), applicable)
	if hostVerdict.Status == scope.Out {
		return refuse(StagePolicy, hostVerdict.Reason)
	}
	hostIn := hostVerdict.Status == scope.In

	if len(addrs) == 0 {
		if recorded {
			return refuse(StageDNS, "no recorded address for "+d.Host)
		}
		if hostIn {
			return allow(StagePolicy, hostVerdict.Reason)
		}
		return refuse(StagePolicy, "no authorized rule covers "+describe(d))
	}

	kind := "resolved"
	if recorded {
		kind = "recorded"
	}
	allIn := true
	for _, ip := range addrs {
		addr := ip.String()
		v := scope.Evaluate(scope.ParseAsset(addr), applicable)
		if v.Status == scope.Out {
			return refuse(StageDNS, kind+" address "+addr+" is "+v.Reason)
		}
		if v.Status != scope.In {
			allIn = false
		}
	}
	// DNS answers may be covered by either a hostname grant or a grant for
	// every address. Task-recorded claims need their own address grants.
	// Exclusions override both.
	if hostIn && !recorded {
		return allow(StagePolicy, hostVerdict.Reason)
	}
	if allIn {
		return allow(StageDNS, "every "+kind+" address of "+d.Host+" is authorized")
	}
	return refuse(StageDNS, kind+" addresses of "+d.Host+" are not all authorized")
}

// applicableRules keeps the rules that were written for this protocol and port.
// A rule only judges destinations inside its own scope, so an exclusion written
// for one port never blocks another.
//
// An exclusion binds without approval: a restriction is never a grant, and an
// operator who wrote one must not have to approve their own refusal before the
// gateway honours it. An include grants only when authorized, so a written but
// unapproved grant authorizes nothing.
func applicableRules(rules []Rule, d Destination) []scope.Rule {
	out := make([]scope.Rule, 0, len(rules))
	for _, r := range rules {
		if !r.judges(d) {
			continue
		}
		if !r.Authorized && scope.Effect(r.Effect) != scope.Exclude {
			continue
		}
		out = append(out, scope.Rule{
			ID:      strconv.FormatInt(r.ID, 10),
			Effect:  scope.Effect(r.Effect),
			Pattern: RulePattern(r.Pattern),
			Note:    r.Note,
		})
	}
	return out
}

// RulePattern turns a bare address into the single-host network the scope
// matcher understands. A hostname or CIDR pattern is already in that form, and
// a bare address written as a hostname would never match an address.
func RulePattern(pattern string) string {
	p := strings.TrimSpace(pattern)
	if addr, err := netip.ParseAddr(p); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	return p
}

func (r Rule) judges(d Destination) bool {
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	if proto != "" && proto != "any" && !strings.EqualFold(proto, d.Protocol) {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == d.Port {
			return true
		}
	}
	return false
}

// publicRefusal reports the first reason a research or install session may not
// reach a destination: the host itself, its neighbours, or a destination another
// live task is authorized to test. The purpose only names the refusal, so a log
// line says which subsystem was stopped.
func publicRefusal(p Purpose, st State, host string, addrs []net.IP) (Decision, bool) {
	what := string(p)
	if protectedHost(host) {
		return refuse(StagePolicy, what+" cannot reach local host "+host), true
	}
	if ip := net.ParseIP(host); ip != nil {
		if kind, ok := protectedIP(ip); ok {
			return refuse(StagePolicy, what+" cannot reach "+kind+" address "+ip.String()), true
		}
	}
	for _, ip := range addrs {
		if kind, ok := protectedIP(ip); ok {
			return refuse(StageDNS, what+" cannot reach "+kind+" address "+ip.String()), true
		}
	}
	if pattern, ok := matchesTarget(st.Targets, host); ok {
		return refuse(StagePolicy, what+" cannot reach a task target ("+pattern+")"), true
	}
	for _, ip := range addrs {
		if pattern, ok := matchesTarget(st.Targets, ip.String()); ok {
			return refuse(StageDNS, what+" cannot reach a task target ("+pattern+") at "+ip.String()), true
		}
	}
	return Decision{}, false
}

// protectedHosts are names that resolve to the host itself, so a research
// session refuses them before any resolver is asked.
var protectedHosts = map[string]bool{
	"localhost":                true,
	"localhost.localdomain":    true,
	"ip6-localhost":            true,
	"ip6-loopback":             true,
	"metadata":                 true,
	"metadata.google.internal": true,
	"instance-data":            true,
}

func protectedHost(host string) bool {
	return protectedHosts[host] || strings.HasSuffix(host, ".localhost")
}

// protectedNets are the ranges research never reaches: the host, its neighbours
// and the cloud metadata endpoints, not the public web. The metadata addresses
// in use (169.254.169.254, 100.100.100.200, 192.0.0.192, fd00:ec2::254) are
// inside these.
var protectedNets = []struct {
	net  *net.IPNet
	what string
}{
	{mustCIDR("0.0.0.0/8"), "this-network"},
	{mustCIDR("10.0.0.0/8"), "private"},
	{mustCIDR("100.64.0.0/10"), "carrier-grade NAT"},
	{mustCIDR("127.0.0.0/8"), "loopback"},
	{mustCIDR("169.254.0.0/16"), "link-local"},
	{mustCIDR("172.16.0.0/12"), "private"},
	{mustCIDR("192.0.0.0/24"), "protocol-assignment"},
	{mustCIDR("192.168.0.0/16"), "private"},
	{mustCIDR("198.18.0.0/15"), "benchmarking"},
	{mustCIDR("224.0.0.0/4"), "multicast"},
	{mustCIDR("240.0.0.0/4"), "reserved"},
	{mustCIDR("::/128"), "unspecified"},
	{mustCIDR("::1/128"), "loopback"},
	{mustCIDR("fc00::/7"), "unique-local"},
	{mustCIDR("fe80::/10"), "link-local"},
	{mustCIDR("ff00::/8"), "multicast"},
}

func protectedIP(ip net.IP) (string, bool) {
	for _, p := range protectedNets {
		if p.net.Contains(ip) {
			return p.what, true
		}
	}
	return "", false
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("netpolicy: bad built-in CIDR " + s)
	}
	return n
}

// matchesTarget reports the first authorized target pattern that covers value.
func matchesTarget(patterns []string, value string) (string, bool) {
	asset := scope.ParseAsset(value)
	for _, p := range patterns {
		if scope.Evaluate(asset, []scope.Rule{{Effect: scope.Include, Pattern: RulePattern(p)}}).Status == scope.In {
			return p, true
		}
	}
	return "", false
}

// normalizeHost accepts what a caller has: a bare host, a host:port, a
// bracketed IPv6 literal, or a trailing dot.
func normalizeHost(raw string) string {
	h := strings.TrimSpace(strings.ToLower(raw))
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(h, ".")
}

func describe(d Destination) string {
	host := d.Host
	if d.Port > 0 {
		host = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	}
	if d.Protocol != "" {
		return d.Protocol + " " + host
	}
	return host
}

func refuse(stage, reason string) Decision { return Decision{Stage: stage, Reason: reason} }

func allow(stage, reason string) Decision { return Decision{Allow: true, Stage: stage, Reason: reason} }

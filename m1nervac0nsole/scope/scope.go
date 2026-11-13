// Package scope decides whether an asset is inside an engagement's boundary.
//
// The verdict is a decision, not advice. Before this package existed, the
// boundary was prose injected into the agent's prompt, which meant an agent
// that ignored a sentence could touch a host the program never authorized —
// and nothing would notice. Rules are rows, the verdict is computed, and the
// tool guard refuses a call whose target is out of scope.
//
// Three properties are deliberate and each has a test:
//
//   - an exclusion always wins, however specific the include that also matches;
//   - among includes the longest pattern wins, so the reason names the rule an
//     operator would have written;
//   - nothing matching is UNKNOWN, never OUT. A pasted scope table is routinely
//     incomplete, and "nobody said" is not "no".
package scope

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Effect is what a rule does to the assets it matches.
type Effect string

const (
	Include Effect = "include"
	Exclude Effect = "exclude"
)

// Status is the verdict for one asset.
type Status string

const (
	In      Status = "in"
	Out     Status = "out"
	Unknown Status = "unknown"
)

// Rule is one line of the boundary.
type Rule struct {
	ID      string `json:"id"`
	Effect  Effect `json:"effect"`
	Pattern string `json:"pattern"`
	Note    string `json:"note,omitempty"`
}

// Asset is what a rule is judged against.
type Asset struct {
	// Value is the canonical spelling: a lowercased host, a bare IP, a CIDR,
	// or a full URL.
	Value string
	// Host is the hostname an asset lives on: the host itself, or a URL's host.
	// Empty for an IP or CIDR.
	Host string
	// IsURL marks a value that carries a scheme and path.
	IsURL bool
}

// Verdict is the outcome, with the rule that decided it.
type Verdict struct {
	Status Status `json:"status"`
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason"`
}

var (
	cidrPattern = regexp.MustCompile(`^[0-9a-fA-F.:]+/\d+$`)
	schemePfx   = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)
)

// ParseAsset canonicalises a value into an Asset. The shape of the value
// decides the kind, not a caller's guess: tools and agents mislabel hosts
// constantly, and a rule cannot match a kind that is wrong.
func ParseAsset(value string) Asset {
	v := strings.TrimSpace(value)
	lower := strings.ToLower(v)
	if lower == "" {
		return Asset{}
	}
	if schemePfx.MatchString(lower) {
		host := lower
		if idx := strings.Index(host, "://"); idx >= 0 {
			host = host[idx+3:]
		}
		if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
			host = host[:idx]
		}
		if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx:], "]") {
			host = host[:idx]
		}
		return Asset{Value: lower, Host: host, IsURL: true}
	}
	if cidrPattern.MatchString(lower) {
		return Asset{Value: lower}
	}
	if net.ParseIP(lower) != nil {
		return Asset{Value: lower}
	}
	host := strings.TrimSuffix(lower, ".")
	return Asset{Value: host, Host: host}
}

// Evaluate judges an asset against the boundary.
func Evaluate(asset Asset, rules []Rule) Verdict {
	if len(rules) == 0 {
		return Verdict{Status: Unknown, Reason: "no scope rules defined yet"}
	}

	var included, excluded []Rule
	for _, r := range rules {
		if !matches(r, asset) {
			continue
		}
		if r.Effect == Exclude {
			excluded = append(excluded, r)
		} else {
			included = append(included, r)
		}
	}

	// An exclusion wins however narrow the include beside it: a host someone
	// deliberately ruled out must not be rescued by a more specific rule.
	if len(excluded) > 0 {
		r := longest(excluded)
		return Verdict{Status: Out, RuleID: r.ID, Reason: "excluded by " + describe(r)}
	}
	if len(included) > 0 {
		r := longest(included)
		return Verdict{Status: In, RuleID: r.ID, Reason: "in scope by " + describe(r)}
	}
	return Verdict{Status: Unknown, Reason: "no scope rule matches " + asset.Value}
}

func longest(rules []Rule) Rule {
	best := rules[0]
	for _, r := range rules[1:] {
		if len(r.Pattern) > len(best.Pattern) {
			best = r
		}
	}
	return best
}

func describe(r Rule) string {
	if r.Note != "" {
		return r.Pattern + " (" + r.Note + ")"
	}
	return r.Pattern
}

func matches(rule Rule, asset Asset) bool {
	pattern := strings.ToLower(strings.TrimSpace(rule.Pattern))
	if pattern == "" {
		return false
	}

	// A network rule judges an ip inside it, or a cidr wholly inside it.
	if cidrPattern.MatchString(pattern) {
		_, netBlock, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		if ip := net.ParseIP(asset.Value); ip != nil {
			return netBlock.Contains(ip)
		}
		if cidrPattern.MatchString(asset.Value) {
			_, assetBlock, err := net.ParseCIDR(asset.Value)
			if err != nil {
				return false
			}
			// A partly overlapping range is not in scope: the operator's rule
			// authorizes the whole of what they named, not a superset.
			first := assetBlock.IP
			last := lastAddress(assetBlock)
			return netBlock.Contains(first) && netBlock.Contains(last)
		}
		return false
	}

	// A pattern with a slash is a url or path glob, matched against a url.
	if strings.Contains(pattern, "/") {
		return asset.IsURL && globMatch(pattern, asset.Value)
	}

	// A hostname rule judges the host an asset lives on, so a url inherits its
	// host's verdict without a second rule.
	if asset.Host == "" {
		return false
	}
	return hostnameMatch(pattern, asset.Host)
}

// hostnameMatch treats `*.example.com` as covering the apex too, which is how a
// program's scope table reads even though DNS disagrees.
func hostnameMatch(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		apex := pattern[2:]
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
	return host == pattern
}

// globMatch is the glob a scope table implies: `*` spans path separators, so
// `*/admin/*` excludes the admin tree of every host rather than one segment of
// it. Anchored at both ends.
func globMatch(pattern, value string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func lastAddress(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	for i := range ip {
		ip[i] |= ^n.Mask[i]
	}
	return ip
}

// Problem explains why a pattern could never match an asset, or returns nil.
//
// A scope rule says WHERE you may test, not WHAT counts as a bug. A program's
// out-of-scope section is usually a mix of the two, and an agent reading it
// will cheerfully file "denial of service by flooding the service" as a rule —
// which can never match anything and leaves the engagement looking bounded
// when it is not. Policy belongs in the task notes; only assets belong here.
func Problem(pattern string) error {
	text := strings.TrimSpace(pattern)
	if text == "" {
		return fmt.Errorf("a scope rule needs a pattern")
	}
	if text == "*" || text == "*." {
		return fmt.Errorf("%q would match everything; name a host, a wildcard, a network or a url glob", text)
	}
	if strings.Contains(text, "/") {
		return nil
	}
	host := strings.TrimPrefix(text, "*.")
	if strings.Contains(host, ":") {
		return fmt.Errorf("%q is not an asset: a scope rule says where you may test, "+
			"not what counts as a bug. Policy belongs in the task notes", text)
	}
	if strings.ContainsAny(host, " \t") {
		return fmt.Errorf("%q contains whitespace and cannot be a host", text)
	}
	if cidrPattern.MatchString(text) || net.ParseIP(host) != nil {
		return nil
	}
	if !strings.Contains(host, ".") && host != "localhost" {
		return fmt.Errorf("%q is not a host, a wildcard, a network or a url glob", text)
	}
	return nil
}

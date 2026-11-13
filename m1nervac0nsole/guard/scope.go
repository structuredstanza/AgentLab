package guard

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"

	"github.com/structuredstanza/norma/hook"
)

// Asset extraction for scope enforcement.
//
// The guard cannot know a tool's semantics, so it reads the call's input as
// text and pulls out anything shaped like a host, an IP, a CIDR or a URL. That
// is deliberately blunt: a false positive costs one refused call with an
// explanation, and a false negative costs an out-of-scope scan. Only an
// explicit exclusion blocks, so a blunt extractor never blocks work that the
// boundary actually permits.

var (
	// A URL with a scheme: take the whole thing so a path rule can match. `]`
	// is allowed because a bracketed IPv6 host needs it; without it the match
	// stops mid-literal and the host is mangled.
	urlLike = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>,;)]+`)
	// An IPv4 address or CIDR.
	ipLike = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	// An IPv6 address or CIDR, optionally bracketed. A bare literal was
	// invisible to the IPv4-only pattern, so an excluded IPv6 range could be
	// reached by any call that named one.
	ip6Like = regexp.MustCompile(`\[?[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?\]?`)
	// A dotted hostname with at least one dot, allowing a leading wildcard-free
	// label. Anchored on word boundaries so a file path fragment is not read as
	// a host.
	hostLike = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
)

// assetsIn returns the candidate assets named by a tool call's input.
//
// The input is scanned twice: as raw JSON text and as decoded string leaves.
// Raw text alone is not enough, because the tool decodes the same bytes before
// executing them — `{"command":"curl http://\u0065vil.example/"}` reads as the
// host `\u0065vil.example` to a regex over the raw bytes but reaches
// `evil.example`, so an escaped character silently defeated the boundary.
func assetsIn(input json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		// Colons are NOT trimmed: they are part of an IPv6 literal, so trimming
		// them turned "::1" into "1" and "fe80::" into "fe80", neither of which
		// can ever match an exclusion.
		v = strings.ToLower(strings.TrimSpace(strings.Trim(v, `"'.,;()[]{}`)))
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	scan := func(text string) {
		if text == "" {
			return
		}
		// URLs first, and mask them out so their host is not also reported as a
		// bare hostname (which would let a path rule be bypassed by the host
		// rule).
		for _, u := range urlLike.FindAllString(text, -1) {
			add(u)
			// A boundary may exclude either the whole URL (a path rule) or its
			// host, so both are candidates; judging only the URL would let a
			// host exclusion be bypassed by naming any path on it.
			if host := hostOf(u); host != "" {
				add(host)
			}
			text = strings.ReplaceAll(text, u, " ")
		}
		for _, ip := range ipLike.FindAllString(text, -1) {
			if net.ParseIP(strings.SplitN(ip, "/", 2)[0]) != nil {
				add(ip)
			}
		}
		for _, ip := range ip6Like.FindAllString(text, -1) {
			// Split the prefix off before parsing: net.ParseIP rejects
			// "2001:db8::/32", so the CIDR form was dropped entirely and an
			// excluded IPv6 range was never enforced. The bare address is a
			// candidate too, so a /128 exclusion still matches its literal.
			host := strings.Trim(ip, "[]")
			if addr, _, found := strings.Cut(host, "/"); found {
				host = addr
			}
			if net.ParseIP(strings.Trim(host, "[]")) != nil {
				add(ip)
			}
		}
		for _, host := range hostLike.FindAllString(text, -1) {
			add(host)
		}
	}

	scan(string(input))
	// Lowercase the decoded leaves: hostLike is case-sensitive, so `API.corp.example`
	// matched only the `corp.example` fragment and a mixed-case name slipped past
	// an exact-host exclusion.
	for _, leaf := range decodedStrings(input) {
		scan(strings.ToLower(leaf))
	}
	return out
}

// decodedStrings returns every string value in a JSON document, decoded.
//
// A tool call's arguments are JSON; the tool unmarshals them and acts on the
// decoded values, so a boundary that inspects only the encoded bytes can be
// bypassed with an escape. Anything that is not valid JSON yields nothing here
// (the raw scan still applies).
func decodedStrings(input json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(node any) {
		switch t := node.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, item := range t {
				walk(item)
			}
		case map[string]any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(v)
	return out
}

// hostOf returns the host of a URL, lowercased and without a port.
func hostOf(raw string) string {
	rest := raw
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
		rest = rest[:idx]
	}
	// A bracketed IPv6 literal ends at the closing bracket; the colons inside
	// it are part of the address, not a port separator.
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end > 0 {
			return strings.ToLower(rest[1:end])
		}
	}
	if idx := strings.LastIndex(rest, ":"); idx > 0 && !strings.Contains(rest[idx:], "]") {
		rest = rest[:idx]
	}
	return strings.ToLower(rest)
}

// checkScope refuses a call that names an excluded asset.
func (g *Guard) checkScope(ev hook.Event) (bool, string) {
	for _, asset := range assetsIn(ev.Input) {
		if out, reason := g.scope.Judge(asset); out {
			return true, "out of scope: " + asset + " — " + reason
		}
	}
	return false, ""
}

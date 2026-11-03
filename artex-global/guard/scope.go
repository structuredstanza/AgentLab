package guard

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"

	"github.com/Autumn-27/norma/hook"
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
	// A URL with a scheme: take the whole thing so a path rule can match.
	urlLike = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>,;)\]]+`)
	// An IPv4 address or CIDR.
	ipLike = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	// A dotted hostname with at least one dot, allowing a leading wildcard-free
	// label. Anchored on word boundaries so a file path fragment is not read as
	// a host.
	hostLike = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
)

// assetsIn returns the candidate assets named by a tool call's input.
func assetsIn(input json.RawMessage) []string {
	text := string(input)
	if len(text) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(strings.Trim(v, `"'.,;:()[]{}`)))
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	// URLs first, and mask them out so their host is not also reported as a
	// bare hostname (which would let a path rule be bypassed by the host rule).
	for _, u := range urlLike.FindAllString(text, -1) {
		add(u)
		// A boundary may exclude either the whole URL (a path rule) or its
		// host, so both are candidates; judging only the URL would let a host
		// exclusion be bypassed by naming any path on it.
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
	for _, host := range hostLike.FindAllString(text, -1) {
		add(host)
	}
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

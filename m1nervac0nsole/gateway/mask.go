package gateway

import (
	"net/http"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
)

// MaskLevel is how much of a request's header identity the gateway rewrites
// before it reaches the origin. The TLS fingerprint is Chrome at every level.
type MaskLevel string

const (
	// MaskNone forwards the headers exactly as the client sent them.
	MaskNone MaskLevel = "none"
	// MaskUA replaces a tool-default User-Agent and nothing else, so recorded
	// traffic never announces curl or Go.
	MaskUA MaskLevel = "ua"
	// MaskNavigation also fills the headers a Chrome page load carries.
	MaskNavigation MaskLevel = "navigation"
)

// Client hints matching useragent.Default (Chrome 131 on Windows).
const (
	secChUA         = `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
	secChUAMobile   = "?0"
	secChUAPlatform = `"Windows"`

	navAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)

// applyMask rewrites req.Header in place for level; it must run before the
// hop-by-hop headers are stripped so an upgrade is still visible here.
//
// Header order is not preserved: Go's encoder sorts a header map and the
// origin clients here write it that way, so only the set of headers is made
// browser-shaped, not their sequence.
func applyMask(level MaskLevel, req *http.Request) {
	if level == MaskNone {
		return
	}
	h := req.Header
	if useragent.IsToolDefault(h.Get("User-Agent")) {
		h.Set("User-Agent", useragent.Get())
		// The hints describe the built-in Chrome; with an overridden UA they
		// would contradict it, which is a worse fingerprint than none.
		if useragent.Get() == useragent.Default {
			setIfAbsent(h, "Sec-Ch-Ua", secChUA)
			setIfAbsent(h, "Sec-Ch-Ua-Mobile", secChUAMobile)
			setIfAbsent(h, "Sec-Ch-Ua-Platform", secChUAPlatform)
		}
	}
	if level != MaskNavigation || !isPlainNavigation(req) {
		return
	}
	// A tool's wildcard Accept is its default, not a choice: replace it.
	if a := h.Get("Accept"); a == "" || a == "*/*" {
		h.Set("Accept", navAccept)
	}
	setIfAbsent(h, "Upgrade-Insecure-Requests", "1")
	setIfAbsent(h, "Sec-Fetch-Site", "none")
	setIfAbsent(h, "Sec-Fetch-Mode", "navigate")
	setIfAbsent(h, "Sec-Fetch-User", "?1")
	setIfAbsent(h, "Sec-Fetch-Dest", "document")
	// Accept-Encoding is left as sent: a client that did not ask for
	// compression cannot decode br/zstd, and the recorder would store it.
	setIfAbsent(h, "Accept-Language", "en-US,en;q=0.9")
}

// isPlainNavigation is a body-less GET or HEAD that is not an upgrade and whose
// Accept is absent or the tool default.
func isPlainNavigation(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	if req.ContentLength != 0 || (req.Body != nil && req.Body != http.NoBody) {
		return false
	}
	if req.Header.Get("Upgrade") != "" {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return false
			}
		}
	}
	return true
}

func setIfAbsent(h http.Header, k, v string) {
	if h.Get(k) == "" {
		h.Set(k, v)
	}
}

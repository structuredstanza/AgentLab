package egress

import (
	"os"
	"path/filepath"
	"strings"
)

// Identity is the one browser the engagement presents.
//
// It is chosen once per engagement and held for every request. Rotating it, or
// randomising it per template the way a scanning tool does, is itself the
// anomaly: a real visitor uses one browser for the whole session.
type Identity struct {
	UserAgent      string
	SecChUA        string
	Platform       string
	Mobile         string
	AcceptLanguage string
}

// chromeWindows is the profile this build pins. A desktop Chrome on Windows is
// the least remarkable thing to look like on a network that also carries
// ordinary user traffic.
var chromeWindows = Identity{
	UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	SecChUA:        `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
	Platform:       `"Windows"`,
	Mobile:         "?0",
	AcceptLanguage: "en-US,en;q=0.9",
}

// LoadIdentity reads the engagement's identity from dir, writing the default on
// first use so an operator can edit it before a run and see exactly what will
// be sent.
func LoadIdentity(dir string) (Identity, error) {
	path := filepath.Join(dir, "user-agent.txt")
	if raw, err := os.ReadFile(path); err == nil {
		if ua := strings.TrimSpace(string(raw)); ua != "" {
			id := chromeWindows
			id.UserAgent = ua
			return id, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Identity{}, err
	}
	if err := os.WriteFile(path, []byte(chromeWindows.UserAgent+"\n"), 0o644); err != nil {
		return Identity{}, err
	}
	return chromeWindows, nil
}

// hopByHop are the headers a proxy must not forward, per RFC 7230.
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// forwarded are the headers the caller controls, carried through untouched.
// Everything not listed here is dropped and replaced by the identity's own set,
// so a tool cannot leak a header the browser would never send.
var forwarded = map[string]bool{
	"content-type":      true,
	"content-length":    true,
	"cookie":            true,
	"authorization":     true,
	"referer":           true,
	"origin":            true,
	"if-none-match":     true,
	"if-modified-since": true,
	"range":             true,
	"x-requested-with":  true,
}

// canonicalHeaders builds the exact header set and order a Chrome navigation
// sends, keeping the caller's body and auth headers.
//
// Order is written out rather than sorted, because Go's encoder sorts and a
// sorted set is not what a browser emits.
func canonicalHeaders(id Identity, method, host, target string, in [][2]string) [][2]string {
	out := make([][2]string, 0, 16)
	out = append(out, [2]string{"Host", host})
	out = append(out, [2]string{"Connection", "keep-alive"})

	// Caller headers that a browser would also send, in the caller's order.
	for _, kv := range in {
		key := strings.ToLower(kv[0])
		if hopByHop[key] || key == "host" || key == "user-agent" {
			continue
		}
		if forwarded[key] {
			out = append(out, kv)
		}
	}

	out = append(out, [2]string{"sec-ch-ua", id.SecChUA})
	out = append(out, [2]string{"sec-ch-ua-mobile", id.Mobile})
	out = append(out, [2]string{"sec-ch-ua-platform", id.Platform})
	out = append(out, [2]string{"Upgrade-Insecure-Requests", "1"})
	out = append(out, [2]string{"User-Agent", id.UserAgent})
	out = append(out, [2]string{"Accept", acceptFor(method, in)})
	out = append(out, [2]string{"Sec-Fetch-Site", "none"})
	out = append(out, [2]string{"Sec-Fetch-Mode", "navigate"})
	out = append(out, [2]string{"Sec-Fetch-User", "?1"})
	out = append(out, [2]string{"Sec-Fetch-Dest", "document"})
	out = append(out, [2]string{"Accept-Encoding", "gzip, deflate, br"})
	out = append(out, [2]string{"Accept-Language", id.AcceptLanguage})
	return out
}

// acceptFor picks the Accept value matching what the request actually is.
func acceptFor(method string, in [][2]string) string {
	for _, kv := range in {
		if strings.EqualFold(kv[0], "content-type") {
			// A request with a body is a form post or an API call, not a page
			// load, so it must not claim to be navigating to a document.
			return "application/json, text/plain, */*"
		}
	}
	if method == "GET" || method == "HEAD" {
		return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}
	return "application/json, text/plain, */*"
}

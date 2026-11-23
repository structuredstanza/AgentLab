// Package useragent is the one place the outbound identity is decided.
//
// Every request the backend makes on its own behalf — enrichment probes, MCP
// handshakes, notifications, custom tools — otherwise carries the language's
// default, Go-http-client/1.1, or a product name. Both name this stack to
// whoever receives them. The engagement's identity is read once from the
// environment the guest supervisor set, so a single value governs the whole VM.
package useragent

import (
	"os"
	"strings"
	"sync"
)

// Default is a current desktop Chrome. It is used when no engagement identity is
// configured, so an unconfigured build still does not announce itself as Go.
const Default = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

var (
	mu     sync.RWMutex
	value  string
	loaded bool
)

// Get returns the identity every outbound request should present.
func Get() string {
	mu.RLock()
	if loaded {
		v := value
		mu.RUnlock()
		return v
	}
	mu.RUnlock()
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		value = strings.TrimSpace(os.Getenv("M1NERVAC0NSOLE_USER_AGENT"))
		if value == "" {
			value = Default
		}
		loaded = true
	}
	return value
}

// Set overrides the identity, for a caller that already resolved it.
//
// Guarded by the same lock as Get: a plain sync.Once let Set write the value
// while another goroutine read it, and marking the Once done without reading
// the environment let a concurrent first Get return an empty identity.
func Set(ua string) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return
	}
	mu.Lock()
	value = ua
	loaded = true
	mu.Unlock()
}

// SetIfAbsent sets the header only when the caller has not chosen one.
func SetIfAbsent(set func(string, string), existing string) {
	if existing == "" {
		set("User-Agent", Get())
	}
}

// toolDefaults are lowercase markers of the User-Agent strings scanners,
// clients and libraries send when nobody chose one. Substrings, not prefixes:
// Nikto and PowerShell hide the name inside a Mozilla-shaped string.
var toolDefaults = []string{
	"curl/", "go-http-client/", "python-requests/", "python-urllib/", "python-httpx/",
	"aiohttp/", "wget/", "fuzz faster u fool", "gobuster/", "nuclei", "sqlmap",
	"wfuzz", "nikto", "feroxbuster/", "dirb/", "whatweb/", "java/", "okhttp/",
	"node-fetch", "axios/", "powershell", "libwww-perl/",
}

// IsToolDefault reports whether ua is a tool's own default identity. An empty
// UA counts: a request that names nothing would otherwise reach the origin with
// whatever the transport adds.
func IsToolDefault(ua string) bool {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return true
	}
	for _, m := range toolDefaults {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}

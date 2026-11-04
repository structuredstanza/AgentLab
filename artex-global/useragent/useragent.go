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
	once  sync.Once
	value string
)

// Get returns the identity every outbound request should present.
func Get() string {
	once.Do(func() {
		value = strings.TrimSpace(os.Getenv("ARTEX_USER_AGENT"))
		if value == "" {
			value = Default
		}
	})
	return value
}

// Set overrides the identity, for a caller that already resolved it.
func Set(ua string) {
	if ua = strings.TrimSpace(ua); ua != "" {
		once.Do(func() {})
		value = ua
	}
}

// SetIfAbsent sets the header only when the caller has not chosen one.
func SetIfAbsent(set func(string, string), existing string) {
	if existing == "" {
		set("User-Agent", Get())
	}
}

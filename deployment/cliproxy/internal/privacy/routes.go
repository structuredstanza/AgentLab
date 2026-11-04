package privacy

import (
	"net"
	"net/http"
	"strings"

	"github.com/artex/cliproxyhost/internal/contract"
)

// kind separates auth/control routes (inspected but never captured) from
// inference routes (inspected, captured, replay-admitted).
type kind uint8

const (
	kindAuth kind = iota + 1
	kindInference
)

type route struct {
	provider contract.Provider
	kind     kind
}

type routeKey struct {
	host, method, path string
}

// allowedRoutes is the source-pinned host/method/path allowlist. Browser-only
// authorization URLs are validated separately; no management proxy is exposed.
var allowedRoutes = buildRoutes()

func buildRoutes() map[routeKey]route {
	m := make(map[routeKey]route)
	add := func(p contract.Provider, host, method, path string, k kind) {
		m[routeKey{host: host, method: method, path: path}] = route{provider: p, kind: k}
	}

	add(contract.ProviderClaude, "platform.claude.com", http.MethodPost, "/v1/oauth/token", kindAuth)
	add(contract.ProviderClaude, "api.anthropic.com", http.MethodGet, "/api/oauth/profile", kindAuth)
	add(contract.ProviderClaude, "api.anthropic.com", http.MethodGet, "/api/oauth/claude_cli/roles", kindAuth)
	add(contract.ProviderClaude, "api.anthropic.com", http.MethodGet, "/api/oauth/usage", kindAuth)
	add(contract.ProviderClaude, "api.anthropic.com", http.MethodPost, "/v1/messages", kindInference)
	add(contract.ProviderClaude, "api.anthropic.com", http.MethodPost, "/v1/messages/count_tokens", kindInference)

	add(contract.ProviderCodex, "auth.openai.com", http.MethodPost, "/oauth/token", kindAuth)
	add(contract.ProviderCodex, "auth.openai.com", http.MethodPost, "/api/accounts/oauth/token", kindAuth)
	add(contract.ProviderCodex, "chatgpt.com", http.MethodGet, "/backend-api/wham/usage", kindAuth)
	add(contract.ProviderCodex, "chatgpt.com", http.MethodPost, "/backend-api/codex/responses", kindInference)
	add(contract.ProviderCodex, "chatgpt.com", http.MethodPost, "/backend-api/codex/responses/compact", kindInference)

	for _, host := range []string{
		"daily-cloudcode-pa.googleapis.com",
		"daily-cloudcode-pa.sandbox.googleapis.com",
		"cloudcode-pa.googleapis.com",
	} {
		add(contract.ProviderAntigravity, host, http.MethodPost, "/v1internal:loadCodeAssist", kindAuth)
		add(contract.ProviderAntigravity, host, http.MethodPost, "/v1internal:fetchAvailableModels", kindAuth)
		add(contract.ProviderAntigravity, host, http.MethodPost, "/v1internal:retrieveUserQuotaSummary", kindAuth)
		add(contract.ProviderAntigravity, host, http.MethodPost, "/v1internal:streamGenerateContent", kindInference)
		add(contract.ProviderAntigravity, host, http.MethodPost, "/v1internal:generateContent", kindInference)
		add(contract.ProviderAntigravity, host, http.MethodPost, "/v1internal:countTokens", kindInference)
	}
	add(contract.ProviderAntigravity, "daily-cloudcode-pa.googleapis.com", http.MethodPost, "/v1internal:onboardUser", kindAuth)
	add(contract.ProviderAntigravity, "oauth2.googleapis.com", http.MethodPost, "/token", kindAuth)
	add(contract.ProviderAntigravity, "www.googleapis.com", http.MethodGet, "/oauth2/v2/userinfo", kindAuth)
	return m
}

// localInferencePaths are the only paths an operator-hosted endpoint may be called on.
var localInferencePaths = map[string]bool{"/v1/chat/completions": true}

// lookupRoute admits only https requests whose host has no port and whose method and
// escaped path match an allowlist entry exactly. Plaintext is admitted solely for a
// loopback-hosted local model, by lookupLoopbackRoute.
func lookupRoute(req *http.Request) (route, bool) {
	if req.URL == nil || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return route{}, false
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if req.URL.Scheme != "https" {
		return lookupLoopbackRoute(req, method)
	}
	rt, ok := allowedRoutes[routeKey{host: strings.ToLower(req.URL.Host), method: method, path: req.URL.EscapedPath()}]
	return rt, ok
}

// lookupLoopbackRoute admits the operator-hosted model endpoint. It is the one upstream
// that is neither a pinned public provider nor reachable over TLS: the endpoint is
// configured locally and called over plaintext loopback, which never leaves the machine,
// so the disguise rationale behind the https-only rule does not apply to it. The
// admission is kept deliberately narrow — loopback host with an explicit port, POST, the
// single completion path, and only for the local provider — so it cannot be reused as a
// general plaintext escape hatch.
func lookupLoopbackRoute(req *http.Request, method string) (route, bool) {
	if req.URL.Scheme != "http" || method != http.MethodPost {
		return route{}, false
	}
	if !localInferencePaths[req.URL.EscapedPath()] || !isLoopbackHost(req.URL.Host) {
		return route{}, false
	}
	return route{provider: contract.ProviderLocal, kind: kindInference}, true
}

// isLoopbackHost accepts a loopback address only when a port is spelled out, so the
// admission is always to one explicit endpoint rather than to a whole host.
func isLoopbackHost(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

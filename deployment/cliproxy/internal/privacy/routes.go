package privacy

import (
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

// lookupRoute admits only https requests whose host has no port and whose
// method and escaped path match an allowlist entry exactly.
func lookupRoute(req *http.Request) (route, bool) {
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return route{}, false
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	rt, ok := allowedRoutes[routeKey{host: strings.ToLower(req.URL.Host), method: method, path: req.URL.EscapedPath()}]
	return rt, ok
}

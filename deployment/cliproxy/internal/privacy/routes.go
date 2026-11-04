package privacy

import (
	"net/http"
	"strings"
	"sync/atomic"

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

// customInferencePaths are the only paths the configured endpoint may be called on.
var customInferencePaths = map[string]bool{"/v1/chat/completions": true}

// lookupRoute admits a request by one of two rules: an https request matching a pinned
// provider entry exactly, or a request to the operator-configured origin. The custom
// origin is checked for both schemes, because an operator may host the endpoint
// themselves over plaintext or point at a remote service over TLS.
func lookupRoute(req *http.Request) (route, bool) {
	if req.URL == nil || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return route{}, false
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if req.URL.Scheme == "https" {
		if rt, ok := allowedRoutes[routeKey{host: strings.ToLower(req.URL.Host), method: method, path: req.URL.EscapedPath()}]; ok {
			return rt, true
		}
	}
	return lookupCustomRoute(req, method)
}

// customOrigin is the host:port the operator configured for the custom provider. It is
// set once at startup from the same configuration that carries the endpoint, so the
// allowlist and the credential can never disagree about where traffic goes.
var customOrigin atomic.Value // string

// SetCustomOrigin pins the single origin the custom provider may reach.
func SetCustomOrigin(origin string) { customOrigin.Store(strings.ToLower(origin)) }

// lookupCustomRoute admits the operator-configured model endpoint. It is the one
// upstream that is not a pinned public provider: the operator chooses it, so the
// allowlist cannot name it in advance. Admission is to that one origin, on the single
// completion path, for POST only — the endpoint cannot be used to reach anything else,
// and an unset origin admits nothing.
//
// Plaintext is allowed here because the endpoint may be a model server the operator
// runs locally, which has no certificate. It is not an escape hatch: the host and port
// must match the configured origin exactly.
func lookupCustomRoute(req *http.Request, method string) (route, bool) {
	if method != http.MethodPost {
		return route{}, false
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return route{}, false
	}
	want, _ := customOrigin.Load().(string)
	if want == "" || !strings.EqualFold(req.URL.Host, want) {
		return route{}, false
	}
	if !customInferencePaths[req.URL.EscapedPath()] {
		return route{}, false
	}
	return route{provider: contract.ProviderCustom, kind: kindInference}, true
}

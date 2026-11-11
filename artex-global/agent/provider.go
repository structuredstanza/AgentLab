// Package agent wires real LLM-driven planner and work agents (on top of the
// agent-core SDK) to the dual SQLite graph. See docs/ARTEX-\u67b6\u6784\u8bbe\u8ba1.md
// §4.3 (planner) and §4.4 (work agent).
//
// Provider configuration is read from the environment so the system runs with
// any Anthropic- or OpenAI-format endpoint. If no key is configured, FromEnv
// returns ok=false and the exploration engine stays idle (an LLM is required).
package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/artex-global/llmrec"
	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
	"github.com/structuredstanza/norma/agentcore"
	"github.com/structuredstanza/norma/compaction"
	"github.com/structuredstanza/norma/llm"
	acperm "github.com/structuredstanza/norma/permission"
	"github.com/structuredstanza/norma/transcript"
)

const FormatAntigravity llm.Format = "antigravity"

const FormatOllama llm.Format = "ollama"

const DefaultOllamaBaseURL = "http://127.0.0.1:11434/v1"

const ollamaPlaceholderKey = "ollama"

// Config describes the LLM backend resolved from the environment.
type Config struct {
	Format  llm.Format
	BaseURL string
	APIKey  string
	// AuthMethod selects API-key or native proxy subscription credentials.
	AuthMethod string
	Model      string
	// Proxy routes all LLM requests through the given proxy URL (http/https/socks5,
	// optionally with user:pass@ credentials). Empty means direct — it does NOT
	// fall back to the standard *_PROXY environment variables.
	Proxy string
	// RatePerSecond / RatePerMinute cap the shared request rate across ALL agents
	// using the provider (0 = that window unlimited).
	RatePerSecond float64
	RatePerMinute float64
	// ContextWindowK is the model's context window in K tokens (user-configured),
	// used to size compaction thresholds. 0 = default; see CompactionWindow.
	ContextWindowK int
	// ThinkingType independently controls the thinking on/off field (thinking.type):
	//   "" = not sent (default, compatible with models that do not support this field); "disabled" = explicitly off;
	//   "enabled" = on; "adaptive" = adaptive (the model decides how much to think).
	//   Fully decoupled from ReasoningEffort——some interfaces have no thinking field,
	//   Thinking can be activated by the strength parameter alone, so the two may each be set independently.
	ThinkingType string
	// ReasoningEffort independently controls the thinking "strength" field:
	//   "" = not sent (default); "low"/"medium"/"high"/"xhigh"/"max" = the corresponding strength.
	//   OpenAI maps it to the top-level reasoning_effort; Anthropic maps it to output_config.effort.
	ReasoningEffort string
	// Stream controls whether this profile uses the streaming (SSE) interface. true (default) = streaming; false = true
	// non-streaming (sends stream:false, receives the complete JSON in one response, and goes through Provider.Complete). Non-streaming can bypass
	// some gateways' poor SSE implementations (empty frames, dropped thinking fields), at the cost of losing live in-progress progress and live
	// Token counting. Maps to agentcore.Options.NonStreaming = !Stream.
	Stream bool
	// MaxTokens is the output limit (in tokens) for a single reply. 0 = do not send this field; the server-side default applies
	// (historical behavior). Unlike ContextWindowK, which is the model's total capacity and is only used locally to compute the compression threshold,
	// Not sent in the request; this value is sent with each request. Maps to agentcore.Options.MaxTokens.
	MaxTokens int
	// MaxTokensField selects which request field name MaxTokens is sent under. It only takes effect for format=openai:
	//   "" = max_tokens (default); "max_completion_tokens" = the newer field.
	// OpenAI reasoning models (o-series/GPT-5) only accept the latter; if they receive max_tokens, they will directly report
	// unsupported_parameter; most compatible gateways accept only the former, so no automatic inference is done and the user chooses according to the endpoint.
	MaxTokensField string
	// SessionHeaderKey, when non-empty, causes every LLM request to carry a custom HTTP header whose name is this value,
	// The header value is the **current session id** (chat session=conv-<id>, worker=exp<x>-worker-i<intent>
	// etc., see WorkerSessionID). Used by certain gateways that do prompt caching or sticky routing keyed on the session-id header.
	// Empty = do not send. The value is attached to the request context by transcript.WithSessionID, and is read by the RoundTripper
	// to fill in the header, so the same shared provider can send different header values for different sessions.
	SessionHeaderKey string
	// Retry is the resolved retry parameters for this configuration (profile override → global policy → built-in defaults, resolved
	// on the server side). For the meaning of the three layers, see RetryConfig; zero value = fully fall back to the built-in defaults.
	Retry RetryConfig
}

// RetryConfig holds the retry parameters that travel with an LLM configuration. The "count" semantics are uniform across each layer:
// 0 = use the built-in default count; negative = disable retries for this layer; >0 = use that value. The "interval" for each layer:
// 0 = use the original exponential backoff of that layer; >0 = use this fixed interval instead.
type RetryConfig struct {
	// ConnectAttempts/ConnectInterval: SDK connection retry (connection reset/timeout/429/5xx, before stream start),
	// Maps directly to llm.Config.MaxRetries / RetryInterval. Defaults to 3 retries, with exponential backoff starting at 0.5s (capped at 8s).
	ConnectAttempts int
	ConnectInterval time.Duration
	// EmptyAttempts/EmptyInterval: SDK empty-response retries (completed but no content block, openai format only),
	// format), mapped to llm.Config.EmptyResponseRetries / EmptyResponseInterval.
	// Default 2 attempts, on the same exponential schedule.
	EmptyAttempts int
	EmptyInterval time.Duration
	// StreamAttempts/StreamInterval: retries within a safety window for the same provider — added on top of the SDK by this project
	// and it only replays dropped streams/overload/in-stream 429s while "no output has been delivered to the caller yet". The SDK cannot see it,
	// Consumed by server/task_llm.go. Defaults to 2 retries, with exponential backoff starting at 0.5s (capped at 4s).
	StreamAttempts int
	StreamInterval time.Duration
}

// compaction window resolution bounds (in K tokens). Below the floor the
// threshold math (window − summary reserve − buffer) would go non-positive and
// compaction would fire every turn; above the cap it would never fire.
const (
	defaultWindowK = 200  // unset → assume a 200K window (Claude default)
	minWindowK     = 32   // floor so effectiveWindow stays comfortably positive
	maxWindowK     = 1000 // cap at 1M tokens (user request)
)

// NeedsAPIKey reports whether this provider format requires an API key.
func (c Config) NeedsAPIKey() bool { return c.Format != FormatOllama }

// CompactionWindow returns the model context window in TOKENS for compaction
// thresholds, resolved from the user-configured size (ContextWindowK). 0/unset →
// a 200K default; otherwise clamped to [32K, 1M] so compaction stays effective.
func (c Config) CompactionWindow() int {
	k := c.ContextWindowK
	if k <= 0 {
		k = defaultWindowK
	}
	if k < minWindowK {
		k = minWindowK
	}
	if k > maxWindowK {
		k = maxWindowK
	}
	return k * 1000
}

// compactionConfig builds the agent-core compaction config for a context window
// in tokens. agentcore.NewSession wires the summarizer (same provider) when this
// is set on Options.Compaction.
func compactionConfig(windowTokens int) *compaction.Config {
	if windowTokens <= 0 {
		windowTokens = defaultWindowK * 1000
	}
	return &compaction.Config{ContextWindow: windowTokens}
}

// FromEnv resolves the LLM provider config:
//
//	ARTEX_LLM_PROVIDER = anthropic|openai (default: inferred from keys)
//	ARTEX_LLM_MODEL    = model id        (default: per provider)
//	ARTEX_LLM_BASE_URL = endpoint        (optional)
//	ARTEX_LLM_PROXY    = proxy URL        (optional; http/https/socks5)
//	ANTHROPIC_API_KEY / OPENAI_API_KEY         = credentials
func FromEnv() (Config, bool) {
	prov := os.Getenv("ARTEX_LLM_PROVIDER")
	anthKey := os.Getenv("ANTHROPIC_API_KEY")
	oaiKey := os.Getenv("OPENAI_API_KEY")
	if prov == "" {
		switch {
		case os.Getenv("OLLAMA_HOST") != "":
			prov = "ollama"
		case anthKey != "":
			prov = "anthropic"
		case oaiKey != "":
			prov = "openai"
		default:
			return Config{}, false
		}
	}

	baseURL := os.Getenv("ARTEX_LLM_BASE_URL")
	if strings.TrimSpace(baseURL) == "" && prov == "ollama" {
		baseURL = os.Getenv("OLLAMA_HOST")
	}
	c := Config{
		BaseURL: baseURL,
		Model:   os.Getenv("ARTEX_LLM_MODEL"),
		Proxy:   strings.TrimSpace(os.Getenv("ARTEX_LLM_PROXY")),
		Stream:  !isFalsy(os.Getenv("ARTEX_LLM_STREAM")),
	}
	switch prov {
	case "openai":
		c.Format = llm.FormatOpenAI
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	case "ollama":
		c.Format = FormatOllama
		if c.BaseURL == "" {
			c.BaseURL = DefaultOllamaBaseURL
		}
		c.BaseURL = normalizeOllamaBaseURL(c.BaseURL)
		if c.Model == "" {
			c.Model = "llama3.2"
		}
	default:
		c.Format = llm.FormatAnthropic
		c.APIKey = anthKey
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	if c.APIKey == "" && c.NeedsAPIKey() {
		return Config{}, false
	}
	return c, true
}

// ConfigFrom builds a Config from UI-provided strings (provider defaults to
// anthropic; model defaults per provider). Inputs are trimmed and the base URL
// is normalized to the API base the provider expects (the provider appends the
// endpoint path itself), so a full endpoint URL is tolerated.
func ConfigFrom(provider, model, baseURL, apiKey, proxy string) Config {
	c := Config{
		Model:   strings.TrimSpace(model),
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:  strings.TrimSpace(apiKey),
		Proxy:   strings.TrimSpace(proxy),
		Stream:  true, // Streaming by default; callers override per profile
	}
	switch strings.TrimSpace(provider) {
	case "openai":
		c.Format = llm.FormatOpenAI
		// provider appends "/chat/completions"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/chat/completions"), "/")
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		// provider appends "/responses"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/responses"), "/")
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	case "antigravity":
		c.Format = FormatAntigravity
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(c.BaseURL, "/v1internal:streamGenerateContent?alt=sse"), "/v1internal:streamGenerateContent"), "/")
		if c.Model == "" {
			c.Model = "gemini-3.1-pro"
		}
	case "ollama":
		c.Format = FormatOllama
		c.BaseURL = normalizeOllamaBaseURL(c.BaseURL)
		if c.Model == "" {
			c.Model = "llama3.2"
		}

	default:
		c.Format = llm.FormatAnthropic
		// provider appends "/v1/messages".
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/v1/messages"), "/")
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	return c
}

func normalizeOllamaBaseURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	base = strings.TrimSuffix(base, "/chat/completions")
	base = strings.TrimRight(base, "/")
	if base == "" {
		return DefaultOllamaBaseURL
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	return base
}

// isFalsy reports whether an env-var string explicitly requests "off". Empty or
// unrecognized → false (so an unset var keeps the streaming default).
func isFalsy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// Provider returns the short provider name ("anthropic", "openai", "ollama", or a native format).
func (c Config) Provider() string {
	switch c.Format {
	case llm.FormatOpenAI:
		return "openai"
	case llm.FormatOpenAIResponses:
		return "openai-responses"
	case FormatAntigravity:
		return "antigravity"
	case FormatOllama:
		return "ollama"
	}
	return "anthropic"
}

// nativeProviders maps subscription auth methods to native executor providers and formats.
var nativeProviders = map[string]struct {
	provider string
	format   llm.Format
}{
	"claude_code": {"claude", llm.FormatAnthropic},
	"codex":       {"codex", llm.FormatOpenAIResponses},
	"antigravity": {"antigravity", FormatAntigravity},
	// A locally hosted model has no grant to refresh, but it is reached through the
	// same proxy so that every model request leaves by one egress under one policy.
	"custom": {"custom", llm.Format("openai")},
}

// NativeProviderName returns the canonical subscription executor, or empty for API-key providers.
func (c Config) NativeProviderName() string { return nativeProviders[c.AuthMethod].provider }

// NewProvider builds an API-key llm.Provider from the config. When a rate is set, the
// limiter lives on the single provider instance — so planner + all workers +
// main agent (which share this provider) are bounded by one shared rate limit.
func (c Config) NewProvider() (llm.Provider, error) {
	if c.AuthMethod != "" && c.AuthMethod != "api_key" {
		return nil, fmt.Errorf("LLM authentication method %q requires NewProviderForProfile", c.AuthMethod)
	}
	if c.Format == FormatAntigravity {
		return nil, fmt.Errorf("LLM authentication method does not match provider format")
	}
	client, err := quotaAwareHTTPClient(c.Proxy, c.SessionHeaderKey, c.Format)
	if err != nil {
		return nil, err
	}
	if c.Format == llm.FormatOpenAIResponses && c.ReasoningEffort == "" {
		log.Printf("llm: model %s has no reasoning_effort, so reasoning summaries are not requested", c.Model)
	}
	wireFormat, baseURL, apiKey := c.Format, c.BaseURL, c.APIKey
	if wireFormat == FormatOllama {
		wireFormat = llm.FormatOpenAI
		baseURL = normalizeOllamaBaseURL(baseURL)
		if strings.TrimSpace(apiKey) == "" {
			apiKey = ollamaPlaceholderKey
		}
	}
	lc := llm.Config{
		Format:     wireFormat,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		Model:      c.Model,
		HTTPClient: client,
	}
	// The thinking toggle and the effort level are passed through as two independent fields (empty = the field is not sent).
	lc.ThinkingType = c.ThinkingType
	lc.ReasoningEffort = c.ReasoningEffort
	// Field-name selection for the output limit (empty = use max_tokens). The value is passed per turn via agentcore.Options.MaxTokens.
	lc.MaxTokensField = c.MaxTokensField
	// Retry parameters follow the SDK semantics (count 0 = default / negative = disabled; interval 0 = exponential backoff / >0 = fixed).
	lc.MaxRetries = c.Retry.ConnectAttempts
	lc.RetryInterval = c.Retry.ConnectInterval
	lc.EmptyResponseRetries = c.Retry.EmptyAttempts
	lc.EmptyResponseInterval = c.Retry.EmptyInterval
	if c.RatePerSecond > 0 || c.RatePerMinute > 0 {
		lc.RateLimit = &llm.RateLimit{PerSecond: c.RatePerSecond, PerMinute: c.RatePerMinute}
	}
	return llm.NewProvider(lc)
}

// NewProviderForProfile builds a provider for a profile. Subscription credentials remain on the native host proxy.
func (c Config) NewProviderForProfile(profileID string, proxy *nativeproxy.Client) (llm.Provider, error) {
	if c.AuthMethod == "" || c.AuthMethod == "api_key" {
		return c.NewProvider()
	}
	sp, ok := nativeProviders[c.AuthMethod]
	if !ok {
		return nil, fmt.Errorf("unsupported LLM authentication method")
	}
	if c.Format != sp.format {
		return nil, fmt.Errorf("LLM authentication method does not match provider format")
	}
	if proxy == nil || profileID == "" {
		return nil, fmt.Errorf("native proxy client and profile id are required")
	}
	if c.BaseURL != "" || c.APIKey != "" || c.Proxy != "" {
		return nil, fmt.Errorf("base URL, API key, and proxy are not supported for native subscription profiles")
	}
	if c.SessionHeaderKey != "" {
		return nil, fmt.Errorf("session header is not supported for native subscription profiles")
	}
	p := &nativeProvider{proxy: proxy, profileID: profileID, provider: sp.provider, model: c.Model, thinking: c.ThinkingType, effort: c.ReasoningEffort}
	return llm.RateLimited(p, llm.RateLimit{PerSecond: c.RatePerSecond, PerMinute: c.RatePerMinute}), nil
}

// IsQuotaExhaustedMessage deliberately recognizes only explicit balance,
// billing, credit, or quota-exhaustion signals. Generic 429/rate-limit text,
// authentication failures, network errors, and server failures are excluded.
var nonFailoverHTTPStatus = regexp.MustCompile(`(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(?:401|403|5\d\d)\b`)
var transientQuotaLimit = regexp.MustCompile(`(?i)(?:\b(?:rpm|tpm|rpd|qps)\b|quota[_\s-]*metric|rate[_\s-]*limit|too many requests|(?:requests?|tokens?)\s+(?:per|/)\s*(?:second|minute)|(?:per|/)\s*(?:second|minute)\s+(?:requests?|tokens?)|generate[_\s-]*requests[_\s-]*per[_\s-]*(?:minute|second)|tokens?[_\s-]*per[_\s-]*(?:minute|second))`)

func IsQuotaExhaustedMessage(message string) bool {
	message = strings.ToLower(message)
	// Authentication/authorization and provider-side 5xx failures never rotate,
	// even when a gateway happens to echo a quota-looking phrase in the body.
	if nonFailoverHTTPStatus.MatchString(message) {
		return false
	}
	// Provider APIs frequently describe an ordinary rate limit as "quota
	// exceeded", especially Google-style responses containing a quota metric.
	// These limits recover with time and must stay on the current provider.
	if transientQuotaLimit.MatchString(message) {
		return false
	}
	markers := []string{
		"insufficient_quota", "quota_exceeded", "quota exceeded", "quota exhausted",
		"exceeded your current quota", "billing_hard_limit_reached",
		"billing hard limit", "billing_not_active", "credit balance", "insufficient credit",
		"insufficient balance", "balance is too low", "payment required", "status 402",
		// Provider error text is whatever the upstream chose to send, so the
		// classifier matches Chinese wording too even though this application is
		// English-only. Do not translate these.
		"\u4f59\u989d\u4e0d\u8db3", "\u989d\u5ea6\u4e0d\u8db3", "\u989d\u5ea6\u5df2\u7528\u5c3d", "\u6b20\u8d39",
	}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// gRPC RESOURCE_EXHAUSTED is overloaded for both account quota and ordinary
	// request-rate limiting. Preserve it as an explicit exhaustion signal only
	// when the same error does not identify a transient rate limit.
	return strings.Contains(message, "resource_exhausted") &&
		!strings.Contains(message, "rate limit") &&
		!strings.Contains(message, "too many requests")
}

// quotaAwareTransport preserves Norma's normal retry behavior except for a 429
// whose body explicitly says the account quota/balance is exhausted. Norma's
// retry loop treats every 429 as transient; normalizing only that response to
// 402 lets a task router fail over immediately while retaining the original
// response body for provider-specific classification and audit logs.
type quotaAwareTransport struct {
	base http.RoundTripper
	// sessionHeaderKey, when non-empty, is the HTTP header name each request
	// carries; its value is the session id read from the request context. Empty
	// disables it. See Config.SessionHeaderKey.
	sessionHeaderKey string
	// format selects the reasoning rewrite for outgoing bodies; see exposeReasoning.
	format llm.Format
}

func (t quotaAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Custom session-id header: name is user-configured, value is THIS run's
	// session id (norma stashes it on the context via transcript.WithSessionID).
	// Stable across a session's turns and distinct across sessions — exactly what
	// a session-keyed prompt cache wants. Skipped when no session id is present.
	if t.sessionHeaderKey != "" {
		if sid := transcript.SessionIDFrom(req.Context()); sid != "" {
			req.Header.Set(t.sessionHeaderKey, sid)
		}
	}

	// Rewrite before capture, so the raw snapshot below is the body actually sent.
	var err error
	if req, err = exposeReasoning(req, t.format); err != nil {
		return nil, err
	}

	// When LLM recording is on, the Recorder puts a Capture on the context so the
	// raw wire bodies can be persisted. This is the only layer that still sees
	// them: norma builds the request body internally and decodes the SSE response
	// before either reaches the recorder.
	capt := llmrec.CaptureFrom(req.Context())
	capt.SetRequest(requestBodySnapshot(req))

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// Tee rather than read: a 200 is an SSE stream that must keep streaming. The
	// 429 branch below reads through this wrapper, so its body lands in the
	// capture before being replaced.
	resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)
	if resp.StatusCode == http.StatusOK &&
		(t.format == llm.FormatAnthropic || t.format == llm.FormatOpenAI || t.format == llm.FormatOpenAIResponses) &&
		strings.Contains(resp.Header.Get("Content-Type"), "event-stream") {
		resp.Body = observeRefusalSSE(req.Context(), t.format, resp.Body)
	}

	// Refusal fallback (Option A): norma folds/drops the OpenAI refusal signal,
	// so sniff the raw NON-streaming body here and flag it on the context for the
	// engine's refusal-replay loop. Anthropic refusals are caught downstream from
	// stop_reason; SSE refusals are observed incrementally by observeRefusalSSE above.
	if resp.StatusCode == http.StatusOK &&
		(t.format == llm.FormatOpenAI || t.format == llm.FormatOpenAIResponses) &&
		!strings.Contains(resp.Header.Get("Content-Type"), "event-stream") {
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read %s response body: %w", t.format, readErr)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		if RefusalInRawResponse(t.format, body) {
			llmrec.MarkRefusal(req.Context())
		}
		return resp, nil
	}

	if resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if readErr != nil {
		return nil, fmt.Errorf("read %s response body: %w", t.format, readErr)
	}
	if IsQuotaExhaustedMessage(string(body)) {
		resp.StatusCode = http.StatusPaymentRequired
		resp.Status = "402 Payment Required"
	}
	return resp, nil
}

// requestBodySnapshot copies an outgoing request body without consuming it.
// norma builds every model request from a *bytes.Reader, so net/http populates
// GetBody and the copy has no effect on what gets sent.
func requestBodySnapshot(req *http.Request) string {
	if req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return string(b)
}

func quotaAwareHTTPClient(proxy, sessionHeaderKey string, format llm.Format) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		transport.Proxy = nil // Empty = connect directly, do not fall back to the HTTP_PROXY/HTTPS_PROXY environment variables
	} else {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5":
		case "":
			return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
		default:
			return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: quotaAwareTransport{base: transport, sessionHeaderKey: strings.TrimSpace(sessionHeaderKey), format: format}}, nil
}

// logTestConnection prints the raw HTTP status code(s) and response body of a
// connection test to the server log, so "Test Connection" leaves a diagnosable trail of
// exactly what the gateway returned — 401 bodies, quota text, empty frames — not
// just the collapsed ok/err the UI shows. Bodies are clipped to keep a chatty
// SSE stream from flooding the log.
func logTestConnection(c Config, capt *llmrec.Capture) {
	attempts := capt.Attempts()
	if len(attempts) == 0 {
		log.Printf("[llm-test] %s / %s @ %s — no HTTP request was sent (config parsing or connection setup failed)",
			c.Provider(), c.Model, c.BaseURL)
		return
	}
	for i, a := range attempts {
		log.Printf("[llm-test] %s / %s @ %s — attempt %d/%d HTTP %d\nresponse body: %s",
			c.Provider(), c.Model, c.BaseURL, i+1, len(attempts), a.Status, clipBody(a.Body))
	}
}

// clipBody trims a wire body for logging. 4K is plenty to show an error JSON or
// the head of an SSE stream while bounding a runaway response.
func clipBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty)"
	}
	const max = 4096
	if len(s) > max {
		return s[:max] + fmt.Sprintf("…(truncated, %d bytes total)", len(s))
	}
	return s
}

// TestConnection makes a minimal real completion to verify the provider/model/
// endpoint/key actually work. Returns the round-trip latency and the model's
// reply text.
func TestConnection(ctx context.Context, c Config) (time.Duration, string, error) {
	prov, err := c.NewProvider()
	if err != nil {
		return 0, "", err
	}
	return testConnection(ctx, c, prov, !c.Stream, true)
}

// TestConnectionForProfile tests a native subscription profile without exposing credentials to the app.
func TestConnectionForProfile(ctx context.Context, c Config, proxy *nativeproxy.Client, profileID string) (time.Duration, string, error) {
	prov, err := c.NewProviderForProfile(profileID, proxy)
	if err != nil {
		return 0, "", err
	}
	return testConnection(ctx, c, prov, true, false)
}

func testConnection(ctx context.Context, c Config, prov llm.Provider, nonStreaming, logBodies bool) (time.Duration, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Capture the raw wire traffic: a connection test most needs to show what the gateway actually returned (status code + response body),
	// but norma decodes the response into StreamEvent and that information is lost. quotaAwareTransport will
	// look up this Capture in the context and fill in the status code and body of each HTTP attempt.
	ctx, capt := llmrec.NewCapture(ctx)
	if logBodies {
		defer logTestConnection(c, capt)
	}
	// The connection test is a single one-shot path that does not go through agentcore's session loop, so nothing attaches to the context
	// a session id to the context. For endpoints configured with SessionHeaderKey (e.g. opencode zen, which strictly requires
	// the x-opencode-session header and returns 400 MissingSessionID if it is missing), this causes "chat works normally,
	// ...the gap of "click to test still gets 400". Here we additionally attach a one-off random session id, so that the test and a real conversation go through the same header-building logic;
	// endpoints that don't configure SessionHeaderKey don't read it, so there is no side effect.
	ctx = transcript.WithSessionID(ctx, "conntest-"+transcript.NewSessionID())
	start := time.Now()
	// MaxTokens must be set generously: reasoning models (e.g. deepseek-v4-pro) produce a long stretch of thinking before giving the answer
	// Thinking (measured: even a single "ping" can burn ~2900 token). If only 32 is given, the model will keep getting stuck in the "thinking phase"
	// and hits the output limit (finish=length) and gets truncated. The connection test still counts as passing (err=nil), but it shows up as a mess of "interrupted/length/resume"
	// a confusing "interrupted/length/resume". Give it enough budget to cleanly emit OK (finish=stop).
	// EscalateMaxTokens stays false: do not raise the limit and retry because of truncation, to avoid a resume loop that wastes tokens.
	reply, err := agentcore.Run(ctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{"You are a connection test. Output exactly the two characters OK - no reasoning, no explanation, nothing else."},
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      8192,
		NonStreaming:   nonStreaming,
	}, "ping")
	lat := time.Since(start)
	if err != nil {
		return lat, "", err
	}
	// err==nil is not enough: cases where the request succeeds but the model outputs not a single character do really happen (thinking consumes the whole budget,
	// the body is swallowed by the safety policy, or the compatibility layer drops the content). A configuration like this amounts to "no reply" within the session,
	// The test then reports success, which is the gap this item is meant to eliminate. Anything without visible body text is judged a failure.
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return lat, "", fmt.Errorf("model returned no reply content (request succeeded, but no text was returned)")
	}
	return lat, reply, nil
}

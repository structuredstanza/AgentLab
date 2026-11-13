// Package usage implements host-side subscription allocation queries for
// Anthropic OAuth usage, Codex wham usage, and Antigravity quota summaries.
// Recipes run only inside the host; responses are normalized to contract.UsageReport.
//
// Provider-specific behavior:
//   - Antigravity does not set Accept-Encoding itself. The Go transport adds gzip
//     and decodes it transparently only when it manages the header.
//   - Timestamps accept RFC 3339 strings only.
package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

const (
	maxBodyBytes = 128 * 1024
	// maxJSMillis is the largest instant a JavaScript Date can represent.
	maxJSMillis = 8.64e15

	anthropicURL = "https://api.anthropic.com/api/oauth/usage"
	codexURL     = "https://chatgpt.com/backend-api/wham/usage"
	agQuotaURL   = "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
)

var (
	fiveHourRE = regexp.MustCompile(`5[\s_-]*hour`)
	sevenDayRE = regexp.MustCompile(`7[\s_-]*day`)
)

// Grant is the host-only credential material one recipe needs. Access is a bearer
// token: never log, format, or return it.
type Grant struct {
	Access    string
	AccountID string
	ProjectID string
}

// Credential supplies the current grant for one profile and provider. The
// implementation owns refresh and extraction from the stored native record.
type Credential interface {
	Grant(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (Grant, error)
}

// Error is a fixed-message failure. It never carries response bodies, URLs, or
// tokens. Status and Code are the public mapping. Upstream is the provider's HTTP
// status, or 0 when the provider returned none.
type Error struct {
	Code     string
	Status   int
	Upstream int
}

func (e *Error) Error() string { return "usage: " + e.Code }

// ErrorStatus returns the public HTTP status and reason code for this failure.
func (e *Error) ErrorStatus() (int, string) { return e.Status, e.Code }

// Service runs the recipes with an injected HTTP client.
type Service struct {
	client *http.Client
	creds  Credential
	now    func() time.Time
}

var _ contract.Usage = (*Service)(nil)

// New builds a usage service. The caller supplies the client; no default is constructed.
func New(client *http.Client, creds Credential) (*Service, error) {
	if client == nil || creds == nil {
		return nil, errors.New("usage: client and credential are required")
	}
	return &Service{client: client, creds: creds, now: time.Now}, nil
}

type result struct {
	plan    *string
	windows []contract.Window
}

// Usage implements contract.Usage.
func (s *Service) Usage(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (contract.UsageReport, error) {
	g, err := s.creds.Grant(ctx, profile, provider)
	if err != nil {
		return contract.UsageReport{}, err
	}
	if g.Access == "" {
		return contract.UsageReport{}, &Error{Code: "unauthorized", Status: http.StatusUnauthorized}
	}

	var res result
	switch provider {
	case contract.ProviderClaude:
		res, err = s.anthropic(ctx, g)
	case contract.ProviderCodex:
		res, err = s.codex(ctx, g)
	case contract.ProviderAntigravity:
		res, err = s.antigravity(ctx, g)
	default:
		return contract.UsageReport{}, &Error{Code: "unsupported_provider", Status: http.StatusBadRequest}
	}
	if err != nil {
		return contract.UsageReport{}, err
	}
	return contract.UsageReport{
		Provider:  provider,
		Plan:      res.plan,
		FetchedAt: formatTime(s.now()),
		Windows:   res.windows,
	}, nil
}

func (s *Service) anthropic(ctx context.Context, g Grant) (result, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+g.Access)
	h.Set("Anthropic-Beta", "oauth-2025-04-20,claude-code-20250219")
	h.Set("Accept", "application/json")
	h.Set("User-Agent", "anthropic-sdk-typescript/0.39.0 userOAuthProvider")

	data, err := s.getJSON(ctx, http.MethodGet, anthropicURL, h, nil)
	if err != nil {
		return result{}, err
	}
	root := asObject(data)
	windows := []contract.Window{}
	if w, ok := anthropicWindow(root, "five_hour", "5-Hour Session"); ok {
		windows = append(windows, w)
	}
	if w, ok := anthropicWindow(root, "seven_day", "7-Day Weekly"); ok {
		windows = append(windows, w)
	}
	return result{plan: asString(root["plan"]), windows: windows}, nil
}

func anthropicWindow(root map[string]any, key, label string) (contract.Window, bool) {
	w := asObject(root[key])
	u, ok := asNumber(w["utilization"])
	if !ok {
		return contract.Window{}, false
	}
	return window(key, label, clamp(u/100), toRFC3339(w["resets_at"])), true
}

func (s *Service) codex(ctx context.Context, g Grant) (result, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+g.Access)
	h.Set("Accept", "application/json")
	h.Set("User-Agent", "codex-cli")
	if g.AccountID != "" {
		h.Set("ChatGPT-Account-Id", g.AccountID)
	}

	data, err := s.getJSON(ctx, http.MethodGet, codexURL, h, nil)
	if err != nil {
		return result{}, err
	}
	root := asObject(data)
	rl := asObject(root["rate_limit"])
	windows := []contract.Window{}
	if pw := asObject(rl["primary_window"]); pw != nil {
		if w, ok := s.codexWindow(pw, "five_hour", "5-Hour Session"); ok {
			windows = append(windows, w)
		}
	}
	if sw := asObject(rl["secondary_window"]); sw != nil {
		if w, ok := s.codexWindow(sw, "seven_day", "7-Day Weekly"); ok {
			windows = append(windows, w)
		}
	}
	return result{plan: asString(root["plan_type"]), windows: windows}, nil
}

func (s *Service) codexWindow(w map[string]any, fallbackID, fallbackLabel string) (contract.Window, bool) {
	usedPercent, ok := asNumber(w["used_percent"])
	if !ok {
		return contract.Window{}, false
	}
	used := clamp(usedPercent / 100)

	id, label := fallbackID, fallbackLabel
	if secs, ok := asNumber(w["limit_window_seconds"]); ok {
		switch {
		case secs == 18000:
			id, label = "five_hour", "5-Hour Session"
		case secs == 604800:
			id, label = "seven_day", "7-Day Weekly"
		case secs >= 86400:
			d := int(math.Round(secs / 86400))
			id, label = fmt.Sprintf("%dd", d), fmt.Sprintf("%d-Day Window", d)
		default:
			h := int(math.Round(secs / 3600))
			id, label = fmt.Sprintf("%dh", h), fmt.Sprintf("%d-Hour Window", h)
		}
	}

	var resets *string
	if at, ok := asNumber(w["reset_at"]); ok {
		resets = toRFC3339(at)
	} else if after, ok := asNumber(w["reset_after_seconds"]); ok {
		resets = msToRFC3339(float64(s.now().UnixMilli()) + after*1000)
	}
	return window(id, label, used, resets), true
}

func (s *Service) antigravity(ctx context.Context, g Grant) (result, error) {
	body, err := json.Marshal(map[string]string{"project": g.ProjectID})
	if err != nil {
		return result{}, &Error{Code: "upstream_error", Status: http.StatusBadGateway}
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+g.Access)
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "antigravity")

	data, err := s.getJSON(ctx, http.MethodPost, agQuotaURL, h, body)
	if err != nil {
		return result{}, err
	}

	root := asObject(data)
	all := append([]any{}, asArray(root["buckets"])...)
	for _, grp := range asArray(root["groups"]) {
		all = append(all, asArray(asObject(grp)["buckets"])...)
	}

	windows := []contract.Window{}
	seen := make(map[string]bool)
	for _, item := range all {
		b := asObject(item)
		if b == nil {
			continue
		}
		if disabled, _ := b["disabled"].(bool); disabled {
			continue
		}
		displayName := asStr(b["displayName"])
		bucketID := asStr(b["bucketId"])
		windowName := asStr(b["window"])
		hint := strings.ToLower(windowName + " " + displayName + " " + bucketID)

		id := firstNonEmpty(bucketID, windowName, "quota")
		label := firstNonEmpty(displayName, bucketID, "Quota")
		switch {
		case strings.Contains(hint, "5h") || strings.Contains(hint, "5 hour") ||
			strings.Contains(hint, "five_hour") || fiveHourRE.MatchString(hint):
			id, label = "five_hour", firstNonEmpty(displayName, "5-Hour Session")
		case strings.Contains(hint, "week") || strings.Contains(hint, "7d") ||
			strings.Contains(hint, "7 day") || sevenDayRE.MatchString(hint):
			id, label = "seven_day", firstNonEmpty(displayName, "7-Day Weekly")
		case strings.Contains(hint, "day") || strings.Contains(hint, "daily") || strings.Contains(hint, "24h"):
			id, label = "daily", firstNonEmpty(displayName, "Daily Window")
		}

		remaining, hasRemaining := 0.0, false
		if f, ok := asNumber(b["remainingFraction"]); ok {
			remaining, hasRemaining = clamp(f), true
		} else if amt, ok := asNumber(b["remainingAmount"]); ok {
			if lim, ok := asNumber(b["limit"]); ok && lim > 0 {
				remaining, hasRemaining = clamp(amt/lim), true
			}
		}
		if !hasRemaining || seen[id] {
			continue
		}
		seen[id] = true
		windows = append(windows, contract.Window{
			ID:                id,
			Label:             label,
			UsedFraction:      clamp(1 - remaining),
			RemainingFraction: remaining,
			ResetsAt:          toRFC3339(b["resetTime"]),
		})
	}

	sort.SliceStable(windows, func(i, j int) bool {
		return antigravityOrder(windows[i].ID) < antigravityOrder(windows[j].ID)
	})
	return result{plan: asString(root["plan"]), windows: windows}, nil
}

func antigravityOrder(id string) int {
	switch id {
	case "five_hour":
		return 1
	case "seven_day":
		return 2
	case "daily":
		return 3
	}
	return 99
}

// getJSON performs one upstream call. Non-2xx statuses become *Error carrying the
// real upstream status. Bodies are capped at maxBodyBytes while reading.
func (s *Service) getJSON(ctx context.Context, method, url string, h http.Header, body []byte) (any, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, &Error{Code: "upstream_error", Status: http.StatusBadGateway}
	}
	req.Header = h

	res, err := s.client.Do(req)
	if err != nil {
		return nil, &Error{Code: "upstream_network_error", Status: http.StatusBadGateway}
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, upstreamError(res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes+1))
	if err != nil {
		return nil, &Error{Code: "upstream_network_error", Status: http.StatusBadGateway}
	}
	if len(raw) > maxBodyBytes {
		return nil, &Error{Code: "response_too_large", Status: http.StatusBadGateway}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, &Error{Code: "invalid_json", Status: http.StatusBadGateway}
	}
	return v, nil
}

func upstreamError(status int) *Error {
	switch status {
	case http.StatusTooManyRequests:
		return &Error{Code: "rate_limited", Status: http.StatusTooManyRequests, Upstream: status}
	case http.StatusUnauthorized, http.StatusForbidden:
		return &Error{Code: "unauthorized", Status: http.StatusUnauthorized, Upstream: status}
	default:
		return &Error{Code: "upstream_error", Status: http.StatusBadGateway, Upstream: status}
	}
}

func window(id, label string, used float64, resets *string) contract.Window {
	return contract.Window{
		ID:                id,
		Label:             label,
		UsedFraction:      used,
		RemainingFraction: clamp(1 - used),
		ResetsAt:          resets,
	}
}

// clamp maps non-finite input to 0 and clamps the rest to [0, 1].
func clamp(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return math.Max(0, math.Min(1, f))
}

// toRFC3339 accepts epoch seconds, epoch milliseconds (values above 1e12), or an
// RFC 3339 string. Anything else yields nil.
func toRFC3339(v any) *string {
	switch x := v.(type) {
	case float64:
		if x > 1e12 {
			return msToRFC3339(x)
		}
		return msToRFC3339(x * 1000)
	case string:
		if x == "" {
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			return nil
		}
		s := formatTime(t)
		return &s
	}
	return nil
}

func msToRFC3339(ms float64) *string {
	if math.IsNaN(ms) || math.IsInf(ms, 0) || math.Abs(ms) > maxJSMillis {
		return nil
	}
	s := formatTime(time.UnixMilli(int64(ms)))
	return &s
}

// formatTime matches JavaScript Date.prototype.toISOString: UTC with milliseconds.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

func asObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asArray(v any) []any {
	a, _ := v.([]any)
	return a
}

func asNumber(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func asString(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func asStr(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

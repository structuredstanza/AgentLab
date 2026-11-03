package usage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/artex/cliproxyhost/internal/contract"
)

type fakeCreds struct{ g Grant }

func (f fakeCreds) Grant(context.Context, contract.ProfileID, contract.Provider) (Grant, error) {
	return f.g, nil
}

// scripted answers each upstream URL with a canned status and body, and records calls.
type scripted struct {
	routes map[string]reply
	calls  []string
}

type reply struct {
	status int
	body   string
}

func (s *scripted) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls = append(s.calls, r.URL.String())
	rep, ok := s.routes[r.URL.String()]
	if !ok {
		return nil, errors.New("unexpected url")
	}
	return &http.Response{
		StatusCode: rep.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(rep.body)),
	}, nil
}

func newService(t *testing.T, s *scripted) *Service {
	t.Helper()
	svc, err := New(&http.Client{Transport: s}, fakeCreds{g: Grant{Access: "x", ProjectID: "p"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc.now = func() time.Time { return time.Unix(1700000000, 0) }
	return svc
}

func profile(t *testing.T) contract.ProfileID {
	t.Helper()
	p, err := contract.ParseProfileID("1")
	if err != nil {
		t.Fatalf("ParseProfileID: %v", err)
	}
	return p
}

func TestAntigravityUpstream401IsNotMaskedAndNoFallback(t *testing.T) {
	s := &scripted{routes: map[string]reply{
		agQuotaURL: {status: http.StatusUnauthorized, body: `{}`},
		// The removed availability endpoint must not be consulted for quota.
	}}
	_, err := newService(t, s).Usage(context.Background(), profile(t), contract.ProviderAntigravity)
	var ue *Error
	if !errors.As(err, &ue) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if ue.Upstream != http.StatusUnauthorized || ue.Status != http.StatusUnauthorized || ue.Code != "unauthorized" {
		t.Fatalf("got %+v, want real 401 surfaced as unauthorized", ue)
	}
	if len(s.calls) != 1 || s.calls[0] != agQuotaURL {
		t.Fatalf("calls = %v, want only the quota-summary request", s.calls)
	}
}

func TestAntigravityQuotaUnavailableDoesNotUseAvailableModelsAsQuota(t *testing.T) {
	s := &scripted{routes: map[string]reply{
		agQuotaURL: {status: http.StatusNotFound, body: `{}`},
	}}
	_, err := newService(t, s).Usage(context.Background(), profile(t), contract.ProviderAntigravity)
	var ue *Error
	if !errors.As(err, &ue) || ue.Upstream != http.StatusNotFound {
		t.Fatalf("Usage error = %v, want upstream 404", err)
	}
	if len(s.calls) != 1 || s.calls[0] != agQuotaURL {
		t.Fatalf("calls = %v, want only the quota-summary request", s.calls)
	}
}

func TestAntigravityKeepsMeasuredZeroAndOmitsUnknownOrDisabledBuckets(t *testing.T) {
	body := `{"buckets":[
		{"bucketId":"five-hour","displayName":"5-hour quota","remainingFraction":0,"resetTime":1700000000},
		{"bucketId":"weekly","displayName":"Weekly quota"},
		{"bucketId":"weekly","displayName":"Weekly quota","remainingFraction":0.25},
		{"bucketId":"unknown","displayName":"Daily quota"},
		{"bucketId":"disabled","displayName":"Disabled quota","remainingFraction":0,"disabled":true}
	]}`
	s := &scripted{routes: map[string]reply{agQuotaURL: {status: http.StatusOK, body: body}}}
	rep, err := newService(t, s).Usage(context.Background(), profile(t), contract.ProviderAntigravity)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if len(rep.Windows) != 2 {
		t.Fatalf("windows = %+v, want only measured enabled buckets", rep.Windows)
	}
	if rep.Windows[0].ID != "five_hour" || rep.Windows[0].RemainingFraction != 0 || rep.Windows[0].UsedFraction != 1 {
		t.Fatalf("exhausted window = %+v, want remaining=0 used=1", rep.Windows[0])
	}
	if rep.Windows[0].ResetsAt == nil || *rep.Windows[0].ResetsAt != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("exhausted reset = %v", rep.Windows[0].ResetsAt)
	}
	if rep.Windows[1].ID != "seven_day" || rep.Windows[1].RemainingFraction != 0.25 || rep.Windows[1].UsedFraction != 0.75 {
		t.Fatalf("positive window = %+v, want remaining=0.25 used=0.75", rep.Windows[1])
	}
}

func TestClaudeUsagePercentNormalizesAndSkipsUnknownWindow(t *testing.T) {
	body := `{"plan":"pro","five_hour":{"utilization":100,"resets_at":"2026-10-30T12:00:00Z"},"seven_day":{}}`
	s := &scripted{routes: map[string]reply{anthropicURL: {status: http.StatusOK, body: body}}}
	rep, err := newService(t, s).Usage(context.Background(), profile(t), contract.ProviderClaude)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if len(rep.Windows) != 1 || rep.Windows[0].RemainingFraction != 0 || rep.Windows[0].UsedFraction != 1 {
		t.Fatalf("windows = %+v, want one exhausted five_hour window", rep.Windows)
	}
	if rep.Windows[0].ResetsAt == nil || *rep.Windows[0].ResetsAt != "2026-10-30T12:00:00.000Z" {
		t.Fatalf("reset = %v", rep.Windows[0].ResetsAt)
	}
}

func TestCodexWindowsNormalize(t *testing.T) {
	body := `{"plan_type":"pro","rate_limit":{
		"primary_window":{"used_percent":25,"limit_window_seconds":18000,"reset_at":1700000000},
		"secondary_window":{"used_percent":10,"limit_window_seconds":604800,"reset_after_seconds":60}}}`
	s := &scripted{routes: map[string]reply{codexURL: {status: http.StatusOK, body: body}}}
	rep, err := newService(t, s).Usage(context.Background(), profile(t), contract.ProviderCodex)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if len(rep.Windows) != 2 {
		t.Fatalf("windows = %d, want 2", len(rep.Windows))
	}
	if rep.Windows[0].ID != "five_hour" || rep.Windows[1].ID != "seven_day" {
		t.Fatalf("ids = %q, %q", rep.Windows[0].ID, rep.Windows[1].ID)
	}
	if rep.Windows[0].RemainingFraction != 0.75 {
		t.Fatalf("remaining = %v, want 0.75", rep.Windows[0].RemainingFraction)
	}
	if rep.Windows[0].ResetsAt == nil || *rep.Windows[0].ResetsAt != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("resets = %v", rep.Windows[0].ResetsAt)
	}
}
func TestCodexMissingUsageIsUnknownButExplicitExhaustionIsZero(t *testing.T) {
	body := `{"rate_limit":{
		"primary_window":{"limit_window_seconds":18000,"reset_at":1700000000},
		"secondary_window":{"used_percent":100,"limit_window_seconds":604800,"reset_at":1700000060}}}`
	s := &scripted{routes: map[string]reply{codexURL: {status: http.StatusOK, body: body}}}
	rep, err := newService(t, s).Usage(context.Background(), profile(t), contract.ProviderCodex)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if len(rep.Windows) != 1 || rep.Windows[0].ID != "seven_day" || rep.Windows[0].RemainingFraction != 0 {
		t.Fatalf("windows = %+v, want only explicit exhausted seven_day window", rep.Windows)
	}
}

func TestClampAndTimeHelpers(t *testing.T) {
	if clamp(2) != 1 || clamp(-1) != 0 {
		t.Fatal("clamp range broken")
	}
	if clamp(nanValue()) != 0 {
		t.Fatal("clamp must map NaN to 0")
	}
	if got := toRFC3339(1700000000.0); got == nil || *got != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("seconds: got %v", got)
	}
	if got := toRFC3339(1700000000000.0); got == nil || *got != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("millis: got %v", got)
	}
	if toRFC3339("not a time") != nil {
		t.Fatal("unparseable string must yield nil")
	}
}

func nanValue() float64 {
	zero := 0.0
	return zero / zero
}

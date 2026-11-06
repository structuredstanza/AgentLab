package limits

import (
	"context"
	"testing"
	"time"
)

// A tool whose declared rate exceeds the ceiling must still start.
//
// Before the clamp, reservePerMin charged rate*60 and the admission test
// required st.reservedPerMin+reserve <= MaxRequestsPerMinute, so the shipped
// ffuf default (50 rps = 3000/min) against a 100/min ceiling could never be
// admitted: run_tool polled until the agent run was cancelled. The existing
// oversubscription test used rate=1, the only value that fit, so nothing
// failed.
func TestAcquireAdmitsRateAboveTheCeiling(t *testing.T) {
	l := New(Policy{MaxRequestsPerMinute: 100, MaxConcurrentPerTarget: 3, MaxConcurrentTotal: 3})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// ffuf's shipped default.
	release, err := l.Acquire(ctx, "example.com", rpsManifest(), map[string]string{"rate": "50"})
	if err != nil {
		t.Fatalf("a 50 rps scan against a 100/min ceiling was never admitted: %v", err)
	}
	release()

	// nuclei's shipped default.
	release, err = l.Acquire(ctx, "example.com", rpsManifest(), map[string]string{"rate": "150"})
	if err != nil {
		t.Fatalf("a 150 rps scan against a 100/min ceiling was never admitted: %v", err)
	}
	release()
}

// A fractional rate declares a real budget; it must not parse to zero and
// silently disable the ceiling.
func TestReservePerMinParsesFractionalRates(t *testing.T) {
	l := New(Policy{MaxRequestsPerMinute: 100})
	cases := map[string]int{
		"1.5":     90,  // ceil(1.5*60)
		"0.5":     30,  // ceil(0.5*60)
		"2":       120, // exact
		"10/s":    0,   // not a number: no declaration, no reservation
		" 5 rps":  0,   // same
		"":        0,
		"notanum": 0,
	}
	for rate, want := range cases {
		got := l.reservePerMin(rpsManifest(), map[string]string{"rate": rate})
		if got != want {
			t.Errorf("reservePerMin(rate=%q) = %d, want %d", rate, got, want)
		}
	}
}

// The three spellings of one host must share one bucket, or a tool that varies
// case or appends a trailing dot multiplies the operator's stated ceiling.
func TestNormalizeCollapsesHostSpellings(t *testing.T) {
	for _, in := range []string{"EXAMPLE.com", "example.com.", "example.com", "http://example.com/x", "example.com:8080"} {
		if got := normalize(in); got != "example.com" {
			t.Errorf("normalize(%q) = %q, want example.com", in, got)
		}
	}
}

// Two distinct IPv6 literals must not share one bucket.
func TestNormalizeKeepsIPv6Distinct(t *testing.T) {
	cases := map[string]string{
		"2001:db8::1":        "2001:db8::1",
		"2001:db8::2":        "2001:db8::2",
		"[2001:db8::1]":      "2001:db8::1",
		"[2001:db8::1]:8080": "2001:db8::1",
		"http://[::1]:8080/": "::1",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
	if normalize("2001:db8::1") == normalize("2001:db8::2") {
		t.Fatal("two IPv6 literals collapsed to one bucket")
	}
}

package limits

import (
	"testing"
)

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

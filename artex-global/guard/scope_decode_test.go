package guard

import (
	"encoding/json"
	"testing"
)

// The escaped-host bypass that was proven before the fix: the raw JSON names
// \u0065vil.example, the shell receives evil.example.
func TestAssetsInDecodesEscapedHost(t *testing.T) {
	raw := json.RawMessage(`{"command":"curl -s http://\u0065vil.example/admin"}`)
	got := assetsIn(raw)
	want := "evil.example"
	for _, a := range got {
		if a == want {
			return
		}
	}
	t.Fatalf("assetsIn(%s) = %q, missing %q", raw, got, want)
}

// A bare IPv6 literal and a bracketed one must both be extracted.
func TestAssetsInExtractsIPv6(t *testing.T) {
	for _, in := range []string{
		`{"command":"nmap -6 2001:db8::1"}`,
		`{"command":"curl -g 'http://[2001:db8::1]/'"}`,
		`{"command":"curl http://[2001:db8::1]:8080/x"}`,
	} {
		got := assetsIn(json.RawMessage(in))
		found := false
		for _, a := range got {
			if a == "2001:db8::1" || a == "[2001:db8::1]" {
				found = true
			}
		}
		if !found {
			t.Errorf("assetsIn(%s) = %q, no IPv6 asset", in, got)
		}
	}
}

// A mixed-case hostname must still be reported so an exact-host exclusion
// matches it.
func TestAssetsInLowercasesBareHostname(t *testing.T) {
	got := assetsIn(json.RawMessage(`{"command":"nmap -sV API.corp.example"}`))
	for _, a := range got {
		if a == "api.corp.example" {
			return
		}
	}
	t.Fatalf("assetsIn = %q, missing api.corp.example", got)
}

// An IPv6 CIDR must survive as a candidate, and a compressed literal must keep
// its colons.
//
// net.ParseIP rejects "2001:db8::/32", so the CIDR arm dropped the whole match
// and an excluded IPv6 range was never enforced. Separately, the normalizer
// trimmed ':' from both ends, turning "::1" into "1" and "fe80::" into "fe80" —
// neither can match an exclusion.
func TestAssetsInKeepsIPv6CIDRAndCompressedLiterals(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{`{"command":"nmap -6 2001:db8::/32"}`, "2001:db8::/32"},
		{`{"command":"curl -g 'http://[::1]:8080/'"}`, "::1"},
		{`{"command":"ping6 fe80::"}`, "fe80::"},
	} {
		got := assetsIn(json.RawMessage(tc.in))
		found := false
		for _, a := range got {
			if a == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("assetsIn(%s) = %q, missing %q", tc.in, got, tc.want)
		}
	}
}

// Invalid JSON must not panic and must still scan the raw text.
func TestAssetsInMalformedJSONStillScans(t *testing.T) {
	got := assetsIn(json.RawMessage(`{"command":"curl http://evil.example/`))
	found := false
	for _, a := range got {
		if a == "evil.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("assetsIn = %q, missing evil.example", got)
	}
}

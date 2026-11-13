package db

import "testing"

// A scope row's kind must come from the value. The failure this prevents is an
// engagement where one host is filed as both `domain` and `subdomain`, or an
// apex is filed as a subdomain — a boundary built on a wrong kind matches
// nothing, and the host it was meant to cover is silently out of bounds.
func TestDeriveScopeKindFromValue(t *testing.T) {
	cases := []struct {
		name      string
		assetType string
		domain    string
		rawURL    string
		ip        string
		wantKind  string
		wantValue string
	}{
		{"apex filed as subdomain is corrected", "subdomain", "example.com", "", "", "root_domain", "example.com"},
		{"real subdomain", "subdomain", "api.example.com", "", "", "subdomain", "api.example.com"},
		{"apex labelled domain", "domain", "example.com", "", "", "root_domain", "example.com"},
		{"subdomain labelled domain is corrected", "domain", "api.example.com", "", "", "subdomain", "api.example.com"},
		{"host from a url", "service", "", "https://api.example.com:8443/x", "", "subdomain", "api.example.com"},
		{"url apex", "endpoint", "", "https://example.com/login", "", "root_domain", "example.com"},
		{"ip literal in host field", "service", "10.0.0.5", "", "", "ip", "10.0.0.5/32"},
		{"ip input", "ip", "", "", "10.0.0.5", "ip", "10.0.0.5/32"},
		{"cidr input", "ip", "", "", "10.20.0.0/16", "cidr", "10.20.0.0/16"},
		{"trailing dot is normalised", "subdomain", "API.Example.COM.", "", "", "subdomain", "api.example.com"},
		{"nothing usable", "subdomain", "", "", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, value := DeriveScopeKind(c.assetType, c.domain, c.rawURL, c.ip)
			if kind != c.wantKind || value != c.wantValue {
				t.Fatalf("got (%q, %q), want (%q, %q)", kind, value, c.wantKind, c.wantValue)
			}
		})
	}
}

// The same host arriving under two different caller labels must land on one
// kind, which is what makes the upsert idempotent rather than duplicating it.
func TestDeriveScopeKindIsStableAcrossLabels(t *testing.T) {
	kindA, valueA := DeriveScopeKind("domain", "api.example.com", "", "")
	kindB, valueB := DeriveScopeKind("subdomain", "api.example.com", "", "")
	kindC, valueC := DeriveScopeKind("service", "", "https://api.example.com/x", "")
	if kindA != kindB || kindB != kindC || valueA != valueB || valueB != valueC {
		t.Fatalf("labels disagree: (%s,%s) (%s,%s) (%s,%s)", kindA, valueA, kindB, valueB, kindC, valueC)
	}
}

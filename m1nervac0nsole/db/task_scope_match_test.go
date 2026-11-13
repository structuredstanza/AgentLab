package db

import "testing"

// A root_domain exclusion covers its whole subtree. Passing the bare apex as the
// pattern made the matcher require exact equality, so excluding corp.example
// blocked the apex and allowed api.corp.example — the opposite of what the kind
// means everywhere else in the system.
func TestMatchesScopeRowRootDomainCoversSubtree(t *testing.T) {
	row := TaskScope{Kind: "root_domain", Domain: "corp.example"}
	for _, asset := range []string{
		"corp.example",
		"api.corp.example",
		"https://deep.api.corp.example/x",
	} {
		if !matchesScopeRow(row, asset) {
			t.Errorf("root_domain exclusion did not match %q", asset)
		}
	}
	for _, asset := range []string{"other.example", "notcorp.example", "corp.example.evil.net"} {
		if matchesScopeRow(row, asset) {
			t.Errorf("root_domain exclusion wrongly matched %q", asset)
		}
	}
}

// A subdomain exclusion is exact.
func TestMatchesScopeRowSubdomainIsExact(t *testing.T) {
	row := TaskScope{Kind: "subdomain", Domain: "api.corp.example"}
	if !matchesScopeRow(row, "api.corp.example") {
		t.Error("subdomain exclusion did not match its own host")
	}
	if !matchesScopeRow(row, "https://api.corp.example/login") {
		t.Error("subdomain exclusion did not match a URL on its host")
	}
	if matchesScopeRow(row, "other.corp.example") {
		t.Error("subdomain exclusion matched a sibling host")
	}
}

// An ip/cidr exclusion matches the address it names.
func TestMatchesScopeRowNetwork(t *testing.T) {
	row := TaskScope{Kind: "cidr", Net: "10.1.0.0/16"}
	if !matchesScopeRow(row, "10.1.2.3") {
		t.Error("cidr exclusion did not match an address inside it")
	}
	if matchesScopeRow(row, "10.2.2.3") {
		t.Error("cidr exclusion matched an address outside it")
	}
}

// A kind the guard cannot evaluate must not silently claim to match.
func TestMatchesScopeRowUnenforceableKindDoesNotMatch(t *testing.T) {
	for _, row := range []TaskScope{
		{Kind: "company", CompanyID: new(int64(7))},
		{Kind: "icp", Value: "12345"},
		{Kind: "keyword", Value: "acme"},
	} {
		if matchesScopeRow(row, "api.corp.example") {
			t.Errorf("%q row claimed to match, but the guard cannot enforce that kind", row.Kind)
		}
	}
}

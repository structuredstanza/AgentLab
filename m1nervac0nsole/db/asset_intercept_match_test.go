package db

import "testing"

func rule(kind, pattern string, enabled bool) AssetInterceptRule {
	return AssetInterceptRule{Kind: kind, Pattern: pattern, Enabled: enabled}
}

func TestMatchAssetInterceptRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []AssetInterceptRule
		domains []string
		ips     []string
		urls    []string
		want    bool
		wantVal string
	}{
		{"built-in fuzzy government domain match", []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
			[]string{"www.example.gov.cn"}, nil, nil, true, "www.example.gov.cn"},
		{"fuzzy education domain match", []AssetInterceptRule{rule("fuzzy_domain", ".edu", true)},
			[]string{"mit.edu"}, nil, nil, true, "mit.edu"},
		{"exact domain match is case insensitive", []AssetInterceptRule{rule("exact_domain", "Example.com", true)},
			[]string{"example.com"}, nil, nil, true, "example.com"},
		{"exact domain does not match a subdomain", []AssetInterceptRule{rule("exact_domain", "example.com", true)},
			[]string{"a.example.com"}, nil, nil, false, ""},
		{"exact IP match", []AssetInterceptRule{rule("exact_ip", "203.0.113.5", true)},
			nil, []string{"203.0.113.5"}, nil, true, "203.0.113.5"},
		{"fuzzy IP prefix match", []AssetInterceptRule{rule("fuzzy_ip", "203.0.113.", true)},
			nil, []string{"203.0.113.99"}, nil, true, "203.0.113.99"},
		{"CIDR match", []AssetInterceptRule{rule("cidr", "192.168.0.0/16", true)},
			nil, []string{"192.168.5.20"}, nil, true, "192.168.5.20"},
		{"CIDR does not match", []AssetInterceptRule{rule("cidr", "192.168.0.0/16", true)},
			nil, []string{"10.0.0.1"}, nil, false, ""},
		{"exact URL match", []AssetInterceptRule{rule("exact_url", "https://example.com/login", true)},
			nil, nil, []string{"https://example.com/login"}, true, "https://example.com/login"},
		{"fuzzy URL matches the path", []AssetInterceptRule{rule("fuzzy_url", "/admin", true)},
			nil, nil, []string{"https://x.com/admin/panel"}, true, "https://x.com/admin/panel"},
		{"a disabled rule does not match", []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", false)},
			[]string{"www.gov.cn"}, nil, nil, false, ""},
		{"no rule does not match", nil, []string{"www.gov.cn"}, nil, nil, false, ""},
		{"an empty pattern does not match", []AssetInterceptRule{rule("fuzzy_domain", "  ", true)},
			[]string{"www.gov.cn"}, nil, nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, val, ok := MatchAssetInterceptRules(c.rules, c.domains, c.ips, c.urls)
			if ok != c.want {
				t.Fatalf("matched = %v, want %v (rule=%+v)", ok, c.want, r)
			}
			if ok && val != c.wantVal {
				t.Fatalf("matched value = %q, want %q", val, c.wantVal)
			}
		})
	}
}

func TestEvaluateAssetGate(t *testing.T) {
	block := []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)}
	allow := []AssetInterceptRule{rule("fuzzy_domain", "example.com", true)}

	// 1. Matches a block rule → reject (block reason takes priority).
	if d := EvaluateAssetGate(block, allow, []string{"www.gov.cn"}, nil, nil); d.Allowed {
		t.Fatal("a matching block rule must be rejected")
	}

	// 2. No block match, allow rules exist but none match → reject (not allowed).
	d := EvaluateAssetGate(block, allow, []string{"foo.other.com"}, nil, nil)
	if d.Allowed {
		t.Fatal("a non-matching allowlist must be rejected")
	}
	if d.Reason == "" {
		t.Fatal("a rejection must include a reason")
	}

	// 3. No block match, matches an allow rule → allow.
	if d := EvaluateAssetGate(block, allow, []string{"api.example.com"}, nil, nil); !d.Allowed {
		t.Fatal("a matching allowlist entry must be allowed")
	}

	// 4. No allow rules (allowlist not enabled) → allow if no block match.
	if d := EvaluateAssetGate(block, nil, []string{"foo.other.com"}, nil, nil); !d.Allowed {
		t.Fatal("without an allowlist, an unmatched block must be allowed")
	}

	// 5. All allow rules are disabled → treated as allowlist not enabled, allow.
	disabledAllow := []AssetInterceptRule{rule("fuzzy_domain", "example.com", false)}
	if d := EvaluateAssetGate(nil, disabledAllow, []string{"foo.other.com"}, nil, nil); !d.Allowed {
		t.Fatal("with all allowlist entries disabled, the request must be allowed")
	}

	// 6. Deny takes precedence over allow: if the same target matches both a deny rule and an allow rule, reject it.
	if d := EvaluateAssetGate(
		[]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
		[]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
		[]string{"www.gov.cn"}, nil, nil,
	); d.Allowed {
		t.Fatal("block must take priority over allow")
	}
}

func TestAssetInterceptCandidates(t *testing.T) {
	// Service assets that carry only a URL: the host should be split out and added to the domain candidates, so that it gets matched by fuzzy_domain.
	a := &Asset{Type: "service", URL: "https://portal.example.gov.cn:8443/app"}
	domains, _, urls := a.interceptCandidates()
	if len(urls) != 1 || urls[0] != a.URL {
		t.Fatalf("urls = %v", urls)
	}
	found := false
	for _, d := range domains {
		if d == "portal.example.gov.cn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("URL host was not split into domain candidates: %v", domains)
	}
	r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)}, domains, nil, urls)
	if !ok {
		t.Fatalf("a URL-only government asset must match fuzzy_domain, rule=%+v", r)
	}

	// When the URL host is an IP, it should be placed into the IP candidates so that it can be matched by a CIDR rule.
	b := &Asset{Type: "service", URL: "http://10.1.2.3/x"}
	_, ips, _ := b.interceptCandidates()
	if r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("cidr", "10.0.0.0/8", true)}, nil, ips, nil); !ok {
		t.Fatalf("an IP from a URL must match CIDR, ips=%v rule=%+v", ips, r)
	}

	// A service on an IP literal stores the address in domain and leaves ip
	// empty; it must still reach the IP rules.
	c := &Asset{Type: "service", Domain: "10.0.0.5"}
	domains, ips, _ = c.interceptCandidates()
	if r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("cidr", "10.0.0.0/8", true)}, domains, ips, nil); !ok {
		t.Fatalf("an IP stored in the domain field must match CIDR, domains=%v ips=%v rule=%+v", domains, ips, r)
	}
}

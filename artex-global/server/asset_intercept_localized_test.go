package server

import "testing"

// Validators for asset and task intercept rules reject bad input before any DB access.
func TestAssetInterceptErrorsLocalized(t *testing.T) {
	// Actual path: the four rejection branches in validateAssetInterceptRuleReq
	for _, c := range []struct {
		label string
		req   assetInterceptRuleReq
	}{
		{"empty_pattern", assetInterceptRuleReq{Kind: "exact_ip", Pattern: "   "}},
		{"invalid_exact_ip", assetInterceptRuleReq{Kind: "exact_ip", Pattern: "not-an-ip"}},
		{"invalid_cidr", assetInterceptRuleReq{Kind: "cidr", Pattern: "nonsense"}},
		{"invalid_kind", assetInterceptRuleReq{Kind: "nope", Pattern: "example.com"}},
	} {
		req := c.req
		err := validateAssetInterceptRuleReq(&req)
		if err == nil {
			t.Fatalf("%s: no error (validation passed)", c.label)
		}
	}

	// Valid input is not rejected
	okReq := assetInterceptRuleReq{Kind: "cidr", Pattern: "192.168.0.0/16"}
	if err := validateAssetInterceptRuleReq(&okReq); err != nil {
		t.Fatalf("valid CIDR was rejected: %v", err)
	}

	// Actual path: the action rejection branch in validateTaskInterceptRuleReq
	badAction := taskInterceptRuleReq{Action: "nope", Kind: "exact_domain", Pattern: "example.com"}
	if err := validateTaskInterceptRuleReq(&badAction); err == nil {
		t.Fatalf("bad_action_path: no error (validation passed)")
	}

	// An empty action is normalized to the default block and passes validation
	defaultAction := taskInterceptRuleReq{Action: "", Kind: "exact_domain", Pattern: "example.com"}
	if err := validateTaskInterceptRuleReq(&defaultAction); err != nil {
		t.Fatalf("default action normalization failed: %v", err)
	}
	if defaultAction.Action != "block" {
		t.Fatalf("default action was not normalized to block: %q", defaultAction.Action)
	}
}

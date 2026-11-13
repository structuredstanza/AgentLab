package scope_test

import (
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

func rule(effect scope.Effect, pattern, note string) scope.Rule {
	return scope.Rule{ID: pattern + "/" + string(effect), Effect: effect, Pattern: pattern, Note: note}
}

// The boundary a typical bug-bounty scope table describes, with the two cases
// that actually bite: a wildcard that must cover the apex, and a parked domain
// that must stay excluded.
var engagement = []scope.Rule{
	rule(scope.Include, "*.target.example", ""),
	rule(scope.Include, "target.example", ""),
	rule(scope.Exclude, "parked.example", "parked by the registrar, not the program"),
	rule(scope.Exclude, "*/admin/*", "program policy 1.1: admin paths out of scope"),
}

func verdict(t *testing.T, value string, rules []scope.Rule) scope.Verdict {
	t.Helper()
	return scope.Evaluate(scope.ParseAsset(value), rules)
}

func TestNoRulesIsUnknown(t *testing.T) {
	v := verdict(t, "target.example", nil)
	if v.Status != scope.Unknown {
		t.Fatalf("status = %q, want unknown", v.Status)
	}
	if v.Status == scope.In {
		t.Fatal("an engagement with no rules must not allow anything")
	}
}

func TestWildcardCoversSubdomain(t *testing.T) {
	if v := verdict(t, "api.target.example", engagement); v.Status != scope.In {
		t.Fatalf("status = %q, want in (%s)", v.Status, v.Reason)
	}
}

func TestWildcardCoversApex(t *testing.T) {
	// A program's scope table means the apex too, even though DNS disagrees.
	rules := []scope.Rule{rule(scope.Include, "*.target.example", "")}
	if v := verdict(t, "target.example", rules); v.Status != scope.In {
		t.Fatalf("status = %q, want in", v.Status)
	}
}

func TestWildcardDoesNotMatchLookalike(t *testing.T) {
	if v := verdict(t, "nottarget.example", engagement); v.Status != scope.Unknown {
		t.Fatalf("status = %q, want unknown", v.Status)
	}
	if v := verdict(t, "target.example.evil.test", engagement); v.Status != scope.Unknown {
		t.Fatalf("status = %q, want unknown", v.Status)
	}
}

func TestExclusionWinsOverNarrowerInclude(t *testing.T) {
	rules := []scope.Rule{
		rule(scope.Include, "app.target.example", ""),
		rule(scope.Exclude, "*.target.example", ""),
	}
	if v := verdict(t, "app.target.example", rules); v.Status != scope.Out {
		t.Fatalf("status = %q, want out: an exclusion must not be rescued by a narrower include", v.Status)
	}
}

func TestExclusionNamesItsNote(t *testing.T) {
	v := verdict(t, "parked.example", engagement)
	if v.Status != scope.Out {
		t.Fatalf("status = %q, want out", v.Status)
	}
	if v.Reason == "" || !contains(v.Reason, "parked by the registrar") {
		t.Fatalf("reason = %q, want the rule's note", v.Reason)
	}
}

func TestURLInheritsHostVerdict(t *testing.T) {
	if v := verdict(t, "https://api.target.example/v1/users", engagement); v.Status != scope.In {
		t.Fatalf("status = %q, want in", v.Status)
	}
}

func TestPathGlobExcludesEvenWhenHostIsInScope(t *testing.T) {
	v := verdict(t, "https://api.target.example/admin/users", engagement)
	if v.Status != scope.Out {
		t.Fatalf("status = %q, want out by path", v.Status)
	}
}

func TestPathGlobDoesNotMatchOtherPaths(t *testing.T) {
	if v := verdict(t, "https://api.target.example/api/users", engagement); v.Status != scope.In {
		t.Fatalf("status = %q, want in", v.Status)
	}
}

func TestIPInsideCIDR(t *testing.T) {
	rules := []scope.Rule{rule(scope.Include, "10.20.0.0/16", "")}
	if v := verdict(t, "10.20.5.9", rules); v.Status != scope.In {
		t.Fatalf("status = %q, want in", v.Status)
	}
	if v := verdict(t, "10.21.5.9", rules); v.Status != scope.Unknown {
		t.Fatalf("status = %q, want unknown", v.Status)
	}
}

func TestCIDRMustBeFullyContained(t *testing.T) {
	rules := []scope.Rule{rule(scope.Include, "10.20.0.0/16", "")}
	if v := verdict(t, "10.20.4.0/24", rules); v.Status != scope.In {
		t.Fatalf("a contained range: status = %q, want in", v.Status)
	}
	// A partly overlapping range is not authorized: the rule covers what the
	// operator named, not a superset of it.
	if v := verdict(t, "10.0.0.0/8", rules); v.Status != scope.Unknown {
		t.Fatalf("an overlapping range: status = %q, want unknown", v.Status)
	}
}

func TestHostnameRuleIgnoresIP(t *testing.T) {
	if v := verdict(t, "10.20.5.9", engagement); v.Status != scope.Unknown {
		t.Fatalf("status = %q, want unknown", v.Status)
	}
}

func TestProblemRejectsPolicyAsScope(t *testing.T) {
	// The failure this exists to prevent: an agent reads a program's
	// out-of-scope section and files a kind of bug as a rule.
	for _, bad := range []string{"class:dos-flooding", "device:remaining-functions", "asset:brand-products"} {
		if err := scope.Problem(bad); err == nil {
			t.Errorf("Problem(%q) = nil, want a rejection", bad)
		}
	}
}

func TestProblemAcceptsRealAssets(t *testing.T) {
	for _, good := range []string{
		"target.example", "*.target.example", "10.20.0.0/16",
		"*/admin/*", "https://app.target.example/admin", "localhost",
	} {
		if err := scope.Problem(good); err != nil {
			t.Errorf("Problem(%q) = %v, want nil", good, err)
		}
	}
}

func TestProblemRejectsWildcardEverything(t *testing.T) {
	for _, bad := range []string{"*", "*.", ""} {
		if err := scope.Problem(bad); err == nil {
			t.Errorf("Problem(%q) = nil, want a rejection", bad)
		}
	}
}

func TestParseAssetDerivesShape(t *testing.T) {
	cases := []struct {
		in    string
		value string
		host  string
		isURL bool
	}{
		{"API.Target.Example", "api.target.example", "api.target.example", false},
		{"https://API.target.example:8443/x?y=1", "https://api.target.example:8443/x?y=1", "api.target.example", true},
		{"10.20.5.9", "10.20.5.9", "", false},
		{"10.20.0.0/16", "10.20.0.0/16", "", false},
	}
	for _, c := range cases {
		a := scope.ParseAsset(c.in)
		if a.Value != c.value || a.Host != c.host || a.IsURL != c.isURL {
			t.Errorf("ParseAsset(%q) = %+v, want value=%q host=%q isURL=%v", c.in, a, c.value, c.host, c.isURL)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

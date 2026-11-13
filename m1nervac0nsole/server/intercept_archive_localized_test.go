package server

import (
	"net/url"
	"testing"
)

// TestInterceptArchiveErrorsLocalized checks that the pure validators in intercept.go and task_archives.go reject bad input.
func TestInterceptArchiveErrorsLocalized(t *testing.T) {
	// intercept.go: interceptFilterParams — query-string validation.
	if _, err := interceptFilterParams(url.Values{"status": {"bogus"}}); err == nil {
		t.Fatal("status validation must not pass")
	}
	if _, err := interceptFilterParams(url.Values{"decision_source": {"bogus"}}); err == nil {
		t.Fatal("decision_source validation must not pass")
	}

	// intercept.go: validateInterceptRuleReq — each branch isolated by making the
	// earlier fields valid.
	ruleCases := []struct {
		label string
		req   interceptRuleReq
	}{
		{"rule.name", interceptRuleReq{Name: ""}},
		{"rule.match_target", interceptRuleReq{Name: "r", MatchTarget: "bad"}},
		{"rule.match_type", interceptRuleReq{Name: "r", MatchTarget: "tool_name", MatchType: "bad"}},
		{"rule.pattern_empty", interceptRuleReq{Name: "r", MatchTarget: "tool_name", MatchType: "string", Pattern: ""}},
		{"rule.action", interceptRuleReq{Name: "r", MatchTarget: "tool_name", MatchType: "string", Pattern: "p", Action: "bad"}},
		{"rule.regex", interceptRuleReq{Name: "r", MatchTarget: "tool_name", MatchType: "regex", Pattern: "(", Action: "allow"}},
	}
	for _, tc := range ruleCases {
		if err := validateInterceptRuleReq(tc.req); err == nil {
			t.Fatalf("%s: validation must not pass", tc.label)
		}
	}

	// task_archives.go: normalizeArchiveIDs — batch id validation.
	if _, err := normalizeArchiveIDs(nil); err == nil {
		t.Fatal("empty archive_ids validation must not pass")
	}
	tooMany := make([]int64, 101)
	for i := range tooMany {
		tooMany[i] = int64(i + 1)
	}
	if _, err := normalizeArchiveIDs(tooMany); err == nil {
		t.Fatal("validation of 101 archive_ids must not pass")
	}
	if _, err := normalizeArchiveIDs([]int64{0}); err == nil {
		t.Fatal("validation of archive id 0 must not pass")
	}

	// task_archives.go: validateArchivePath — package path validation.
	if err := validateArchivePath("/tmp/m1nervac0nsole-data", ""); err == nil {
		t.Fatal("validation of an empty archive path must not pass")
	}
	if err := validateArchivePath("/tmp/m1nervac0nsole-data", "/etc/passwd"); err == nil {
		t.Fatal("validation of a path outside the managed directory must not pass")
	}
}

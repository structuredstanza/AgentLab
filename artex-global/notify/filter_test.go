package notify

import "testing"

func TestParseFilterMalformedFallsBackToMatchAll(t *testing.T) {
	// Malformed JSON, empty input, and fields of the wrong type must all degrade to a zero-value Filter,
	// meaning "no filtering." This invariant is where the principle "better to over-deliver than to drop" is enforced:
	// if this ever changes to return an error or a partial parse, a single mistyped character from the user would silently drop all high-risk notifications.
	cases := []struct {
		name string
		raw  string
	}{
		{"空输入", ""},
		{"非法 JSON", `{not json`},
		{"截断的 JSON", `{"min_severity":`},
		{"类型不匹配", `{"min_severity": 123, "task_ids": "abc"}`},
		{"顶层是数组", `[1,2,3]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ParseFilter([]byte(tc.raw))
			if f.MinSeverity != "" || len(f.TaskIDs) != 0 || len(f.AssetIDs) != 0 {
				t.Fatalf("a malformed config must degrade to a zero-value Filter, got %+v", f)
			}
			// A zero-value Filter must match any event.
			ev := Snapshot{Kind: EventFindingCreated, Severity: "low", VulnClass: "XSS"}
			if !Match(f, ev) {
				t.Fatal("a zero-value Filter must match every event")
			}
		})
	}
}

func TestMatchSeverityThreshold(t *testing.T) {
	ev := func(sev string) Snapshot {
		return Snapshot{Kind: EventFindingCreated, Severity: sev}
	}
	cases := []struct {
		min    string
		sev    string
		expect bool
	}{
		{"", "low", true},
		{"", "critical", true},
		{"high", "critical", true},
		{"high", "high", true},
		{"high", "medium", false},
		{"high", "low", false},
		{"critical", "high", false},
		{"critical", "critical", true},
		// Unknown severity ordinal is 0, so it should be blocked by any non-empty threshold (when in doubt, do not push).
		{"low", "", false},
		{"low", "unknown", false},
		{"", "", true},
	}
	for _, tc := range cases {
		got := Match(Filter{MinSeverity: tc.min}, ev(tc.sev))
		if got != tc.expect {
			t.Errorf("min=%q sev=%q: expected %v, got %v", tc.min, tc.sev, tc.expect, got)
		}
	}
}

func TestMatchScopeRestrictions(t *testing.T) {
	ev := Snapshot{
		Kind:      EventFindingCreated,
		Severity:  "high",
		TaskID:    7,
		AssetIDs:  []int64{10, 20},
		VulnClass: "SQL注入",
	}
	cases := []struct {
		name   string
		filter Filter
		expect bool
	}{
		{"空范围=不限", Filter{}, true},
		{"任务命中", Filter{TaskIDs: []int64{7}}, true},
		{"任务未命中", Filter{TaskIDs: []int64{8}}, false},
		{"任务多选含命中", Filter{TaskIDs: []int64{8, 7}}, true},
		{"资产有交集", Filter{AssetIDs: []int64{20, 99}}, true},
		{"资产无交集", Filter{AssetIDs: []int64{99}}, false},
		{"任务与资产同时命中", Filter{TaskIDs: []int64{7}, AssetIDs: []int64{10}}, true},
		{"任务命中但资产未命中", Filter{TaskIDs: []int64{7}, AssetIDs: []int64{99}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.filter, ev); got != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, got)
			}
		})
	}
}

func TestMatchVulnClassKeywords(t *testing.T) {
	ev := func(class string) Snapshot {
		return Snapshot{Kind: EventFindingCreated, Severity: "high", VulnClass: class}
	}
	cases := []struct {
		name   string
		filter Filter
		class  string
		expect bool
	}{
		{"include 为空=全收", Filter{}, "任意类型", true},
		{"include 命中", Filter{VulnClassInclude: []string{"SQL"}}, "SQL注入", true},
		{"include 未命中", Filter{VulnClassInclude: []string{"命令执行"}}, "SQL注入", false},
		{"include 多词任一命中", Filter{VulnClassInclude: []string{"命令执行", "SQL"}}, "SQL注入", true},
		{"大小写不敏感", Filter{VulnClassInclude: []string{"sql"}}, "SQL注入", true},
		{"exclude 命中即排除", Filter{VulnClassExclude: []string{"信息泄露"}}, "信息泄露", false},
		{"exclude 未命中则放行", Filter{VulnClassExclude: []string{"信息泄露"}}, "SQL注入", true},
		// Exclusion takes precedence over inclusion: when both match, the item should be filtered out.
		{"排除优先于包含", Filter{
			VulnClassInclude: []string{"SQL"},
			VulnClassExclude: []string{"注入"},
		}, "SQL注入", false},
		// Keywords that are pure whitespace should be ignored; otherwise they would degrade into "matching every string that contains a space".
		{"空白关键词被忽略", Filter{VulnClassInclude: []string{"", "  "}}, "SQL注入", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.filter, ev(tc.class)); got != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, got)
			}
		})
	}
}

func TestMatchStatusChangeRequiresOptIn(t *testing.T) {
	ev := Snapshot{Kind: EventFindingStatusChanged, Severity: "critical", FromStatus: "pending", ToStatus: "fixed"}
	// Off by default: what most people mean by "push vulnerabilities" is discovering new vulnerabilities, not a ledger of status changes.
	if Match(Filter{MinSeverity: "low"}, ev) {
		t.Fatal("status-change event must be skipped when not enabled")
	}
	if !Match(Filter{OnStatusChange: true}, ev) {
		t.Fatal("status-change event must match when on_status_change is enabled")
	}
	// Creating events is not affected by on_status_change.
	created := Snapshot{Kind: EventFindingCreated, Severity: "critical"}
	if !Match(Filter{MinSeverity: "low"}, created) {
		t.Fatal("created events must not depend on on_status_change")
	}
}

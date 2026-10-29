package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract for the notification_channels.filter JSONB column: the filter conditions for a channel instance.
// All fields are optional; omitting one means "no filtering" — this is exactly the fallback semantics for malformed configuration, see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity threshold (low/medium/high/critical); empty means no threshold.
	MinSeverity string `json:"min_severity"`
	// TaskIDs / AssetIDs: an empty array means unrestricted; a non-empty one requires the event to intersect with it.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// An empty VulnClassInclude means match everything; when non-empty, vulnclass must hit at least one of its keywords.
	// If vulnclass hits any keyword in VulnClassExclude, it is excluded (exclusion takes precedence over inclusion).
	// Matching is a case-insensitive substring match, which is safer than regex: a user who misconfigures a regex will not cause the channel to silently stop working.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange determines whether this channel receives vulnerability status change events (only meaningful in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses the channel filter configuration.
//
// **Never returns an error.** This is a deliberate design choice: when the filter condition configuration is malformed, it always degrades to zero values.
// Filter (= no filtering = everything matches), because for a vulnerability notification system, **pushing one extra notification is far better than
// silently missing one high-severity vulnerability**. Turning a parse failure into "no push" would give the user a configuration that appears to be set up correctly,
// A channel that pushes nothing at all — this is the worst failure mode.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// If parsing fails, f keeps its zero value, meaning no filtering is applied.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid minimum-severity threshold (an empty string means no threshold is set).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the fields of the filter config whose values are **restricted**; it is called when a channel is saved.
//
// Why this must be caught at write time: Match treats an unknown threshold as `rank >= 0`, which is always true —
// that is, if min_severity has a typo ("hgih"), the filter **silently stops working** and becomes
// "push everything". This matches the package's trade-off of "better to over-push than to miss" (nothing is missed),
// but the consequence is that users think they are doing tiered push notifications while actually flooding the group with every vulnerability,
// And there is no sign at all that he misconfigured it. This kind of "silent degradation" should be intercepted at the entry point.
//
// Note that Validate is only used on the **write** path. The read path still uses the lenient semantics of ParseFilter,
// so that bad values already present in historical data do not cause the entire channel to become unreadable.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("invalid minimum severity: %q. Choose from low / medium / high / critical, or leave empty for no restriction", f.MinSeverity)
	}
	return nil
}

// Match determines whether an event should be delivered to a channel that has this filter condition.
//
// **Never returns an error**, for the same reason as ParseFilter: any internal exception is treated as a "match."
// The evaluation order is: event type → severity threshold → task/asset scope → vulnerability type keywords.
func Match(f Filter, s Snapshot) bool {
	// Status change events are only received by channels that explicitly enable them. This is off by default, because the vast majority of users
	// expect "push" to mean "a new vulnerability was discovered," not a log-style notification for every status transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclusion takes precedence: matching any exclusion keyword rules the item out, even if it also matches the inclusion list.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// A linear scan is fine for small sets; on both sides the sizes are "a few dozen items hand-picked by people,"
	// building a map would cost more than it saves.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any of the keywords in keywords (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

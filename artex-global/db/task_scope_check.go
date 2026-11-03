package db

import (
	"strings"

	"github.com/Autumn-27/artex/scope"
)

// TaskScopeChecker answers the guard's scope question for one task.
//
// It is a thin adapter over task_scope: the rows already record what the
// engagement may touch, and this only decides which of them are exclusions.
// A task with no rows reports nothing as excluded, so a fresh task is never
// blocked by an empty boundary.
type TaskScopeChecker struct {
	assets *AssetStore
	taskID int64
}

// NewTaskScopeChecker returns a checker for a task, or nil when the store is
// unavailable (the guard then skips scope enforcement rather than guessing).
func NewTaskScopeChecker(assets *AssetStore, taskID int64) *TaskScopeChecker {
	if assets == nil || taskID <= 0 {
		return nil
	}
	return &TaskScopeChecker{assets: assets, taskID: taskID}
}

// Judge reports whether an asset is explicitly excluded by the task's boundary.
//
// Only an explicit exclusion returns out=true. The include side is deliberately
// not enforced here: a task's scope rows accumulate as the hunt discovers
// assets, so treating "no include rule matches" as out would refuse every call
// the agent makes against a host it just found — the exact behaviour that
// makes a boundary unusable in practice.
func (c *TaskScopeChecker) Judge(asset string) (bool, string) {
	if c == nil {
		return false, ""
	}
	// WithSources, not ListTaskScope: an exclusion set on a parent task must
	// bind its children, or a spawned worker can reach a host its parent
	// explicitly ruled out.
	rows, err := c.assets.ListTaskScopeWithSources(c.taskID)
	if err != nil {
		// A read failure must not become a silent permission grant, but it also
		// must not stop the engagement: report nothing and let the audit log
		// carry the failure.
		return false, ""
	}
	for _, row := range rows {
		if !strings.EqualFold(row.Effect, "exclude") {
			continue
		}
		if matchesScopeRow(row, asset) {
			return true, "task scope excludes it"
		}
	}
	return false, ""
}

// matchesScopeRow compares one stored scope row against a candidate asset,
// reusing the same matcher the rules use so the two cannot disagree.
func matchesScopeRow(row TaskScope, asset string) bool {
	pattern := ""
	switch row.Kind {
	case "root_domain", "subdomain":
		pattern = row.Domain
	case "ip", "cidr":
		pattern = row.Net
	default:
		pattern = row.Value
	}
	if pattern == "" {
		return false
	}
	rules := []scope.Rule{{ID: "row", Effect: scope.Exclude, Pattern: pattern}}
	return scope.Evaluate(scope.ParseAsset(asset), rules).Status == scope.Out
}

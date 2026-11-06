package db

import (
	"log"
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
		// "Could not verify" is not "allowed". The previous behaviour returned
		// false with a comment claiming the audit log would carry the failure,
		// but nothing logged and nothing recorded, so a transient database
		// error silently permitted every call — and /api/audit showed an
		// ordinary allow. Refuse the call instead and say why; the worker sees
		// the reason and can retry once the database recovers.
		log.Printf("[scope] task %d: cannot read the task scope, refusing the call: %v", c.taskID, err)
		return true, "the task scope could not be read, so this call was not verified: " + err.Error()
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
//
// A root_domain row covers its whole subtree — that is what the kind means
// everywhere else in the system (`a.root_domain = ts.domain` in SQL, and the
// tool description's "a whole root domain, including all subdomains"). Passing
// the bare apex as the pattern made hostnameMatch require exact equality, so
// excluding corp.example blocked corp.example and allowed api.corp.example.
func matchesScopeRow(row TaskScope, asset string) bool {
	pattern := ""
	switch row.Kind {
	case "root_domain":
		if row.Domain == "" {
			return false
		}
		pattern = "*." + row.Domain
		// The apex itself is part of the subtree.
		if strings.EqualFold(strings.TrimSuffix(scope.ParseAsset(asset).Host, "."), strings.TrimSuffix(row.Domain, ".")) {
			return true
		}
	case "subdomain":
		pattern = row.Domain
	case "ip", "cidr":
		pattern = row.Net
	default:
		// company / icp / keyword are matched in SQL against asset columns; the
		// guard's host matcher cannot express them. AddAgentScope refuses to
		// store one as an exclusion, so reaching this means a row was written by
		// hand or restored from an archive.
		log.Printf("[scope] task %d: ignoring %q scope row #%d as an exclusion: this kind cannot be enforced by the tool guard", row.TaskID, row.Kind, row.ID)
		return false
	}
	if pattern == "" {
		return false
	}
	rules := []scope.Rule{{ID: "row", Effect: scope.Exclude, Pattern: pattern}}
	return scope.Evaluate(scope.ParseAsset(asset), rules).Status == scope.Out
}

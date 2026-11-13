package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// The reflection engine turns what actually happened into a small, stable set
// of reflections: one per signal per intent or task. Every signal below is
// computed from rows that exist (activity, yields edges, findings, tool_usage,
// skill_usage); nothing is invented, and a second run for the same intent or
// task adds nothing because the dedupe key is the signal identity.
//
// What the intent -> activity link is: a worker run stamps activity.node_id
// with the intent it is working on (agent/worker.go), so activity rows are the
// per-intent record. Intercept denials are not linked to an intent in
// intercept_pending (that table only knows the task as text), so the opsec
// signal is read from the denial text the guard and interceptor write into the
// intent's own tool_result rows.

const (
	noiseMinCallsForErrorRate = 5
	noiseErrorRateThreshold   = 0.4
	noiseDuplicateRepeats     = 3
	noiseMinCallsForNoYield   = 8
	taskFindingQualityMin     = 3
	taskFindingQualityRatio   = 0.3
	engineReasonMax           = 120
	engineReasonsMax          = 5
)

// denialMarkers are the platform-side block messages. Lowercase on purpose:
// the comparison is case-insensitive.
var denialMarkers = []string{
	"[platform control - not target defense]",
	"cannot be executed under intercept rule",
	"a person denied execution",
	"approval timed out",
}

type intentActivityRow struct {
	tool    string
	isError bool
	summary string
	detail  string
}

// taskExplorationID resolves the exploration of a live task.
func (d *DB) taskExplorationID(ctx context.Context, taskID int64) (int64, error) {
	var expID int64
	err := d.QueryRowContext(ctx,
		`SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&expID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("task %d: %w", taskID, sql.ErrNoRows)
	}
	if err != nil {
		return 0, fmt.Errorf("task %d: %w", taskID, err)
	}
	return expID, nil
}

// intentActivity loads one intent's tool calls and tool results, oldest first.
func (d *DB) intentActivity(ctx context.Context, expID, intentID int64) (uses, results []intentActivityRow, err error) {
	rows, err := d.QueryContext(ctx, `
SELECT kind, COALESCE(tool,''), is_error, COALESCE(summary,''), COALESCE(detail,'')
FROM activity
WHERE exploration_id=$1 AND node_id=$2 AND kind IN ('tool_use','tool_result')
ORDER BY id`, expID, intentID)
	if err != nil {
		return nil, nil, fmt.Errorf("intent activity: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var r intentActivityRow
		if err := rows.Scan(&kind, &r.tool, &r.isError, &r.summary, &r.detail); err != nil {
			return nil, nil, fmt.Errorf("intent activity: %w", err)
		}
		if kind == "tool_use" {
			uses = append(uses, r)
		} else {
			results = append(results, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("intent activity: %w", err)
	}
	return uses, results, nil
}

// intentYields counts the fact and finding nodes the intent yielded.
func (d *DB) intentYields(ctx context.Context, expID, intentID int64) (map[string]int, error) {
	rows, err := d.QueryContext(ctx, `
SELECT n.kind, count(*)
FROM exploration_edges e
JOIN exploration_nodes n ON n.id=e.dst_id AND n.exploration_id=e.exploration_id
WHERE e.exploration_id=$1 AND e.src_id=$2 AND e.rel='yields'
GROUP BY n.kind`, expID, intentID)
	if err != nil {
		return nil, fmt.Errorf("intent yields: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("intent yields: %w", err)
		}
		out[kind] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intent yields: %w", err)
	}
	return out, nil
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// shortHash fingerprints a request line so a signal can point at it without
// storing the command itself.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(s), " "))))
	return hex.EncodeToString(sum[:8])
}

// topTool returns the most frequent key, breaking ties alphabetically so the
// result is deterministic.
func topTool(counts map[string]int) string {
	best, bestN := "", -1
	for k, n := range counts {
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

func hasDenialMarker(text string) bool {
	lower := strings.ToLower(text)
	for _, m := range denialMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// DeriveIntentReflections derives the end-of-batch reflections of one intent.
// It is deterministic and idempotent; the return value is the number of
// reflections this call created (a second run returns 0).
func (d *DB) DeriveIntentReflections(ctx context.Context, taskID, intentID int64) (int, error) {
	if taskID <= 0 || intentID <= 0 {
		return 0, fmt.Errorf("derive intent reflections needs task and intent ids: %w", ErrMemoryInvalid)
	}
	expID, err := d.taskExplorationID(ctx, taskID)
	if err != nil {
		return 0, err
	}
	var nodeKind string
	err = d.QueryRowContext(ctx,
		`SELECT kind FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`, intentID, expID).Scan(&nodeKind)
	if errors.Is(err, sql.ErrNoRows) {
		// An intent of another task is a bad argument, not a missing row.
		var otherExp int64
		if err2 := d.QueryRowContext(ctx,
			`SELECT exploration_id FROM exploration_nodes WHERE id=$1 AND kind='intent'`, intentID).Scan(&otherExp); err2 == nil {
			return 0, fmt.Errorf("intent %d belongs to another task: %w", intentID, ErrMemoryInvalid)
		}
		return 0, fmt.Errorf("intent %d of task %d: %w", intentID, taskID, sql.ErrNoRows)
	}
	if err != nil {
		return 0, fmt.Errorf("derive intent reflections: %w", err)
	}
	if nodeKind != "intent" {
		return 0, fmt.Errorf("node %d is %q, not an intent: %w", intentID, nodeKind, ErrMemoryInvalid)
	}

	uses, results, err := d.intentActivity(ctx, expID, intentID)
	if err != nil {
		return 0, err
	}
	yielded, err := d.intentYields(ctx, expID, intentID)
	if err != nil {
		return 0, err
	}

	created := 0
	add := func(kind, key, summary, detail string, signal map[string]any) error {
		_, ok, err := d.AddReflection(ctx, ReflectionInput{
			TaskID: taskID, IntentID: intentID, Kind: kind, Source: "engine",
			DedupeKey: key, Summary: summary, Detail: detail, Signal: signal,
		})
		if err != nil {
			return err
		}
		if ok {
			created++
		}
		return nil
	}

	// noise: tool-call error rate.
	if len(results) >= noiseMinCallsForErrorRate {
		errs := 0
		perTool := map[string]int{}
		for _, r := range results {
			if r.isError {
				errs++
				perTool[r.tool]++
			}
		}
		rate := float64(errs) / float64(len(results))
		if rate >= noiseErrorRateThreshold {
			top := topTool(perTool)
			if top == "" {
				top = "unknown"
			}
			if err := add("noise", fmt.Sprintf("intent:%d:tool-error-rate", intentID),
				fmt.Sprintf("%d of %d tool calls failed (%.0f%%); top failing tool: %s", errs, len(results), rate*100, top),
				"Repeated failing calls burn the batch; fix the invocation or stop the approach instead of retrying it.",
				map[string]any{"tool_calls": len(results), "errors": errs, "error_rate": round2(rate), "top_failing_tool": top}); err != nil {
				return created, err
			}
		}
	}

	// noise: identical requests repeated inside the intent.
	if len(uses) > 0 {
		seen := map[string]int{}
		worstKey, worstN := "", 0
		for _, u := range uses {
			key := u.tool + "|" + strings.ToLower(strings.Join(strings.Fields(u.summary), " "))
			seen[key]++
			if seen[key] > worstN {
				worstKey, worstN = key, seen[key]
			}
		}
		if worstN >= noiseDuplicateRepeats {
			tool, summary, _ := strings.Cut(worstKey, "|")
			if err := add("noise", fmt.Sprintf("intent:%d:duplicate-requests", intentID),
				fmt.Sprintf("%s repeated %d times with the same request; top repeated: %s", tool, worstN, memoryLine(summary, engineReasonMax)),
				"An identical request that already failed or returned nothing will not behave differently; change the approach.",
				map[string]any{"repeats": worstN, "tool": tool, "request_sha256": shortHash(summary)}); err != nil {
				return created, err
			}
		}
	}

	// noise: a long intent that produced no fact and no finding.
	if len(uses) >= noiseMinCallsForNoYield && yielded["fact"]+yielded["finding"] == 0 {
		if err := add("noise", fmt.Sprintf("intent:%d:no-yield", intentID),
			fmt.Sprintf("%d tool calls produced no fact and no finding", len(uses)),
			"The intent spent its budget without yielding anything reusable; split it or narrow it to one testable question.",
			map[string]any{"tool_calls": len(uses), "facts": 0, "findings": 0}); err != nil {
			return created, err
		}
	}

	// opsec: platform-side denials recorded in this intent's tool results.
	var reasons []string
	deniedTools := map[string]int{}
	for _, r := range results {
		if !hasDenialMarker(r.summary) && !hasDenialMarker(r.detail) {
			continue
		}
		deniedTools[r.tool]++
		reason := memoryLine(r.summary, engineReasonMax)
		if reason == "" {
			reason = memoryLine(r.detail, engineReasonMax)
		}
		dup := false
		for _, have := range reasons {
			if have == reason {
				dup = true
				break
			}
		}
		if !dup && reason != "" && len(reasons) < engineReasonsMax {
			reasons = append(reasons, reason)
		}
	}
	if len(deniedTools) > 0 {
		denials := 0
		for _, n := range deniedTools {
			denials += n
		}
		tools := make([]string, 0, len(deniedTools))
		for t := range deniedTools {
			tools = append(tools, t)
		}
		sort.Strings(tools)
		if err := add("opsec", fmt.Sprintf("intent:%d:guard-denials", intentID),
			fmt.Sprintf("%d tool calls were blocked by the platform during this intent", denials),
			"Denial reasons: "+strings.Join(reasons, " | "),
			map[string]any{"denials": denials, "tools": tools, "reasons": reasons}); err != nil {
			return created, err
		}
	}

	return created, nil
}

// DeriveTaskReflections derives the task-level reflections from the task's
// findings, tool usage and skill usage. Deterministic and idempotent; returns
// the number of reflections this call created.
func (d *DB) DeriveTaskReflections(ctx context.Context, taskID int64) (int, error) {
	if taskID <= 0 {
		return 0, fmt.Errorf("derive task reflections needs a task id: %w", ErrMemoryInvalid)
	}
	if _, err := d.taskExplorationID(ctx, taskID); err != nil {
		return 0, err
	}

	statuses := map[string]int{}
	rows, err := d.QueryContext(ctx, `SELECT status, count(*) FROM findings WHERE task_id=$1 GROUP BY status`, taskID)
	if err != nil {
		return 0, fmt.Errorf("derive task reflections: %w", err)
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return 0, fmt.Errorf("derive task reflections: %w", err)
		}
		statuses[status] = n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("derive task reflections: %w", err)
	}
	rows.Close()

	var calls int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM tool_usage WHERE task_id=$1`, taskID).Scan(&calls); err != nil {
		return 0, fmt.Errorf("derive task reflections: %w", err)
	}

	missRows, err := d.QueryContext(ctx, `
SELECT skill, count(*) FROM skill_usage
WHERE task_id=$1 AND NOT found
GROUP BY skill ORDER BY count(*) DESC, skill`, taskID)
	if err != nil {
		return 0, fmt.Errorf("derive task reflections: %w", err)
	}
	var misses int
	var missedSkills []string
	for missRows.Next() {
		var skill string
		var n int
		if err := missRows.Scan(&skill, &n); err != nil {
			missRows.Close()
			return 0, fmt.Errorf("derive task reflections: %w", err)
		}
		misses += n
		missedSkills = append(missedSkills, skill)
	}
	if err := missRows.Err(); err != nil {
		missRows.Close()
		return 0, fmt.Errorf("derive task reflections: %w", err)
	}
	missRows.Close()

	created := 0
	add := func(kind, key, summary, detail string, signal map[string]any) error {
		_, ok, err := d.AddReflection(ctx, ReflectionInput{
			TaskID: taskID, Kind: kind, Source: "engine",
			DedupeKey: key, Summary: summary, Detail: detail, Signal: signal,
		})
		if err != nil {
			return err
		}
		if ok {
			created++
		}
		return nil
	}

	total, rejected, confirmed := 0, 0, 0
	for status, n := range statuses {
		total += n
		switch status {
		case "false_positive", "duplicate", "ignored", "risk_accepted":
			rejected += n
		case "confirmed", "resolved", "fixed":
			confirmed += n
		}
	}

	// noise: the findings the task reported were mostly rejected.
	if total >= taskFindingQualityMin {
		ratio := float64(rejected) / float64(total)
		if ratio >= taskFindingQualityRatio {
			if err := add("noise", "task:finding-quality",
				fmt.Sprintf("%d of %d findings were rejected as false positive, duplicate or ignored", rejected, total),
				"Review what looked reportable but was not; tighten the evidence bar before reporting.",
				map[string]any{"findings": total, "rejected": rejected, "confirmed": confirmed, "rejected_ratio": round2(ratio)}); err != nil {
				return created, err
			}
		}
	}

	// learning: how expensive one confirmed finding was.
	if confirmed > 0 && calls > 0 {
		perFinding := float64(calls) / float64(confirmed)
		if err := add("learning", "task:calls-per-finding",
			fmt.Sprintf("%d tool calls produced %d confirmed findings (%.1f calls per finding)", calls, confirmed, perFinding),
			"Cost per confirmed finding; compare against later runs of the same task shape.",
			map[string]any{"tool_calls": calls, "confirmed": confirmed, "calls_per_finding": round2(perFinding)}); err != nil {
			return created, err
		}
	}

	// lookfor: skills the model wanted but did not have.
	if misses > 0 {
		if err := add("lookfor", "task:skill-misses",
			fmt.Sprintf("%d skill misses (skills: %s)", misses, strings.Join(missedSkills, ", ")),
			"No matching skill was available for these requests; record the capability gap and add the skill if it recurs.",
			map[string]any{"misses": misses, "skills": missedSkills}); err != nil {
			return created, err
		}
	}

	return created, nil
}

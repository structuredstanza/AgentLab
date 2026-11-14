package db

import (
	"fmt"
	"strconv"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

// TaskScopeRule is one operator-written boundary line, stored beside the rows
// the hunt accumulates.
type TaskScopeRule struct {
	ID        int64  `json:"id"`
	TaskID    int64  `json:"task_id"`
	Effect    string `json:"effect"`
	Pattern   string `json:"pattern"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

// ListTaskScopeRules returns the task's rules in the shape the matcher takes.
//
// Rules are the explicit layer: they are consulted before the accumulated
// task_scope rows, so an operator who writes "include api.corp.example" is
// obeyed even when a broad row excludes corp.example.
func (s *AssetStore) ListTaskScopeRules(taskID int64) ([]scope.Rule, error) {
	// The task's own rules and those of its explicit source tasks, exactly like
	// the rows: an exclusion an operator wrote on a parent engagement must bind
	// the child it spawned, or a worker can reach a host the parent ruled out.
	rows, err := s.db.Query(`WITH `+directTaskContextCTE+`
SELECT r.id, r.effect, r.pattern, r.note
FROM task_scope_rules r JOIN context_tasks ctx ON ctx.task_id=r.task_id
ORDER BY (r.task_id=$1) DESC, r.id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list scope rules: %w", err)
	}
	defer rows.Close()
	var out []scope.Rule
	for rows.Next() {
		var (
			id                    int64
			effect, pattern, note string
		)
		if err := rows.Scan(&id, &effect, &pattern, &note); err != nil {
			return nil, fmt.Errorf("list scope rules: %w", err)
		}
		out = append(out, scope.Rule{ID: strconv.FormatInt(id, 10), Effect: scope.Effect(effect), Pattern: pattern, Note: note})
	}
	return out, rows.Err()
}

// AddTaskScopeRule stores one rule and returns its id.
func (s *AssetStore) AddTaskScopeRule(taskID int64, effect, pattern, note string) (int64, error) {
	if taskID <= 0 {
		return 0, fmt.Errorf("scope rule needs a task")
	}
	if effect != string(scope.Include) && effect != string(scope.Exclude) {
		return 0, fmt.Errorf("effect must be include or exclude, got %q", effect)
	}
	if pattern == "" {
		return 0, fmt.Errorf("pattern is empty")
	}
	var id int64
	if err := s.db.QueryRow(`INSERT INTO task_scope_rules(task_id, effect, pattern, note)
VALUES ($1,$2,$3,$4) RETURNING id`, taskID, effect, pattern, note).Scan(&id); err != nil {
		return 0, fmt.Errorf("add scope rule: %w", err)
	}
	return id, nil
}

// DeleteTaskScopeRule removes one rule.
func (s *AssetStore) DeleteTaskScopeRule(taskID, id int64) error {
	res, err := s.db.Exec(`DELETE FROM task_scope_rules WHERE id=$1 AND task_id=$2`, id, taskID)
	if err != nil {
		return fmt.Errorf("delete scope rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("scope rule %d not found", id)
	}
	return nil
}

// ListTaskScopeRuleRows returns the rules with their metadata for the API.
func (s *AssetStore) ListTaskScopeRuleRows(taskID int64) ([]TaskScopeRule, error) {
	rows, err := s.db.Query(`SELECT id, task_id, effect, pattern, note, created_at::text
FROM task_scope_rules WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list scope rules: %w", err)
	}
	defer rows.Close()
	out := []TaskScopeRule{}
	for rows.Next() {
		var r TaskScopeRule
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Effect, &r.Pattern, &r.Note, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("list scope rules: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateTaskScopeRule rewrites one rule in place, so an operator can correct a
// pattern without losing the row's identity in the audit trail.
func (s *AssetStore) UpdateTaskScopeRule(taskID, id int64, effect, pattern, note string) error {
	if effect != string(scope.Include) && effect != string(scope.Exclude) {
		return fmt.Errorf("effect must be include or exclude, got %q", effect)
	}
	if pattern == "" {
		return fmt.Errorf("pattern is empty")
	}
	res, err := s.db.Exec(`UPDATE task_scope_rules SET effect=$3, pattern=$4, note=$5 WHERE id=$1 AND task_id=$2`,
		id, taskID, effect, pattern, note)
	if err != nil {
		return fmt.Errorf("update scope rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("scope rule %d not found", id)
	}
	return nil
}

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

// TaskScopeRule is one operator-written boundary line, stored beside the rows
// the hunt accumulates.
type TaskScopeRule struct {
	ID         int64  `json:"id"`
	TaskID     int64  `json:"task_id"`
	Effect     string `json:"effect"`
	Pattern    string `json:"pattern"`
	Note       string `json:"note"`
	CreatedAt  string `json:"created_at"`
	Protocol   string `json:"protocol"`
	Ports      []int  `json:"ports"`
	Authorized bool   `json:"authorized"`
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

// AddTaskScopeRule stores one rule and returns its id. The console's write path
// goes through the policy accessor, so it records the same audit row and moves
// the same revision; a written rule is not a grant until it is approved.
func (s *AssetStore) AddTaskScopeRule(taskID int64, effect, pattern, note string) (int64, error) {
	return s.db.AddPolicyRule(context.Background(), taskID,
		netpolicy.Rule{Effect: effect, Pattern: pattern, Note: note}, OperatorActor)
}

// DeleteTaskScopeRule removes one rule.
func (s *AssetStore) DeleteTaskScopeRule(taskID, id int64) error {
	return s.db.DeletePolicyRule(context.Background(), taskID, id, OperatorActor)
}

// ListTaskScopeRuleRows returns the rules with their metadata for the API.
func (s *AssetStore) ListTaskScopeRuleRows(taskID int64) ([]TaskScopeRule, error) {
	rows, err := s.db.Query(`SELECT id, task_id, effect, pattern, note, created_at::text,
       protocol, COALESCE(array_to_json(ports)::text,'[]'), authorized
FROM task_scope_rules WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list scope rules: %w", err)
	}
	defer rows.Close()
	out := []TaskScopeRule{}
	for rows.Next() {
		var (
			r     TaskScopeRule
			ports string
		)
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Effect, &r.Pattern, &r.Note, &r.CreatedAt,
			&r.Protocol, &ports, &r.Authorized); err != nil {
			return nil, fmt.Errorf("list scope rules: %w", err)
		}
		if err := json.Unmarshal([]byte(ports), &r.Ports); err != nil {
			return nil, fmt.Errorf("scope rule %d ports: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateTaskScopeRule rewrites one rule in place, so an operator can correct a
// pattern without losing the row's identity in the audit trail. An edit to the
// effect or the pattern drops the rule's approval: the old grant named the old
// line.
func (s *AssetStore) UpdateTaskScopeRule(taskID, id int64, effect, pattern, note string) error {
	return s.db.UpdatePolicyRule(context.Background(), taskID, id,
		netpolicy.Rule{Effect: effect, Pattern: pattern, Note: note}, OperatorActor)
}

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// ErrPolicyRuleNotFound reports an approve/revoke for a rule that is not on the
// task named, so the API can answer 404 without hiding a database failure.
var ErrPolicyRuleNotFound = errors.New("policy rule not found")

// OperatorActor is the audit identity of a policy change made through the
// operator console. Agent and curator writes carry their own actor.
const OperatorActor = "operator"

const agentPolicyActor = "agent"

// CertException is one operator-approved origin certificate exception: bound to
// one task and one authority, and expiring. It never disables verification
// globally, and it never authorizes a destination.
type CertException struct {
	ID        int64      `json:"id"`
	TaskID    int64      `json:"task_id"`
	Authority string     `json:"authority"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// PolicyState implements netpolicy.Source: it loads everything one session is
// judged against.
//
// Only a task's own rules authorize. A spawned task must carry its own grant, so
// an explicit parent relationship can never widen a child's reach, and the
// revision and the rules are read in one statement so the two cannot disagree.
func (d *DB) PolicyState(ctx context.Context, s netpolicy.Session) (netpolicy.State, error) {
	st := netpolicy.State{}
	if s.TaskID > 0 {
		rev, rules, err := d.policyRules(ctx, s.TaskID)
		if err != nil {
			return netpolicy.State{}, err
		}
		st.Revision, st.Rules = rev, rules
	}
	// Research and install are judged by the public-destination rule, so both
	// consult the live target set: an install must not reach a destination a live
	// task is authorized to test. A testing session does not pay for a query it
	// cannot use.
	if s.Purpose == netpolicy.PurposeResearch || s.Purpose == netpolicy.PurposeInstall {
		targets, err := d.policyTargets(ctx)
		if err != nil {
			return netpolicy.State{}, err
		}
		st.Targets = targets
	}
	return st, nil
}

// policyRules reads one task's policy revision and rules in one statement. A
// task that is missing, deleted or archived is netpolicy.ErrNoTask: an
// authorization question about it has no answer, and guessing one is the bug.
func (d *DB) policyRules(ctx context.Context, taskID int64) (int64, []netpolicy.Rule, error) {
	rows, err := d.QueryContext(ctx, `
SELECT t.policy_revision, r.id, r.effect, r.pattern, r.protocol,
       COALESCE(array_to_json(r.ports)::text,'[]'), r.authorized, r.note
FROM tasks t
LEFT JOIN task_scope_rules r ON r.task_id = t.id
WHERE t.id = $1 AND t.deleted_at IS NULL AND t.archived_at IS NULL
ORDER BY r.id`, taskID)
	if err != nil {
		return 0, nil, fmt.Errorf("read policy rules: %w", err)
	}
	defer rows.Close()

	var (
		rev   int64
		rules []netpolicy.Rule
		seen  bool
	)
	for rows.Next() {
		var (
			id         sql.NullInt64
			effect     sql.NullString
			pattern    sql.NullString
			protocol   sql.NullString
			ports      string
			authorized sql.NullBool
			note       sql.NullString
		)
		if err := rows.Scan(&rev, &id, &effect, &pattern, &protocol, &ports, &authorized, &note); err != nil {
			return 0, nil, fmt.Errorf("scan policy rule: %w", err)
		}
		seen = true
		if !id.Valid {
			continue
		}
		var ps []int
		if err := json.Unmarshal([]byte(ports), &ps); err != nil {
			return 0, nil, fmt.Errorf("policy rule %d ports: %w", id.Int64, err)
		}
		rules = append(rules, netpolicy.Rule{
			ID:         id.Int64,
			TaskID:     taskID,
			Effect:     effect.String,
			Pattern:    pattern.String,
			Protocol:   protocol.String,
			Ports:      ps,
			Authorized: authorized.Bool,
			Note:       note.String,
		})
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("read policy rules: %w", err)
	}
	if !seen {
		return 0, nil, fmt.Errorf("policy state for task %d: %w", taskID, netpolicy.ErrNoTask)
	}
	return rev, rules, nil
}

// policyTargets lists the authorized include patterns of every live task.
// Research must not reach a destination another task is authorized to test,
// however public it looks.
func (d *DB) policyTargets(ctx context.Context) ([]string, error) {
	rows, err := d.QueryContext(ctx, `
SELECT r.pattern
FROM task_scope_rules r
JOIN tasks t ON t.id = r.task_id
WHERE r.authorized AND r.effect = 'include'
  AND t.deleted_at IS NULL AND t.archived_at IS NULL
ORDER BY r.pattern`)
	if err != nil {
		return nil, fmt.Errorf("read policy targets: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var pattern string
		if err := rows.Scan(&pattern); err != nil {
			return nil, fmt.Errorf("scan policy target: %w", err)
		}
		out = append(out, pattern)
	}
	return out, rows.Err()
}

// TaskPolicyRules gives discovery tools the task's rules, including pending ones.
func (s *AssetStore) TaskPolicyRules(ctx context.Context, taskID int64) ([]netpolicy.Rule, error) {
	return s.db.ListPolicyRules(ctx, taskID)
}

// AddPendingPolicyRule records an agent proposal without approving a grant.
func (s *AssetStore) AddPendingPolicyRule(ctx context.Context, taskID int64, r netpolicy.Rule) (int64, error) {
	r.Authorized = false
	return s.db.AddPolicyRule(ctx, taskID, r, agentPolicyActor)
}

// ListPolicyRules returns every rule for a task, authorized or not, so the
// operator view can show which rows are grants and which are only written.
func (d *DB) ListPolicyRules(ctx context.Context, taskID int64) ([]netpolicy.Rule, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id, effect, pattern, protocol, COALESCE(array_to_json(ports)::text,'[]'), authorized, note
FROM task_scope_rules WHERE task_id = $1 ORDER BY id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list policy rules: %w", err)
	}
	defer rows.Close()
	var out []netpolicy.Rule
	for rows.Next() {
		r := netpolicy.Rule{TaskID: taskID}
		var ports string
		if err := rows.Scan(&r.ID, &r.Effect, &r.Pattern, &r.Protocol, &ports, &r.Authorized, &r.Note); err != nil {
			return nil, fmt.Errorf("scan policy rule: %w", err)
		}
		if err := json.Unmarshal([]byte(ports), &r.Ports); err != nil {
			return nil, fmt.Errorf("policy rule %d ports: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddPolicyRule stores one rule for a task and records who wrote it. A rule is a
// grant only when the caller says so: an agent-written rule is stored
// unauthorized, and only SetPolicyRuleAuthorized turns it into one.
func (d *DB) AddPolicyRule(ctx context.Context, taskID int64, r netpolicy.Rule, actor string) (int64, error) {
	if taskID <= 0 {
		return 0, errors.New("add policy rule: a task is required")
	}
	if err := netpolicy.ValidateRule(r); err != nil {
		return 0, err
	}
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	if proto == "" {
		proto = "any"
	}
	var approvedBy, approvedAt any
	if r.Authorized {
		approvedBy, approvedAt = actor, time.Now().UTC()
	} else if actor == agentPolicyActor {
		// Retain the proposal's provenance without setting an approval time.
		approvedBy = actor
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("add policy rule: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var id int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO task_scope_rules(task_id, effect, pattern, note, protocol, ports, authorized, approved_by, approved_at)
VALUES ($1,$2,$3,$4,$5,COALESCE($6::int[],'{}'),$7,$8,$9)
RETURNING id`,
		taskID, r.Effect, r.Pattern, r.Note, proto, r.Ports, r.Authorized, approvedBy, approvedAt).Scan(&id); err != nil {
		return 0, fmt.Errorf("add policy rule: %w", err)
	}
	if err := recordPolicyAudit(ctx, tx, taskID, actor, "rule.add", map[string]any{
		"rule_id": id, "effect": r.Effect, "pattern": r.Pattern,
		"protocol": proto, "ports": r.Ports, "authorized": r.Authorized,
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("add policy rule: %w", err)
	}
	return id, nil
}

// SetPolicyRuleAuthorized approves or revokes one rule. The change and its audit
// row commit together, and the schema trigger moves the task's policy revision,
// so a cached verdict or a pooled connection issued under the old revision stops
// being trusted.
func (d *DB) SetPolicyRuleAuthorized(ctx context.Context, taskID, ruleID int64, authorized bool, actor string) error {
	var approvedBy, approvedAt any
	if authorized {
		approvedBy, approvedAt = actor, time.Now().UTC()
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("authorize policy rule: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var effect, pattern string
	if err := tx.QueryRowContext(ctx, `
UPDATE task_scope_rules
SET authorized = $3, approved_by = $4, approved_at = $5
WHERE id = $1 AND task_id = $2
RETURNING effect, pattern`, ruleID, taskID, authorized, approvedBy, approvedAt).Scan(&effect, &pattern); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("policy rule %d: %w", ruleID, ErrPolicyRuleNotFound)
		}
		return fmt.Errorf("authorize policy rule: %w", err)
	}
	if err := recordPolicyAudit(ctx, tx, taskID, actor, "rule.authorize", map[string]any{
		"rule_id": ruleID, "effect": effect, "pattern": pattern, "authorized": authorized,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("authorize policy rule: %w", err)
	}
	return nil
}

// UpdatePolicyRule rewrites one rule. A change to its effect or pattern makes
// the earlier approval meaningless, so the rule drops to unauthorized in the
// same statement: an approval names one grant, and this is a different one. A
// note-only edit keeps the approval. The change and its audit row commit
// together, and the schema trigger moves the task's policy revision.
func (d *DB) UpdatePolicyRule(ctx context.Context, taskID, ruleID int64, r netpolicy.Rule, actor string) error {
	if err := netpolicy.ValidateRule(r); err != nil {
		return err
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("update policy rule: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var (
		effect, pattern string
		authorized      bool
	)
	if err := tx.QueryRowContext(ctx, `
UPDATE task_scope_rules
SET effect = $3, pattern = $4, note = $5,
    authorized = CASE WHEN effect = $3 AND pattern = $4 THEN authorized ELSE false END,
    approved_by = CASE WHEN effect = $3 AND pattern = $4 THEN approved_by END,
    approved_at = CASE WHEN effect = $3 AND pattern = $4 THEN approved_at END
WHERE id = $1 AND task_id = $2
RETURNING effect, pattern, authorized`, ruleID, taskID, r.Effect, r.Pattern, r.Note).
		Scan(&effect, &pattern, &authorized); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("policy rule %d: %w", ruleID, ErrPolicyRuleNotFound)
		}
		return fmt.Errorf("update policy rule: %w", err)
	}
	if err := recordPolicyAudit(ctx, tx, taskID, actor, "rule.update", map[string]any{
		"rule_id": ruleID, "effect": effect, "pattern": pattern, "authorized": authorized,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("update policy rule: %w", err)
	}
	return nil
}

// DeletePolicyRule removes one rule and records the delete, so the audit trail
// says who withdrew a boundary line. The schema trigger moves the task's policy
// revision in the same transaction.
func (d *DB) DeletePolicyRule(ctx context.Context, taskID, ruleID int64, actor string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete policy rule: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var effect, pattern string
	if err := tx.QueryRowContext(ctx, `
DELETE FROM task_scope_rules WHERE id = $1 AND task_id = $2
RETURNING effect, pattern`, ruleID, taskID).Scan(&effect, &pattern); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("policy rule %d: %w", ruleID, ErrPolicyRuleNotFound)
		}
		return fmt.Errorf("delete policy rule: %w", err)
	}
	if err := recordPolicyAudit(ctx, tx, taskID, actor, "rule.delete", map[string]any{
		"rule_id": ruleID, "effect": effect, "pattern": pattern,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("delete policy rule: %w", err)
	}
	return nil
}

// AddCertException approves an origin certificate exception for one task and
// authority, replacing an earlier one for the same pair. An expired exception
// authorizes nothing: ListCertExceptions omits it.
func (d *DB) AddCertException(ctx context.Context, taskID int64, authority, reason string, expiresAt *time.Time, actor string) error {
	authority = strings.ToLower(strings.TrimSpace(authority))
	if taskID <= 0 || authority == "" {
		return errors.New("cert exception: a task and an authority are required")
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cert exception: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `
INSERT INTO cert_exceptions(task_id, authority, reason, expires_at)
VALUES ($1,$2,$3,$4)
ON CONFLICT (task_id, authority)
DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at, created_at = now()`,
		taskID, authority, reason, expiresAt); err != nil {
		return fmt.Errorf("cert exception: %w", err)
	}
	if err := recordPolicyAudit(ctx, tx, taskID, actor, "cert.exception", map[string]any{
		"authority": authority, "reason": reason, "expires_at": expiresAt,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cert exception: %w", err)
	}
	return nil
}

// ListCertExceptions returns the task's unexpired exceptions for the TLS stage.
func (d *DB) ListCertExceptions(ctx context.Context, taskID int64) ([]CertException, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id, task_id, authority, reason, created_at, expires_at
FROM cert_exceptions
WHERE task_id = $1 AND (expires_at IS NULL OR expires_at > now())
ORDER BY authority`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list cert exceptions: %w", err)
	}
	defer rows.Close()
	var out []CertException
	for rows.Next() {
		var (
			e       CertException
			expires sql.NullTime
		)
		if err := rows.Scan(&e.ID, &e.TaskID, &e.Authority, &e.Reason, &e.CreatedAt, &expires); err != nil {
			return nil, fmt.Errorf("scan cert exception: %w", err)
		}
		if expires.Valid {
			at := expires.Time
			e.ExpiresAt = &at
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrCertExceptionNotFound reports a delete for an exception that is not on the
// task named, so the API can answer 404 without hiding a database failure.
var ErrCertExceptionNotFound = errors.New("certificate exception not found")

// DeleteCertException removes one exception. The delete and its audit row commit
// together, and a second delete reports the missing row instead of succeeding
// silently: a stale operator view must not hide a wrong task id.
func (d *DB) DeleteCertException(ctx context.Context, taskID, id int64, actor string) error {
	if taskID <= 0 || id <= 0 {
		return fmt.Errorf("cert exception %d: %w", id, ErrCertExceptionNotFound)
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete cert exception: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var authority string
	if err := tx.QueryRowContext(ctx, `
DELETE FROM cert_exceptions WHERE id = $1 AND task_id = $2
RETURNING authority`, id, taskID).Scan(&authority); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("cert exception %d: %w", id, ErrCertExceptionNotFound)
		}
		return fmt.Errorf("delete cert exception: %w", err)
	}
	if err := recordPolicyAudit(ctx, tx, taskID, actor, "cert.exception.delete", map[string]any{
		"exception_id": id, "authority": authority,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("delete cert exception: %w", err)
	}
	return nil
}

func recordPolicyAudit(ctx context.Context, tx *sql.Tx, taskID int64, actor, action string, detail map[string]any) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("policy audit detail: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO policy_audit(task_id, actor, action, detail)
VALUES (NULLIF($1,0), $2, $3, $4::jsonb)`, taskID, actor, action, string(body)); err != nil {
		return fmt.Errorf("policy audit: %w", err)
	}
	return nil
}

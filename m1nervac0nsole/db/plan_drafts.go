package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/plan"
)

// ErrPlanDraftState reports a draft that is no longer pending: applied or
// discarded drafts cannot be applied again.
var ErrPlanDraftState = errors.New("plan draft is not pending")

// ErrPlanDraftInclude reports a proposal that would widen the task's scope. An
// exclusion only narrows the engagement; an inclusion needs the operator to say
// so explicitly, because it changes what the guard will allow.
var ErrPlanDraftInclude = errors.New("the draft adds scope inclusions: apply it with allow_include")

// PlanDraft is one drafted engagement plan awaiting the operator's decision.
type PlanDraft struct {
	ID             int64           `json:"id"`
	TaskID         int64           `json:"task_id"`
	Status         string          `json:"status"` // draft | applied | discarded
	Summary        string          `json:"summary"`
	Proposal       json.RawMessage `json:"proposal"`
	CreatedNodeIDs []int64         `json:"created_node_ids,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	AppliedAt      *time.Time      `json:"applied_at,omitempty"`
}

const planDraftColumns = `id, task_id, status, summary, proposal, created_node_ids, created_at, applied_at`

func scanPlanDraft(row interface{ Scan(...any) error }) (*PlanDraft, error) {
	var (
		d       PlanDraft
		raw     []byte
		nodes   []byte
		applied sql.NullTime
	)
	if err := row.Scan(&d.ID, &d.TaskID, &d.Status, &d.Summary, &raw, &nodes, &d.CreatedAt, &applied); err != nil {
		return nil, err
	}
	d.Proposal = json.RawMessage(raw)
	if len(nodes) > 0 {
		_ = json.Unmarshal(nodes, &d.CreatedNodeIDs)
	}
	if applied.Valid {
		t := applied.Time
		d.AppliedAt = &t
	}
	return &d, nil
}

// CreatePlanDraft stores a validated proposal as the task's one pending draft.
// A previous pending draft is discarded first: the operator reviews what the
// assistant just proposed, not a pile of stale proposals.
func (d *DB) CreatePlanDraft(ctx context.Context, taskID int64, summary string, proposal json.RawMessage) (*PlanDraft, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("plan draft needs a task id")
	}
	var out *PlanDraft
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE plan_drafts SET status='discarded' WHERE task_id=$1 AND status='draft'`, taskID); err != nil {
			return err
		}
		row := tx.QueryRowContext(ctx, `
INSERT INTO plan_drafts(task_id, summary, proposal) VALUES ($1,$2,$3)
RETURNING `+planDraftColumns, taskID, summary, string(proposal))
		var err error
		out, err = scanPlanDraft(row)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create plan draft: %w", err)
	}
	return out, nil
}

// GetPlanDraft reads one draft.
func (d *DB) GetPlanDraft(ctx context.Context, id int64) (*PlanDraft, error) {
	row := d.QueryRowContext(ctx, `SELECT `+planDraftColumns+` FROM plan_drafts WHERE id=$1`, id)
	out, err := scanPlanDraft(row)
	if err != nil {
		return nil, fmt.Errorf("plan draft %d: %w", id, err)
	}
	return out, nil
}

// ListPlanDrafts returns a task's drafts, newest first.
func (d *DB) ListPlanDrafts(ctx context.Context, taskID int64) ([]*PlanDraft, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+planDraftColumns+`
FROM plan_drafts WHERE task_id=$1 ORDER BY created_at DESC, id DESC`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list plan drafts: %w", err)
	}
	defer rows.Close()
	out := []*PlanDraft{}
	for rows.Next() {
		draft, err := scanPlanDraft(rows)
		if err != nil {
			return nil, fmt.Errorf("list plan drafts: %w", err)
		}
		out = append(out, draft)
	}
	return out, rows.Err()
}

// DiscardPlanDraft marks a pending draft discarded. An applied draft is left
// alone: its nodes exist and discarding the record would hide what created them.
func (d *DB) DiscardPlanDraft(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `UPDATE plan_drafts SET status='discarded' WHERE id=$1 AND status='draft'`, id)
	if err != nil {
		return fmt.Errorf("discard plan draft %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("plan draft %d: %w", id, ErrPlanDraftState)
	}
	return nil
}

// ApplyPlanDraft writes a pending draft into the graph in one transaction:
// goals, open seed intents, active hints and scope rows, then marks the draft
// applied with the ids it created. Nothing is written if any step fails.
func (d *DB) ApplyPlanDraft(ctx context.Context, id int64, allowInclude bool) (*PlanDraft, error) {
	var out *PlanDraft
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var (
			taskID  int64
			status  string
			summary string
			raw     []byte
		)
		if err := tx.QueryRowContext(ctx,
			`SELECT task_id, status, summary, proposal FROM plan_drafts WHERE id=$1 FOR UPDATE`, id).
			Scan(&taskID, &status, &summary, &raw); err != nil {
			return fmt.Errorf("plan draft %d: %w", id, err)
		}
		if status != "draft" {
			return fmt.Errorf("plan draft %d: %w", id, ErrPlanDraftState)
		}
		var p plan.Proposal
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("plan draft %d: %w", id, err)
		}
		if plan.HasInclude(p) && !allowInclude {
			return ErrPlanDraftInclude
		}
		var expID int64
		if err := tx.QueryRowContext(ctx,
			`SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&expID); err != nil {
			return fmt.Errorf("plan draft %d: task %d: %w", id, taskID, err)
		}

		var nodeIDs []int64
		goalIDs := map[string]int64{}
		for _, g := range p.Goals {
			payload := map[string]any{"text": g.Text}
			if g.VulnClass != "" {
				payload["vulnclass"] = g.VulnClass
			}
			nodeID, err := insertPlanNode(ctx, tx, expID, "goal", payload, 0, "open", "operator")
			if err != nil {
				return err
			}
			goalIDs[g.Ref] = nodeID
			nodeIDs = append(nodeIDs, nodeID)
		}

		intentIDs := map[string]int64{}
		for _, it := range p.Intents {
			payload := map[string]any{"summary": it.Summary}
			if goalID := goalIDs[it.Goal]; goalID != 0 {
				payload["goal_id"] = goalID
			}
			if len(it.AssetIDs) > 0 {
				payload["asset_ids"] = it.AssetIDs
			}
			nodeID, err := insertPlanNode(ctx, tx, expID, "intent", payload, 5, "open", "operator")
			if err != nil {
				return err
			}
			for _, assetID := range it.AssetIDs {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
					nodeID, assetID); err != nil {
					return fmt.Errorf("plan draft %d: anchor %d: %w", id, assetID, err)
				}
			}
			intentIDs[it.Ref] = nodeID
			nodeIDs = append(nodeIDs, nodeID)
		}
		// depends_on is advisory order for the operator and the planner's view;
		// it is stored once every intent has an id.
		for _, it := range p.Intents {
			if len(it.DependsOn) == 0 {
				continue
			}
			deps := make([]int64, 0, len(it.DependsOn))
			for _, ref := range it.DependsOn {
				if depID := intentIDs[ref]; depID != 0 {
					deps = append(deps, depID)
				}
			}
			encoded, _ := json.Marshal(deps)
			if _, err := tx.ExecContext(ctx,
				`UPDATE exploration_nodes SET payload = payload || jsonb_build_object('depends_on', $2::jsonb) WHERE id=$1`,
				intentIDs[it.Ref], string(encoded)); err != nil {
				return fmt.Errorf("plan draft %d: depends_on: %w", id, err)
			}
		}

		for _, h := range p.Hints {
			payload := map[string]any{"text": h.Text}
			if h.Rule {
				payload["rule"] = true
			}
			nodeID, err := insertPlanNode(ctx, tx, expID, "hint", payload, 0, "active", "operator")
			if err != nil {
				return err
			}
			for _, assetID := range h.AssetIDs {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
					nodeID, assetID); err != nil {
					return fmt.Errorf("plan draft %d: hint anchor %d: %w", id, assetID, err)
				}
			}
			nodeIDs = append(nodeIDs, nodeID)
		}

		scoped := &AssetStore{db: d, company: d.Companies(), tx: tx}
		for _, s := range p.Scope {
			ts := TaskScope{TaskID: taskID, Kind: s.Kind, Source: "manual", Reason: s.Note, Effect: s.Effect}
			switch s.Kind {
			case "root_domain", "subdomain":
				ts.Domain = s.Value
			case "ip", "cidr":
				ts.Net = s.Value
			default:
				ts.Value = s.Value
			}
			if _, err := scoped.upsertTaskScopeResult(ts); err != nil {
				return fmt.Errorf("plan draft %d: scope %s %s: %w", id, s.Kind, s.Value, err)
			}
		}

		encoded, _ := json.Marshal(nodeIDs)
		if _, err := tx.ExecContext(ctx,
			`UPDATE plan_drafts SET status='applied', applied_at=now(), created_node_ids=$2 WHERE id=$1`,
			id, string(encoded)); err != nil {
			return fmt.Errorf("plan draft %d: mark applied: %w", id, err)
		}
		out = &PlanDraft{ID: id, TaskID: taskID, Status: "applied", Summary: summary,
			Proposal: json.RawMessage(raw), CreatedNodeIDs: nodeIDs}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func insertPlanNode(ctx context.Context, tx *sql.Tx, expID int64, kind string, payload map[string]any, priority int, state, origin string) (int64, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		expID, kind, string(raw), priority, state, origin).Scan(&id); err != nil {
		return 0, fmt.Errorf("insert %s node: %w", kind, err)
	}
	return id, nil
}

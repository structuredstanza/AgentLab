package db

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/plan"
)

func planProposal(t *testing.T, p plan.Proposal) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPlanDraftApplyCreatesTheGraph(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	task := memoryTask(t, d)

	p := plan.Proposal{
		Summary: "Map the web tier, then test the login.",
		Goals:   []plan.Goal{{Ref: "g1", Text: "Map every HTTP service"}, {Ref: "g2", Text: "Prove SQL injection in login"}},
		Intents: []plan.Intent{
			{Ref: "i1", Goal: "g1", Summary: "Fingerprint the web tier"},
			{Ref: "i2", Goal: "g2", Summary: "Test the login form", DependsOn: []string{"i1"}},
		},
		Hints: []plan.Hint{{Text: "Stay under 5 requests per second", Rule: true}},
		Scope: []plan.Scope{{Effect: "exclude", Kind: "root_domain", Value: "vendor.example", Note: "third party"}},
	}
	draft, err := d.CreatePlanDraft(context.Background(), task.ID, p.Summary, planProposal(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != "draft" {
		t.Fatalf("new draft status = %q", draft.Status)
	}

	applied, err := d.ApplyPlanDraft(context.Background(), draft.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" || len(applied.CreatedNodeIDs) != 5 {
		t.Fatalf("applied = %+v", applied)
	}

	var goals, intents, hints int
	if err := d.QueryRow(`SELECT
  count(*) FILTER (WHERE kind='goal'), count(*) FILTER (WHERE kind='intent'), count(*) FILTER (WHERE kind='hint')
FROM exploration_nodes WHERE exploration_id=$1 AND origin='operator'`, task.ExplorationID).
		Scan(&goals, &intents, &hints); err != nil {
		t.Fatal(err)
	}
	if goals != 2 || intents != 2 || hints != 1 {
		t.Fatalf("created goals=%d intents=%d hints=%d", goals, intents, hints)
	}

	// depends_on is stored as node ids, so the operator's order survives.
	var deps string
	if err := d.QueryRow(`SELECT payload->>'depends_on' FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND payload->>'summary'='Test the login form'`, task.ExplorationID).Scan(&deps); err != nil {
		t.Fatal(err)
	}
	if deps == "" || deps == "[]" {
		t.Fatalf("depends_on was not stored: %q", deps)
	}

	// The exclusion reached the boundary.
	var effect string
	if err := d.QueryRow(`SELECT effect FROM task_scope WHERE task_id=$1 AND domain='vendor.example'`, task.ID).Scan(&effect); err != nil {
		t.Fatal(err)
	}
	if effect != "exclude" {
		t.Fatalf("scope effect = %q", effect)
	}

	// A second apply is refused: the nodes exist once.
	if _, err := d.ApplyPlanDraft(context.Background(), draft.ID, false); !errors.Is(err, ErrPlanDraftState) {
		t.Fatalf("second apply = %v, want ErrPlanDraftState", err)
	}
}

func TestPlanDraftIncludeNeedsExplicitApproval(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	task := memoryTask(t, d)

	p := plan.Proposal{
		Summary: "Widen the boundary",
		Scope:   []plan.Scope{{Effect: "include", Kind: "ip", Value: "10.9.9.9"}},
	}
	draft, err := d.CreatePlanDraft(context.Background(), task.ID, p.Summary, planProposal(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApplyPlanDraft(context.Background(), draft.ID, false); !errors.Is(err, ErrPlanDraftInclude) {
		t.Fatalf("apply without allow_include = %v, want ErrPlanDraftInclude", err)
	}
	// The refusal wrote nothing and left the draft pending.
	if _, err := d.ApplyPlanDraft(context.Background(), draft.ID, true); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND effect='include' AND net='10.9.9.9/32'`, task.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("include rows = %d", n)
	}
}

func TestPlanDraftOneOpenDraftPerTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	task := memoryTask(t, d)

	first := plan.Proposal{Summary: "first", Hints: []plan.Hint{{Text: "one"}}}
	second := plan.Proposal{Summary: "second", Hints: []plan.Hint{{Text: "two"}}}
	a, err := d.CreatePlanDraft(context.Background(), task.ID, first.Summary, planProposal(t, first))
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreatePlanDraft(context.Background(), task.ID, second.Summary, planProposal(t, second))
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetPlanDraft(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "discarded" {
		t.Fatalf("the superseded draft is %q, want discarded", got.Status)
	}
	if b.Status != "draft" {
		t.Fatalf("the new draft is %q", b.Status)
	}
	if err := d.DiscardPlanDraft(context.Background(), b.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DiscardPlanDraft(context.Background(), b.ID); !errors.Is(err, ErrPlanDraftState) {
		t.Fatalf("second discard = %v, want ErrPlanDraftState", err)
	}
}

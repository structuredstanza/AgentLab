package db

import (
	"context"
	"testing"
	"time"
)

// The audit trail is readable and bounded: a row per call, and a prune that
// drops only what is older than the window.
func TestMCPAuditListAndPrune(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("audit trail", "audit rows", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	_, token, err := d.CreateAPIToken(ctx, "audit test", task.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := d.Exec(`INSERT INTO mcp_audit(token_id, tool, args) VALUES ($1,'list_findings','{}'::jsonb)`, token.ID); err != nil {
		t.Fatal(err)
	}
	// An old row, as if it had been written a year ago.
	if _, err := d.Exec(`INSERT INTO mcp_audit(token_id, tool, args, created_at)
VALUES ($1,'list_assets','{}'::jsonb, now() - interval '365 days')`, token.ID); err != nil {
		t.Fatal(err)
	}

	rows, err := d.ListMCPAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Tool != "list_findings" || rows[0].TokenName != "audit test" || rows[0].TaskID != task.ID {
		t.Fatalf("rows = %+v", rows)
	}

	pruned, err := d.PruneMCPAudit(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("pruned %d rows, want 1", pruned)
	}
	rows, err = d.ListMCPAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Tool != "list_findings" {
		t.Fatalf("after prune rows = %+v", rows)
	}
}

func TestUpdateTaskScopeRule(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("rule update", "edit a rule in place", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	assets := d.Assets()

	id, err := assets.AddTaskScopeRule(task.ID, "exclude", "old.invalid", "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.UpdateTaskScopeRule(task.ID, id, "include", "new.invalid", "second"); err != nil {
		t.Fatal(err)
	}
	rows, err := assets.ListTaskScopeRuleRows(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Effect != "include" || rows[0].Pattern != "new.invalid" || rows[0].Note != "second" {
		t.Fatalf("rows = %+v", rows)
	}
	if err := assets.UpdateTaskScopeRule(task.ID, id, "maybe", "x", ""); err == nil {
		t.Fatal("an unknown effect was accepted")
	}
	if err := assets.UpdateTaskScopeRule(task.ID, 0, "include", "x", ""); err == nil {
		t.Fatal("a missing rule was updated")
	}
}

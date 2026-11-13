package db

import (
	"context"
	"errors"
	"testing"
)

// TestKnowledgeUsageLedger round-trips the read ledger: a batch write is one
// row per id, the read reports the total hit count and the newest rows first,
// and a task-less read (the curation chat) stores NULL rather than 0.
func TestKnowledgeUsageLedger(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	task := memoryTask(t, d)
	first := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: task.ID, Kind: "technique", Title: "usage ledger first",
		Body: "a lesson worth reading twice", Source: "agent",
	})
	second := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: task.ID, Kind: "opsec", Title: "usage ledger second",
		Body: "another lesson", Source: "agent",
	})
	unread := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: task.ID, Kind: "note", Title: "usage ledger unread",
		Body: "never shown to anyone", Source: "agent",
	})
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM knowledge_entries WHERE id = ANY($1)`,
			[]int64{first.ID, second.ID, unread.ID})
	})

	if err := d.RecordKnowledgeUsage(ctx, task.ID, "task_start", []int64{first.ID, second.ID}); err != nil {
		t.Fatalf("record batch: %v", err)
	}
	if err := d.RecordKnowledgeUsage(ctx, task.ID, "recall", []int64{first.ID}); err != nil {
		t.Fatalf("record recall: %v", err)
	}
	if err := d.RecordKnowledgeUsage(ctx, 0, "chat", []int64{first.ID}); err != nil {
		t.Fatalf("record chat: %v", err)
	}

	sum, err := d.GetKnowledgeUsage(ctx, first.ID, 10)
	if err != nil {
		t.Fatalf("read usage: %v", err)
	}
	if sum.Hits != 3 || len(sum.Usage) != 3 {
		t.Fatalf("usage = %+v, want 3 hits and 3 rows", sum)
	}
	if sum.LastUsed.IsZero() || sum.Usage[0].ShownAt.Before(sum.Usage[1].ShownAt) {
		t.Fatalf("usage not newest-first: %+v", sum.Usage)
	}
	surfaces := map[string]bool{}
	chatTaskID := int64(-1)
	for _, row := range sum.Usage {
		surfaces[row.Surface] = true
		if row.Surface == "chat" {
			chatTaskID = row.TaskID
		}
	}
	for _, want := range []string{"task_start", "recall", "chat"} {
		if !surfaces[want] {
			t.Errorf("usage rows missing surface %q: %+v", want, sum.Usage)
		}
	}
	if chatTaskID != 0 {
		t.Errorf("task-less chat row task_id = %d, want 0 (NULL)", chatTaskID)
	}

	// limit bounds the rows but not the hit count: the window count is taken
	// before LIMIT.
	limited, err := d.GetKnowledgeUsage(ctx, first.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if limited.Hits != 3 || len(limited.Usage) != 1 {
		t.Errorf("limited usage = %+v, want hits 3 with one row", limited)
	}

	// An entry nothing has read reports zero hits and an empty list.
	none, err := d.GetKnowledgeUsage(ctx, unread.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if none.Hits != 0 || len(none.Usage) != 0 || !none.LastUsed.IsZero() {
		t.Errorf("unread entry usage = %+v, want zero", none)
	}

	// An empty batch is a no-op, not an error, and an unknown surface is
	// rejected before it reaches the CHECK constraint.
	if err := d.RecordKnowledgeUsage(ctx, task.ID, "recall", nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if err := d.RecordKnowledgeUsage(ctx, task.ID, "bogus", []int64{first.ID}); !errors.Is(err, ErrMemoryInvalid) {
		t.Fatalf("unknown surface err = %v, want ErrMemoryInvalid", err)
	}
}

// TestKnowledgeUsageHitsBulk counts many entries in one query, leaving unread
// ids out of the map: the list view must not issue one count per row.
func TestKnowledgeUsageHitsBulk(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	task := memoryTask(t, d)
	ids := make([]int64, 0, 3)
	for _, title := range []string{"bulk usage one", "bulk usage two", "bulk usage three"} {
		e := mustAddKnowledge(t, d, KnowledgeInput{
			TaskID: task.ID, Kind: "note", Title: title, Body: "bulk usage body", Source: "agent",
		})
		ids = append(ids, e.ID)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM knowledge_entries WHERE id = ANY($1)`, ids)
	})

	if err := d.RecordKnowledgeUsage(ctx, task.ID, "round", []int64{ids[0], ids[1]}); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordKnowledgeUsage(ctx, task.ID, "round", []int64{ids[0]}); err != nil {
		t.Fatal(err)
	}

	hits, err := d.KnowledgeUsageHits(ctx, ids)
	if err != nil {
		t.Fatalf("bulk hits: %v", err)
	}
	if hits[ids[0]] != 2 || hits[ids[1]] != 1 {
		t.Errorf("bulk hits = %v, want %d:2 %d:1", hits, ids[0], ids[1])
	}
	if _, ok := hits[ids[2]]; ok {
		t.Errorf("unread entry %d appears in the hit map: %v", ids[2], hits)
	}

	if empty, err := d.KnowledgeUsageHits(ctx, nil); err != nil || len(empty) != 0 {
		t.Errorf("empty bulk lookup = %v err=%v, want an empty map and no error", empty, err)
	}
}

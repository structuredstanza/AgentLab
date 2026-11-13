package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestKnowledgeReviewOrdersCandidatesByOriginOutcome: the queue lists one
// task's candidates with the evidence behind each, strongest first, and shows
// nothing from another task or from the adopted base.
func TestKnowledgeReviewOrdersCandidatesByOriginOutcome(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	tk := memoryTask(t, d)
	other := memoryTask(t, d)
	es := d.Exploration(tk.ExplorationID)
	suffix := fmt.Sprintf(" [%d]", tk.ID)
	title := func(name string) string { return name + suffix }

	intent := func(summary string) int64 {
		id, err := es.AddIntent(map[string]any{"summary": summary}, 1, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	findingIntent := intent("confirmed finding")
	pendingIntent := intent("unconfirmed finding")
	factIntent := intent("negative result")
	emptyIntent := intent("nothing yielded")
	rejectedIntent := intent("rejected finding")

	finding, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, ExplorationID: tk.ExplorationID, IntentID: findingIntent,
		VulnClass: "sql injection", Name: "review queue finding", Severity: "high",
		Summary: "confirmed by replay",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(finding.FindingID, "confirmed"); err != nil {
		t.Fatal(err)
	}
	// Reported but never confirmed: it counts as a fact, not a finding.
	if _, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, ExplorationID: tk.ExplorationID, IntentID: pendingIntent,
		VulnClass: "xss", Name: "review queue pending finding", Severity: "low",
		Summary: "awaiting confirmation",
	}); err != nil {
		t.Fatal(err)
	}
	factID, err := es.AddNode(KindFact, map[string]any{"summary": "only msg consumed"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(factIntent, RelYields, factID); err != nil {
		t.Fatal(err)
	}
	// A finding the owner rejected is not evidence of anything.
	rejected, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, ExplorationID: tk.ExplorationID, IntentID: rejectedIntent,
		VulnClass: "ssrf", Name: "review queue rejected finding", Severity: "low",
		Summary: "owner rejected it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingStatus(rejected.FindingID, "false_positive"); err != nil {
		t.Fatal(err)
	}

	// Created worst-evidence-first, so the order asserted below can only come
	// from the query.
	unknown := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: title("proxy header smuggling"),
		Body: "hop-by-hop header accepted from 203.0.113.9", Source: "operator"})
	none := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: title("jwt none algorithm"), Body: "b", Source: "agent"})
	pending := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: title("stored xss in profile"), Body: "b", Source: "agent"})
	fact := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: title("smb null session"), Body: "b", Source: "agent"})
	findingEntry := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: title("sqli time oracle"), Body: "b", Source: "agent"})
	rejectedEntry := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: title("rejected ssrf route"), Body: "b", Source: "agent"})
	for _, stamp := range []struct{ entry, intent int64 }{
		{none.ID, emptyIntent}, {pending.ID, pendingIntent},
		{fact.ID, factIntent}, {findingEntry.ID, findingIntent},
		{rejectedEntry.ID, rejectedIntent},
	} {
		if _, err := d.Exec(`UPDATE knowledge_entries SET origin_intent_id=$2 WHERE id=$1`, stamp.entry, stamp.intent); err != nil {
			t.Fatal(err)
		}
	}

	// Neither another task's candidate nor an adopted entry is a queue item.
	mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: other.ID, Kind: "technique", Title: title("other task candidate"), Body: "b", Source: "agent"})
	adopted := mustAddKnowledge(t, d, KnowledgeInput{
		Scope: "global", Kind: "technique",
		Title: fmt.Sprintf("sqli time oracle variant %d", time.Now().UnixNano()),
		Body:  "b", Source: "operator", Status: "adopted"})
	t.Cleanup(func() { _ = d.DeleteKnowledge(ctx, adopted.ID) })

	items, err := d.KnowledgeReview(ctx, tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 6 {
		t.Fatalf("queue has %d items, want the task's 6 candidates only: %+v", len(items), items)
	}
	want := []struct {
		entry   KnowledgeEntry
		intent  int64
		outcome string
	}{
		{findingEntry, findingIntent, "finding"},
		{fact, factIntent, "fact"},
		{pending, pendingIntent, "fact"},
		{rejectedEntry, rejectedIntent, "none"},
		{none, emptyIntent, "none"},
		{unknown, 0, "unknown"},
	}
	for i, w := range want {
		got := items[i]
		if got.Entry.ID != w.entry.ID || got.OriginOutcome != w.outcome || got.OriginIntentID != w.intent {
			t.Fatalf("item %d = entry %d outcome %q intent %d, want entry %d outcome %q intent %d",
				i, got.Entry.ID, got.OriginOutcome, got.OriginIntentID, w.entry.ID, w.outcome, w.intent)
		}
	}

	// The operator-written candidate still carries the IP, so a promotion would
	// generalise it; the agent-written ones were generalised at write time.
	if items[5].Redactions != 1 {
		t.Fatalf("promotion redactions = %d, want the one IP literal", items[5].Redactions)
	}
	if items[0].Redactions != 0 {
		t.Fatalf("agent-written candidate reports %d redactions, want 0", items[0].Redactions)
	}

	// Nearest adopted is per candidate: only the sqli title matches.
	if items[0].NearestAdopted == nil || items[0].NearestAdopted.ID != adopted.ID {
		t.Fatalf("finding candidate nearest adopted = %+v, want entry %d", items[0].NearestAdopted, adopted.ID)
	}
	if items[5].NearestAdopted != nil {
		t.Fatalf("unrelated candidate matched %+v", items[5].NearestAdopted)
	}
}

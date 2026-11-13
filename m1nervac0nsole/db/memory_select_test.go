package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// memorySelectorTask builds one task whose current intent and finished sibling
// are anchored to the same asset, with a second asset that shares nothing.
func memorySelectorTask(t *testing.T) (d *DB, tk *Task, store *ExplorationStore, asset, current, sibling int64) {
	t.Helper()
	d = memoryTestDB(t)
	tk, err := d.CreateTask("memory selector", "probe the sqlmap upload path", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(tk.ID) })
	store = d.Exploration(tk.ExplorationID)
	var other int64
	if err := d.QueryRow(`INSERT INTO assets(type, ip) VALUES('ip','10.9.9.41') RETURNING id`).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO assets(type, ip) VALUES('ip','10.9.9.42') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE id = ANY($1::bigint[])`, []int64{asset, other})
	})
	current, err = store.AddIntent(map[string]any{"summary": "probe the sqlmap upload path"}, 5, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	sibling, err = store.AddIntent(map[string]any{"summary": "probe the upload path"}, 5, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeState(sibling, "done"); err != nil {
		t.Fatal(err)
	}
	return d, tk, store, asset, current, sibling
}

// TestSelectMemoryAttemptsUseTheYieldedFact: a finished sibling is represented
// by its yielded fact that best matches this intent's text, not by its result
// summary.
func TestSelectMemoryAttemptsUseTheYieldedFact(t *testing.T) {
	d, tk, store, _, current, sibling := memorySelectorTask(t)
	ctx := context.Background()
	fact, err := store.AddNode(KindFact, map[string]any{
		"summary": "JSON-field probing consumed only msg",
		"detail":  "the sqlmap upload path answered",
	}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(sibling, RelYields, fact); err != nil {
		t.Fatal(err)
	}
	node := sibling
	if _, err := store.AppendActivity(Activity{NodeID: &node, Kind: "result", Summary: "the worker result summary"}); err != nil {
		t.Fatal(err)
	}

	sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Attempts) != 1 {
		t.Fatalf("attempts = %+v, want one", sel.Attempts)
	}
	a := sel.Attempts[0]
	if a.IntentID != sibling || a.State != "done" || a.Facts != 1 {
		t.Fatalf("attempt = %+v, want the sibling with one fact", a)
	}
	if !strings.Contains(a.Text, "JSON-field probing consumed only msg") || strings.Contains(a.Text, "the worker result summary") {
		t.Fatalf("attempt text = %q, want the yielded fact, not the result row", a.Text)
	}
}

// TestSelectMemoryAttemptsFallBackToResultRow: an intent that yielded no fact
// is represented by its latest result activity, summary before detail.
func TestSelectMemoryAttemptsFallBackToResultRow(t *testing.T) {
	d, tk, store, asset, current, sibling := memorySelectorTask(t)
	ctx := context.Background()
	node := sibling
	if _, err := store.AppendActivity(Activity{NodeID: &node, Kind: "result", Summary: "only msg was consumed"}); err != nil {
		t.Fatal(err)
	}
	third, err := store.AddIntent(map[string]any{"summary": "probe the upload again"}, 5, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeState(third, "exhausted"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(Activity{NodeID: &third, Kind: "result", Detail: "detail only"}); err != nil {
		t.Fatal(err)
	}

	sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current})
	if err != nil {
		t.Fatal(err)
	}
	texts := map[int64]string{}
	for _, a := range sel.Attempts {
		texts[a.IntentID] = a.Text
	}
	if texts[sibling] != "only msg was consumed" {
		t.Fatalf("summary fallback = %q, want the result summary", texts[sibling])
	}
	if texts[third] != "detail only" {
		t.Fatalf("detail fallback = %q, want the result detail", texts[third])
	}
}

// TestSelectMemoryOrdersReflections: tooling and same-asset rows first, agent
// rows before engine heuristics inside each group, then newest.
func TestSelectMemoryOrdersReflections(t *testing.T) {
	d, tk, _, _, current, sibling := memorySelectorTask(t)
	ctx := context.Background()
	add := func(in ReflectionInput) Reflection {
		t.Helper()
		r, _, err := d.AddReflection(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	tooling := add(ReflectionInput{TaskID: tk.ID, Kind: "learning", Source: "worker",
		Summary: "tooling lesson", Signal: map[string]any{"scope": "tooling"}})
	related := add(ReflectionInput{TaskID: tk.ID, IntentID: sibling, Kind: "opsec", Source: "worker",
		Summary: "agent on the same asset"})
	engineRelated := add(ReflectionInput{TaskID: tk.ID, IntentID: sibling, Kind: "noise", Source: "engine",
		Summary: "engine on the same asset"})
	unrelated := add(ReflectionInput{TaskID: tk.ID, Kind: "lookfor", Source: "worker",
		Summary: "unrelated target"})
	engineOther := add(ReflectionInput{TaskID: tk.ID, Kind: "noise", Source: "engine",
		Summary: "engine elsewhere"})

	sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]int64, len(sel.Reflections))
	for i, r := range sel.Reflections {
		got[i] = r.ID
	}
	want := []int64{related.ID, tooling.ID, engineRelated.ID, unrelated.ID}
	if len(got) != len(want) {
		t.Fatalf("reflections = %v, want %v (engineOther %d must lose the fourth slot)", got, want, engineOther.ID)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reflections = %v, want %v", got, want)
		}
	}
}

// TestSelectMemoryAttachesVerdictWithoutHidingTarget: a verdict is appended to
// its target and never suppresses or reorders it.
func TestSelectMemoryAttachesVerdictWithoutHidingTarget(t *testing.T) {
	d, tk, _, _, current, _ := memorySelectorTask(t)
	ctx := context.Background()
	target, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "opsec", Source: "worker", Summary: "RCE route closed"})
	if err != nil {
		t.Fatal(err)
	}
	judge, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "learning", Source: "worker", Summary: "RCE worked through the upload",
		Signal: map[string]any{"scope": "target", "about": []string{fmt.Sprintf("R%d", target.ID)}, "verdict": "wrong"}})
	if err != nil {
		t.Fatal(err)
	}

	sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current})
	if err != nil {
		t.Fatal(err)
	}
	var found *MemoryReflection
	for i := range sel.Reflections {
		if sel.Reflections[i].ID == target.ID {
			found = &sel.Reflections[i]
		}
	}
	if found == nil {
		t.Fatalf("target %d was hidden: %+v", target.ID, sel.Reflections)
	}
	if found.Verdict == nil || found.Verdict.Verdict != "wrong" || found.Verdict.ReflectionID != judge.ID {
		t.Fatalf("verdict = %+v, want wrong by R%d", found.Verdict, judge.ID)
	}
	block, _ := RenderLaunchBlock(sel, 2400)
	if !strings.Contains(block, "RCE route closed") {
		t.Fatalf("target text missing from the block:\n%s", block)
	}
	if !strings.Contains(block, fmt.Sprintf("(wrong by R%d: RCE worked through the upload)", judge.ID)) {
		t.Fatalf("verdict missing from the block:\n%s", block)
	}
}

// TestSelectMemoryAttachesVerdictToKnowledge: a verdict about a knowledge id
// shows on its index line - in the launch block and the start block - and the
// line still renders.
func TestSelectMemoryAttachesVerdictToKnowledge(t *testing.T) {
	d, tk, _, _, current, _ := memorySelectorTask(t)
	ctx := context.Background()
	entry := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "technique", Title: "RCE route through the upload", Body: "b", Source: "operator"})
	judge, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "learning", Source: "worker", Summary: "the upload route works",
		Signal: map[string]any{"scope": "target", "about": []string{fmt.Sprintf("K%d", entry.ID)}, "verdict": "wrong"}})
	if err != nil {
		t.Fatal(err)
	}

	sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current})
	if err != nil {
		t.Fatal(err)
	}
	var found *MemoryKnowledge
	for i := range sel.Knowledge {
		if sel.Knowledge[i].ID == entry.ID {
			found = &sel.Knowledge[i]
		}
	}
	if found == nil {
		t.Fatalf("entry %d was hidden: %+v", entry.ID, sel.Knowledge)
	}
	if found.Verdict == nil || found.Verdict.Verdict != "wrong" || found.Verdict.ReflectionID != judge.ID {
		t.Fatalf("verdict = %+v, want wrong by R%d", found.Verdict, judge.ID)
	}
	block, _ := RenderLaunchBlock(sel, 2400)
	if !strings.Contains(block, "RCE route through the upload") {
		t.Fatalf("entry text missing from the block:\n%s", block)
	}
	if !strings.Contains(block, fmt.Sprintf("(wrong by R%d: the upload route works)", judge.ID)) {
		t.Fatalf("knowledge verdict missing from the block:\n%s", block)
	}

	// The start block's index attaches the same verdict to an adopted entry.
	adopted := mustAddKnowledge(t, d, KnowledgeInput{
		Scope: "global", Kind: "technique", Source: "operator", Status: "adopted",
		Title: "adopted upload route", Body: "b"})
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, adopted.ID) })
	staleJudge, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "learning", Source: "worker", Summary: "the adopted route is stale",
		Signal: map[string]any{"scope": "target", "about": []string{fmt.Sprintf("K%d", adopted.ID)}, "verdict": "stale"}})
	if err != nil {
		t.Fatal(err)
	}
	index, err := d.KnowledgeIndex(ctx, tk.ID, MemorySearchTerms(tk.Name+" "+tk.Goal), nil)
	if err != nil {
		t.Fatal(err)
	}
	var startEntry *MemoryKnowledge
	for i := range index {
		if index[i].ID == adopted.ID {
			startEntry = &index[i]
		}
	}
	if startEntry == nil || startEntry.Verdict == nil || startEntry.Verdict.Verdict != "stale" {
		t.Fatalf("start index verdict = %+v, want stale", startEntry)
	}
	start, _ := RenderStartBlock(nil, index, 2400)
	if !strings.Contains(start, "adopted upload route") {
		t.Fatalf("adopted entry missing from the start block:\n%s", start)
	}
	if !strings.Contains(start, fmt.Sprintf("(stale by R%d: the adopted route is stale)", staleJudge.ID)) {
		t.Fatalf("start block verdict missing:\n%s", start)
	}
}

// TestSelectMemoryBeforeExcludesLaterRows: Before is the preview's as-of
// instant; nothing created after it may appear, and an intent that was still
// running then is not a finished attempt even if it has finished since.
func TestSelectMemoryBeforeExcludesLaterRows(t *testing.T) {
	d, tk, store, asset, current, sibling := memorySelectorTask(t)
	ctx := context.Background()
	early, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "opsec", Source: "worker", Summary: "early reflection"})
	if err != nil {
		t.Fatal(err)
	}
	earlyEntry := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "note", Title: "early entry", Body: "b", Source: "operator"})
	// An intent that had finished by the cut is an attempt at that instant.
	doneBefore, err := store.AddIntent(map[string]any{"summary": "probe the upload"}, 5, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeState(doneBefore, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(Activity{NodeID: &doneBefore, Kind: "result", Summary: "finished before the cut"}); err != nil {
		t.Fatal(err)
	}
	cut := time.Now()
	late, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "opsec", Source: "worker", Summary: "late reflection"})
	if err != nil {
		t.Fatal(err)
	}
	lateEntry := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "note", Title: "late entry", Body: "b", Source: "operator"})
	// An intent that finished after the cut was still running at that instant.
	doneAfter, err := store.AddIntent(map[string]any{"summary": "probe the upload again"}, 5, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeState(doneAfter, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(Activity{NodeID: &doneAfter, Kind: "result", Summary: "finished after the cut"}); err != nil {
		t.Fatal(err)
	}

	sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current, Before: cut})
	if err != nil {
		t.Fatal(err)
	}
	refl := map[int64]bool{}
	for _, r := range sel.Reflections {
		refl[r.ID] = true
	}
	if !refl[early.ID] || refl[late.ID] {
		t.Fatalf("reflections = %v, want early %d and not late %d", refl, early.ID, late.ID)
	}
	entries := map[int64]bool{}
	for _, e := range sel.Knowledge {
		entries[e.ID] = true
	}
	if !entries[earlyEntry.ID] || entries[lateEntry.ID] {
		t.Fatalf("knowledge = %v, want early %d and not late %d", entries, earlyEntry.ID, lateEntry.ID)
	}
	attempts := map[int64]bool{}
	for _, a := range sel.Attempts {
		attempts[a.IntentID] = true
	}
	if !attempts[doneBefore] || attempts[doneAfter] || attempts[sibling] {
		t.Fatalf("attempts = %v, want only the intent that had finished by the cut (doneAfter=%d, noResult=%d)",
			attempts, doneAfter, sibling)
	}

	// A live launch keeps the state filter alone: the intent that finished
	// after the cut is a finished attempt now.
	live, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: current})
	if err != nil {
		t.Fatal(err)
	}
	liveAttempts := map[int64]bool{}
	for _, a := range live.Attempts {
		liveAttempts[a.IntentID] = true
	}
	if !liveAttempts[doneAfter] {
		t.Fatalf("live attempts = %v, want the intent that finished after the cut", liveAttempts)
	}
}

// TestKnowledgeIndexOrdersMatchThenNewest: the start block's index puts the
// entries matching the task's own wording first, then newest.
func TestKnowledgeIndexOrdersMatchThenNewest(t *testing.T) {
	d := memoryTestDB(t)
	ctx := context.Background()
	tk := memoryTask(t, d)
	suffix := fmt.Sprintf(" [%d]", tk.ID)
	unmatched := mustAddKnowledge(t, d, KnowledgeInput{
		Scope: "global", Kind: "note", Source: "operator", Status: "adopted",
		Title: "unrelated platform note" + suffix, Body: "b"})
	matched := mustAddKnowledge(t, d, KnowledgeInput{
		Scope: "global", Kind: "technique", Source: "operator", Status: "adopted",
		Title: "memory test technique" + suffix, Body: "b"})
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM knowledge_entries WHERE id = ANY($1::bigint[])`, []int64{unmatched.ID, matched.ID})
	})
	index, err := d.KnowledgeIndex(ctx, tk.ID, MemorySearchTerms(tk.Name+" "+tk.Goal), nil)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[int64]int{}
	for i, e := range index {
		pos[e.ID] = i
	}
	matchedPos, okMatched := pos[matched.ID]
	unmatchedPos, okUnmatched := pos[unmatched.ID]
	if !okMatched || !okUnmatched {
		t.Fatalf("index = %+v, want both adopted entries", index)
	}
	if matchedPos >= unmatchedPos {
		t.Fatalf("index order = %+v, want the goal match before the unrelated entry", index)
	}
}

// TestRenderLaunchBlockFillsEveryReflectionSlot: the section cap is derived
// from the slots, so four maximum-length reflections all render.
func TestRenderLaunchBlockFillsEveryReflectionSlot(t *testing.T) {
	long := strings.Repeat("a", 400)
	sel := MemorySelection{Reflections: make([]MemoryReflection, 0, memoryReflectionSlots)}
	for i := 1; i <= memoryReflectionSlots; i++ {
		sel.Reflections = append(sel.Reflections, MemoryReflection{
			Reflection: Reflection{ID: int64(i), Kind: "opsec", Summary: long, Detail: long},
			Count:      1,
		})
	}
	block, shown := RenderLaunchBlock(sel, 2400)
	if len(shown.Reflections) != memoryReflectionSlots {
		t.Fatalf("shown reflections = %v, want all %d slots", shown.Reflections, memoryReflectionSlots)
	}
	if !strings.Contains(block, fmt.Sprintf("- R%d ", memoryReflectionSlots)) {
		t.Fatalf("the last reflection slot is unreachable:\n%s", block)
	}
}

// TestSelectMemoryForeignIntentStillReturnsTaskMemory: an intent that belongs
// to another task, or does not exist, only skips the asset-ordered attempts; it
// must not blank the task's own reflections and knowledge index.
func TestSelectMemoryForeignIntentStillReturnsTaskMemory(t *testing.T) {
	d, tk, _, _, _, _ := memorySelectorTask(t)
	ctx := context.Background()
	other := memoryTask(t, d)
	refl, _, err := d.AddReflection(ctx, ReflectionInput{
		TaskID: tk.ID, Kind: "opsec", Source: "worker", Summary: "the task's own lesson"})
	if err != nil {
		t.Fatal(err)
	}
	entry := mustAddKnowledge(t, d, KnowledgeInput{
		TaskID: tk.ID, Kind: "note", Title: "the task's own entry", Body: "b", Source: "operator"})
	foreign, err := d.Exploration(other.ExplorationID).AddIntent(
		map[string]any{"summary": "another task's direction"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	for _, intent := range []int64{foreign, 1 << 40} {
		sel, err := d.SelectMemory(ctx, MemoryQuery{TaskID: tk.ID, IntentID: intent})
		if err != nil {
			t.Fatal(err)
		}
		if len(sel.Attempts) != 0 {
			t.Fatalf("intent %d: attempts = %+v, want none", intent, sel.Attempts)
		}
		gotRefl := false
		for _, r := range sel.Reflections {
			if r.ID == refl.ID {
				gotRefl = true
			}
		}
		if !gotRefl {
			t.Fatalf("intent %d: reflections = %+v, want the task's own %d", intent, sel.Reflections, refl.ID)
		}
		gotEntry := false
		for _, e := range sel.Knowledge {
			if e.ID == entry.ID {
				gotEntry = true
			}
		}
		if !gotEntry {
			t.Fatalf("intent %d: knowledge = %+v, want the task's own %d", intent, sel.Knowledge, entry.ID)
		}
	}
}

// TestRenderStartBlockSkipsAnOversizedIndexLine: an index line that does not fit
// is skipped, never a stop, and the footer counts what was left out.
func TestRenderStartBlockSkipsAnOversizedIndexLine(t *testing.T) {
	index := []MemoryKnowledge{
		{KnowledgeEntry: KnowledgeEntry{ID: 1, Kind: "note", Title: strings.Repeat("k", 400)}},
		{KnowledgeEntry: KnowledgeEntry{ID: 2, Kind: "note", Title: "short"}},
	}
	block, shown := RenderStartBlock(nil, index, 350)
	if strings.Contains(block, "- K1 ") {
		t.Fatalf("the oversized index line was rendered:\n%s", block)
	}
	if !strings.Contains(block, "- K2 [note] short") {
		t.Fatalf("the index loop stopped at the line that did not fit:\n%s", block)
	}
	if len(shown.Knowledge) != 1 || shown.Knowledge[0] != 2 {
		t.Fatalf("shown knowledge = %v, want only K2", shown.Knowledge)
	}
	if !strings.Contains(block, "(+1 more: recall(query))") {
		t.Fatalf("footer does not count the skipped line:\n%s", block)
	}
}

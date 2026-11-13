package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestKnowledgeReviewRoute: the queue route answers the contract shape, 400s a
// missing or malformed task id, and lists only the requested task's candidates.
func TestKnowledgeReviewRoute(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/knowledge/review", s.knowledgeReview)

	taskA, err := m.CreateTaskWithOptions("mtest review a", "find ssrf", db.TaskCreateOptions{Name: "mtest review a"})
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := strconv.ParseInt(taskA.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(aID) }()
	taskB, err := m.CreateTaskWithOptions("mtest review b", "find ssrf", db.TaskCreateOptions{Name: "mtest review b"})
	if err != nil {
		t.Fatal(err)
	}
	bID, _ := strconv.ParseInt(taskB.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(bID) }()

	tag := fmt.Sprintf("mtestreview%d", time.Now().UnixNano())
	ctx := context.Background()
	cand, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{
		Scope: "task", TaskID: aID, Kind: "technique", Title: tag + " candidate",
		Body: "probe 203.0.113.9 login", Source: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{
		Scope: "task", TaskID: bID, Kind: "technique", Title: tag + " other", Body: "b", Source: "agent",
	}); err != nil {
		t.Fatal(err)
	}
	adopted, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{
		Scope: "global", Kind: "technique", Title: tag + " candidate variant", Body: "b",
		Source: "operator", Status: "adopted",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.pg.DeleteKnowledge(ctx, adopted.ID) }()

	code, out := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/review?task_id="+taskA.ID, "")
	if code != http.StatusOK {
		t.Fatalf("review status=%d body=%v", code, out)
	}
	if total, _ := out["total"].(float64); total != 1 {
		t.Fatalf("total=%v want the task's one candidate: %v", out["total"], out)
	}
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%v want one", out["items"])
	}
	item, _ := items[0].(map[string]any)
	entry, _ := item["entry"].(map[string]any)
	if id, _ := entry["id"].(float64); int64(id) != cand.ID {
		t.Fatalf("item entry id=%v want %d", entry["id"], cand.ID)
	}
	if item["origin_outcome"] != "unknown" || item["origin_intent_id"] != float64(0) {
		t.Fatalf("origin fields = %v / %v, want unknown / 0", item["origin_outcome"], item["origin_intent_id"])
	}
	if redactions, _ := item["redactions"].(float64); redactions != 1 {
		t.Fatalf("redactions=%v want the one IP literal", item["redactions"])
	}
	nearest, _ := item["nearest_adopted"].(map[string]any)
	if nearest == nil || int64(nearest["id"].(float64)) != adopted.ID {
		t.Fatalf("nearest_adopted=%v want entry %d", item["nearest_adopted"], adopted.ID)
	}

	// Another task's candidate stays in its own queue.
	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/review?task_id="+taskB.ID, "")
	if code != http.StatusOK {
		t.Fatalf("task B review status=%d body=%v", code, out)
	}
	if total, _ := out["total"].(float64); total != 1 {
		t.Fatalf("task B total=%v want its own one candidate: %v", out["total"], out)
	}

	for _, path := range []string{
		"/api/knowledge/review",
		"/api/knowledge/review?task_id=abc",
		"/api/knowledge/review?task_id=0",
	} {
		if code, _ := knowledgeCall(t, mux, http.MethodGet, path, ""); code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400", path, code)
		}
	}
}

// TestKnowledgeReviewRouteEmptyTask: a task with no candidates answers an empty
// queue rather than an error, so the review screen can render "nothing to do".
func TestKnowledgeReviewRouteEmptyTask(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/knowledge/review", s.knowledgeReview)
	task, err := m.CreateTaskWithOptions("mtest review empty", "find ssrf", db.TaskCreateOptions{Name: "mtest review empty"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(id) }()

	code, out := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/review?task_id="+task.ID, "")
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, out)
	}
	if items, ok := out["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("items=%v want an empty array", out["items"])
	}
	if total, _ := out["total"].(float64); total != 0 {
		t.Fatalf("total=%v want 0", out["total"])
	}
}

// TestKnowledgeReviewCountsRoute: the tasks list gets one cheap number per task
// with waiting candidates, and nothing for a task whose entries are already
// adopted or retired or for the adopted base.
func TestKnowledgeReviewCountsRoute(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/knowledge/review/counts", s.knowledgeReviewCounts)
	ctx := context.Background()

	// The counts are global, so the assertion is about what this test adds:
	// other packages' fixtures may hold candidates of their own.
	before, err := m.pg.KnowledgeReviewCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	newTask := func(name string) int64 {
		t.Helper()
		task, err := m.CreateTaskWithOptions(name, "find ssrf", db.TaskCreateOptions{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		id, _ := strconv.ParseInt(task.ID, 10, 64)
		t.Cleanup(func() { _ = m.pg.DeleteTask(id) })
		return id
	}
	taskA := newTask("mtest counts a")
	taskB := newTask("mtest counts b")
	taskC := newTask("mtest counts c")

	tag := fmt.Sprintf("mtestcounts%d", time.Now().UnixNano())
	add := func(in db.KnowledgeInput) {
		t.Helper()
		if _, _, err := m.pg.AddKnowledge(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		add(db.KnowledgeInput{Scope: "task", TaskID: taskA, Kind: "technique",
			Title: fmt.Sprintf("%s a%d", tag, i), Body: "b", Source: "agent"})
	}
	add(db.KnowledgeInput{Scope: "task", TaskID: taskB, Kind: "technique",
		Title: tag + " b0", Body: "b", Source: "agent"})
	// A task whose only entries are already decided contributes nothing.
	add(db.KnowledgeInput{Scope: "task", TaskID: taskC, Kind: "technique",
		Title: tag + " c adopted", Body: "b", Source: "operator", Status: "adopted"})
	add(db.KnowledgeInput{Scope: "task", TaskID: taskC, Kind: "technique",
		Title: tag + " c retired", Body: "b", Source: "operator", Status: "retired"})
	// Neither does the adopted base, which carries no task id.
	adopted, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{Scope: "global", Kind: "technique",
		Title: tag + " global adopted", Body: "b", Source: "operator", Status: "adopted"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteKnowledge(ctx, adopted.ID) })

	code, out := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/review/counts", "")
	if code != http.StatusOK {
		t.Fatalf("counts status=%d body=%v", code, out)
	}
	counts, ok := out["counts"].(map[string]any)
	if !ok {
		t.Fatalf("counts is not an object: %v", out["counts"])
	}
	key := func(id int64) string { return strconv.FormatInt(id, 10) }
	if got, _ := counts[key(taskA)].(float64); got != 2 {
		t.Fatalf("task A count=%v want 2: %v", counts[key(taskA)], counts)
	}
	if got, _ := counts[key(taskB)].(float64); got != 1 {
		t.Fatalf("task B count=%v want 1: %v", counts[key(taskB)], counts)
	}
	if _, listed := counts[key(taskC)]; listed {
		t.Fatalf("task C has only adopted/retired entries but was counted: %v", counts)
	}

	after, err := m.pg.KnowledgeReviewCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for id, n := range after {
		if id == taskA || id == taskB {
			continue
		}
		if before[id] != n {
			t.Fatalf("this test changed task %d's count %d -> %d", id, before[id], n)
		}
	}
}

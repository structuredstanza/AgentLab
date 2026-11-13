package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// planTestMux registers the three plan routes on a bare mux, so the handlers
// are exercised without the auth chain.
func planTestMux(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tasks/{id}/plans", s.taskPlans)
	mux.HandleFunc("POST /api/tasks/{id}/plans/{draft}/apply", s.applyTaskPlan)
	mux.HandleFunc("DELETE /api/tasks/{id}/plans/{draft}", s.deleteTaskPlan)
	return mux
}

// TestPlanDraftRoutes is DB-backed: drafts live in plan_drafts and applying one
// writes graph nodes, so it skips without M1NERVAC0NSOLE_PG_DSN. It pins the
// review contract: list per task, apply once, refuse an inclusion without the
// flag, refuse another task's draft, and discard only a pending draft.
func TestPlanDraftRoutes(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_PG_DSN") == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	m, s, _ := memoryTestServer(t)
	mux := planTestMux(s)
	ctx := context.Background()

	taskA, err := m.CreateTaskWithOptions("mtest plans a", "find ssrf", db.TaskCreateOptions{Name: "mtest plans a"})
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := strconv.ParseInt(taskA.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(aID) }()
	taskB, err := m.CreateTaskWithOptions("mtest plans b", "find ssrf", db.TaskCreateOptions{Name: "mtest plans b"})
	if err != nil {
		t.Fatal(err)
	}
	bID, _ := strconv.ParseInt(taskB.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(bID) }()

	proposal := json.RawMessage(`{"summary":"mtest plan","goals":[{"ref":"g1","text":"prove ssrf"}],` +
		`"intents":[{"ref":"i1","summary":"probe login","goal":"g1"}]}`)
	draft, err := m.pg.CreatePlanDraft(ctx, aID, "mtest plan", proposal)
	if err != nil {
		t.Fatal(err)
	}

	// (a) the task's list carries the pending draft.
	code, out := knowledgeCall(t, mux, http.MethodGet, fmt.Sprintf("/api/tasks/%d/plans", aID), "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, out)
	}
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items=%v want one draft", out["items"])
	}
	item, _ := items[0].(map[string]any)
	if id, _ := item["id"].(float64); int64(id) != draft.ID {
		t.Fatalf("item id=%v want %d", item["id"], draft.ID)
	}
	if item["status"] != "draft" {
		t.Fatalf("item status=%v want draft", item["status"])
	}

	// A task with no drafts answers an empty list; a malformed id is a 400.
	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/tasks/987654321/plans", "")
	if code != http.StatusOK {
		t.Fatalf("unknown task list status=%d body=%v", code, out)
	}
	if items, ok := out["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("unknown task items=%v want an empty array", out["items"])
	}
	for _, path := range []string{"/api/tasks/abc/plans", "/api/tasks/0/plans"} {
		if code, _ := knowledgeCall(t, mux, http.MethodGet, path, ""); code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400", path, code)
		}
	}

	// (c) another task's route must not apply this draft, and must write nothing.
	code, out = knowledgeCall(t, mux, http.MethodPost,
		fmt.Sprintf("/api/tasks/%d/plans/%d/apply", bID, draft.ID), "{}")
	if code != http.StatusNotFound {
		t.Fatalf("cross-task apply status=%d body=%v want 404", code, out)
	}
	unchanged, err := m.pg.GetPlanDraft(ctx, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != "draft" {
		t.Fatalf("cross-task apply changed status to %q", unchanged.Status)
	}

	// (b) applying writes the plan and marks the draft applied.
	code, out = knowledgeCall(t, mux, http.MethodPost,
		fmt.Sprintf("/api/tasks/%d/plans/%d/apply", aID, draft.ID), "{}")
	if code != http.StatusOK {
		t.Fatalf("apply status=%d body=%v", code, out)
	}
	applied, _ := out["draft"].(map[string]any)
	if applied["status"] != "applied" {
		t.Fatalf("apply response status=%v want applied", applied["status"])
	}
	stored, err := m.pg.GetPlanDraft(ctx, draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "applied" || stored.AppliedAt == nil {
		t.Fatalf("stored draft status=%q applied_at=%v want applied with a timestamp", stored.Status, stored.AppliedAt)
	}
	if len(stored.CreatedNodeIDs) == 0 {
		t.Fatalf("applied draft created no nodes")
	}

	// (d) a second apply is a conflict, not a second write.
	code, out = knowledgeCall(t, mux, http.MethodPost,
		fmt.Sprintf("/api/tasks/%d/plans/%d/apply", aID, draft.ID), "{}")
	if code != http.StatusConflict {
		t.Fatalf("second apply status=%d body=%v want 409", code, out)
	}

	// (e) an inclusion needs the operator's explicit flag.
	include := json.RawMessage(`{"summary":"mtest include",` +
		`"scope":[{"effect":"include","kind":"keyword","value":"mtestinclude"}]}`)
	includeDraft, err := m.pg.CreatePlanDraft(ctx, aID, "mtest include", include)
	if err != nil {
		t.Fatal(err)
	}
	code, out = knowledgeCall(t, mux, http.MethodPost,
		fmt.Sprintf("/api/tasks/%d/plans/%d/apply", aID, includeDraft.ID), "{}")
	if code != http.StatusBadRequest {
		t.Fatalf("include without flag status=%d body=%v want 400", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "allow_include") {
		t.Fatalf("include refusal %q does not name allow_include", msg)
	}
	code, out = knowledgeCall(t, mux, http.MethodPost,
		fmt.Sprintf("/api/tasks/%d/plans/%d/apply", aID, includeDraft.ID), `{"allow_include":true}`)
	if code != http.StatusOK {
		t.Fatalf("include with flag status=%d body=%v", code, out)
	}

	// (f) delete discards a pending draft, and a second delete is a conflict.
	discard, err := m.pg.CreatePlanDraft(ctx, aID, "mtest discard", proposal)
	if err != nil {
		t.Fatal(err)
	}
	code, out = knowledgeCall(t, mux, http.MethodDelete,
		fmt.Sprintf("/api/tasks/%d/plans/%d", aID, discard.ID), "")
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("delete status=%d body=%v want 200 ok", code, out)
	}
	if got, err := m.pg.GetPlanDraft(ctx, discard.ID); err != nil || got.Status != "discarded" {
		t.Fatalf("discarded draft=%v err=%v want status discarded", got, err)
	}
	code, out = knowledgeCall(t, mux, http.MethodDelete,
		fmt.Sprintf("/api/tasks/%d/plans/%d", aID, discard.ID), "")
	if code != http.StatusConflict {
		t.Fatalf("second delete status=%d body=%v want 409", code, out)
	}
}

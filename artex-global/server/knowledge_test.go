package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
)

// memoryTestServer builds a Manager against the disposable test Postgres and a
// Server on top of it. Tests that need no database skip instead of failing.
func memoryTestServer(t *testing.T) (*Manager, *Server, string) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	return m, s, token
}

// memoryAPI issues one authenticated JSON request through the real handler
// chain. An empty token leaves the Authorization header off.
func memoryAPI(t *testing.T, s *Server, token, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func memoryEntryID(t *testing.T, out map[string]any) int64 {
	t.Helper()
	entry, _ := out["entry"].(map[string]any)
	id, _ := entry["id"].(float64)
	if id <= 0 {
		t.Fatalf("response carries no entry id: %v", out)
	}
	return int64(id)
}

func TestKnowledgeRoutesAuthValidationAndCRUD(t *testing.T) {
	m, s, token := memoryTestServer(t)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'mtest%'`) }()

	if code, _ := memoryAPI(t, s, "", http.MethodGet, "/api/knowledge", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status=%d want 401", code)
	}

	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/knowledge",
		`{"scope":"global","kind":"technique","title":"mtestheaderinjection","body":"send Authorization: Bearer abcdef123456 and password=hunter2, then retry","tags":["web"]}`)
	if code != http.StatusOK {
		t.Fatalf("create status=%d body=%v", code, out)
	}
	if redactions, _ := out["redactions"].(float64); redactions < 1 {
		t.Fatalf("redactions=%v want >=1", out["redactions"])
	}
	entry, _ := out["entry"].(map[string]any)
	if entry["status"] != "adopted" || entry["scope"] != "global" {
		t.Fatalf("operator create must be adopted global: %v", entry)
	}
	if body, _ := entry["body"].(string); strings.Contains(body, "hunter2") {
		t.Fatalf("secret survived create: %q", body)
	}
	id := memoryEntryID(t, out)

	code, out = memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?scope=global&kind=technique&limit=5", "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, out)
	}
	found := false
	list, _ := out["entries"].([]any)
	for _, raw := range list {
		item, _ := raw.(map[string]any)
		if int64(item["id"].(float64)) == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("created entry %d missing from list: %v", id, out)
	}
	// q combined with a scope filter falls through to the filterable list.
	if code, out := memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?scope=global&q=mtestheaderinjection", ""); code != http.StatusOK {
		t.Fatalf("list with q+scope status=%d body=%v", code, out)
	}

	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"bad scope", `{"scope":"bogus","kind":"note","title":"x"}`, http.StatusBadRequest},
		{"bad kind", `{"scope":"global","kind":"bogus","title":"x"}`, http.StatusBadRequest},
		{"empty title", `{"scope":"global","kind":"note","title":"   "}`, http.StatusBadRequest},
		{"global with ids", `{"scope":"global","kind":"note","title":"x","task_id":5}`, http.StatusBadRequest},
		{"company without id", `{"scope":"company","kind":"note","title":"x"}`, http.StatusBadRequest},
		{"task without id", `{"scope":"task","kind":"note","title":"x"}`, http.StatusBadRequest},
		{"unknown task", `{"scope":"task","kind":"note","title":"x","task_id":999999999}`, http.StatusNotFound},
		{"environment with ids", `{"scope":"environment","kind":"note","title":"x","task_id":5}`, http.StatusBadRequest},
		{"not json", `nope`, http.StatusBadRequest},
	} {
		if code, _ := memoryAPI(t, s, token, http.MethodPost, "/api/knowledge", tc.body); code != tc.want {
			t.Errorf("%s: status=%d want %d", tc.name, code, tc.want)
		}
	}

	// The environment scope and the lead kind are accepted by the API.
	code, out = memoryAPI(t, s, token, http.MethodPost, "/api/knowledge",
		`{"scope":"environment","kind":"lead","title":"mtestenvlead","body":"b","tags":["env:test-deployment"]}`)
	if code != http.StatusOK {
		t.Fatalf("create environment lead status=%d body=%v", code, out)
	}
	if entry, _ := out["entry"].(map[string]any); entry["scope"] != "environment" || entry["kind"] != "lead" || entry["status"] != "adopted" {
		t.Fatalf("environment lead create wrong: %v", entry)
	}

	for _, tc := range []struct {
		name, query string
		want        int
	}{
		{"bad scope", "scope=bogus", http.StatusBadRequest},
		{"bad kind", "kind=bogus", http.StatusBadRequest},
		{"bad status", "status=bogus", http.StatusBadRequest},
		{"bad limit", "limit=0", http.StatusBadRequest},
		{"bad task id", "task_id=abc", http.StatusBadRequest},
		{"unknown task", "task_id=999999999", http.StatusNotFound},
	} {
		if code, _ := memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?"+tc.query, ""); code != tc.want {
			t.Errorf("%s: status=%d want %d", tc.name, code, tc.want)
		}
	}

	path := "/api/knowledge/" + strconv.FormatInt(id, 10)
	code, out = memoryAPI(t, s, token, http.MethodPatch, path, `{"title":"mtestheaderinjectionv2"}`)
	if code != http.StatusOK {
		t.Fatalf("patch status=%d body=%v", code, out)
	}
	if entry, _ := out["entry"].(map[string]any); entry["title"] != "mtestheaderinjectionv2" {
		t.Fatalf("patch did not update the title: %v", entry)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPatch, path, `{"kind":"bogus"}`); code != http.StatusBadRequest {
		t.Fatalf("patch bad kind status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPatch, path, `{"status":"bogus"}`); code != http.StatusBadRequest {
		t.Fatalf("patch bad status status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPatch, "/api/knowledge/999999999", `{"title":"x"}`); code != http.StatusNotFound {
		t.Fatalf("patch unknown status=%d want 404", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPatch, "/api/knowledge/nope", `{"title":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("patch bad id status=%d want 400", code)
	}

	if code, _ := memoryAPI(t, s, token, http.MethodDelete, path, ""); code != http.StatusOK {
		t.Fatalf("delete status=%d want 200", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodDelete, path, ""); code != http.StatusNotFound {
		t.Fatalf("second delete status=%d want 404", code)
	}
}

func TestKnowledgePromoteAndTaskIsolation(t *testing.T) {
	m, s, token := memoryTestServer(t)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'mtest%'`) }()

	taskA, err := m.CreateTaskWithOptions("mtest promote", "find ssrf", db.TaskCreateOptions{Name: "mtest alpha"})
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := strconv.ParseInt(taskA.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(aID) }()
	taskB, err := m.CreateTaskWithOptions("mtest other", "find ssrf", db.TaskCreateOptions{Name: "mtest beta"})
	if err != nil {
		t.Fatal(err)
	}
	bID, _ := strconv.ParseInt(taskB.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(bID) }()

	cand, _, err := m.pg.AddKnowledge(context.Background(), db.KnowledgeInput{
		Scope: "task", TaskID: aID, Kind: "technique", Title: "mtestcandidatealpha",
		Body: "ssrf via invoice upload on 203.0.113.9", Source: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cand.Status != "candidate" || cand.Scope != "task" {
		t.Fatalf("agent write must be a task candidate: %+v", cand)
	}
	// An agent write is generalised at write time, so the IP is already gone
	// before promotion.
	if !strings.Contains(cand.Body, "<ip>") || strings.Contains(cand.Body, "203.0.113.9") {
		t.Fatalf("agent write kept the target IP: %q", cand.Body)
	}
	path := "/api/knowledge/" + strconv.FormatInt(cand.ID, 10)

	// Adopting a task-scoped entry is refused: promotion is the only way out.
	if code, _ := memoryAPI(t, s, token, http.MethodPatch, path, `{"status":"adopted"}`); code != http.StatusConflict {
		t.Fatalf("adopt task entry status=%d want 409", code)
	}

	// A candidate never leaves its own task.
	code, out := memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?task_id="+taskB.ID+"&q=mtestcandidatealpha", "")
	if code != http.StatusOK {
		t.Fatalf("task B search status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 0 {
		t.Fatalf("task B sees task A's candidate: %v", out)
	}
	code, out = memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?task_id="+taskA.ID+"&q=mtestcandidatealpha", "")
	if code != http.StatusOK {
		t.Fatalf("task A search status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 1 {
		t.Fatalf("task A cannot see its own candidate: %v", out)
	}
	// The filterable list path applies the same lens: scope=task with task B's
	// id must not list task A's candidate.
	code, out = memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?task_id="+taskB.ID+"&scope=task&q=mtestcandidatealpha", "")
	if code != http.StatusOK {
		t.Fatalf("task B list status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 0 {
		t.Fatalf("task B list leaks task A's candidate: %v", out)
	}

	code, out = memoryAPI(t, s, token, http.MethodPost, path+"/promote", `{"scope":"global"}`)
	if code != http.StatusOK {
		t.Fatalf("promote status=%d body=%v", code, out)
	}
	entry, _ := out["entry"].(map[string]any)
	if entry["scope"] != "global" || entry["status"] != "adopted" {
		t.Fatalf("promote did not adopt global: %v", entry)
	}
	if body, _ := entry["body"].(string); !strings.Contains(body, "<ip>") || strings.Contains(body, "203.0.113.9") {
		t.Fatalf("promote did not keep the body generalised: %q", body)
	}

	// The adopted global entry is visible to the other task.
	code, out = memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?task_id="+taskB.ID+"&q=mtestcandidatealpha", "")
	if code != http.StatusOK {
		t.Fatalf("task B search after promote status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 1 {
		t.Fatalf("adopted global entry invisible to task B: %v", out)
	}

	if code, _ := memoryAPI(t, s, token, http.MethodPost, path+"/promote", `{"scope":"global"}`); code != http.StatusBadRequest {
		t.Fatalf("re-promote status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPost, path+"/promote", `{"scope":"task"}`); code != http.StatusBadRequest {
		t.Fatalf("promote to task status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPost, "/api/knowledge/999999999/promote", `{"scope":"global"}`); code != http.StatusNotFound {
		t.Fatalf("promote unknown status=%d want 404", code)
	}

	// Promotion into the environment scope: no company id, adopted, visible to
	// the other task whatever the query.
	envCand, _, err := m.pg.AddKnowledge(context.Background(), db.KnowledgeInput{
		Scope: "task", TaskID: aID, Kind: "opsec", Title: "mtestenvpromote",
		Body: "the proxy answers CONNECT before dialling", Source: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	envPath := "/api/knowledge/" + strconv.FormatInt(envCand.ID, 10) + "/promote"
	if code, _ := memoryAPI(t, s, token, http.MethodPost, envPath, `{"scope":"environment","company_id":7}`); code != http.StatusBadRequest {
		t.Fatalf("environment promote with a company id status=%d want 400", code)
	}
	code, out = memoryAPI(t, s, token, http.MethodPost, envPath, `{"scope":"environment"}`)
	if code != http.StatusOK {
		t.Fatalf("environment promote status=%d body=%v", code, out)
	}
	if entry, _ := out["entry"].(map[string]any); entry["scope"] != "environment" || entry["status"] != "adopted" {
		t.Fatalf("environment promote did not adopt: %v", entry)
	}
	code, out = memoryAPI(t, s, token, http.MethodGet, "/api/knowledge?task_id="+taskB.ID+"&scope=environment", "")
	if code != http.StatusOK {
		t.Fatalf("task B environment list status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n < 1 {
		t.Fatalf("promoted environment entry invisible to task B: %v", out)
	}
}

func TestTaskReflectionsRoute(t *testing.T) {
	m, s, token := memoryTestServer(t)

	task, err := m.CreateTaskWithOptions("mtest reflections", "find ssrf", db.TaskCreateOptions{Name: "mtest gamma"})
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()

	for _, in := range []db.ReflectionInput{
		{TaskID: taskID, Kind: "opsec", Source: "worker", Summary: "waf blocked the upload probe"},
		{TaskID: taskID, Kind: "noise", Source: "worker", Summary: "repeated the same request three times"},
	} {
		if _, _, err := m.pg.AddReflection(context.Background(), in); err != nil {
			t.Fatal(err)
		}
	}

	base := "/api/tasks/" + task.ID + "/reflections"
	code, out := memoryAPI(t, s, token, http.MethodGet, base, "")
	if code != http.StatusOK {
		t.Fatalf("reflections status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 2 {
		t.Fatalf("count=%v want 2: %v", out["count"], out)
	}
	code, out = memoryAPI(t, s, token, http.MethodGet, base+"?kind=opsec", "")
	if code != http.StatusOK {
		t.Fatalf("opsec status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 1 {
		t.Fatalf("opsec count=%v want 1: %v", out["count"], out)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodGet, base+"?kind=bogus", ""); code != http.StatusBadRequest {
		t.Fatalf("bad kind status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodGet, base+"?limit=0", ""); code != http.StatusBadRequest {
		t.Fatalf("bad limit status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodGet, "/api/tasks/999999999/reflections", ""); code != http.StatusNotFound {
		t.Fatalf("unknown task status=%d want 404", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodGet, "/api/tasks/nope/reflections", ""); code != http.StatusBadRequest {
		t.Fatalf("bad task id status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, "", http.MethodGet, base, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d want 401", code)
	}
}

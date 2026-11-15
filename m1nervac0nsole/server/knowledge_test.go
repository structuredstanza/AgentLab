package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
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
	s := newFixtureServer(t, m)
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

// TestKnowledgeListReportsRelaxedQuery: the list response carries the relaxed
// flag so a UI or script can tell a widened result from the filter's answer.
func TestKnowledgeListReportsRelaxedQuery(t *testing.T) {
	m, s, token := memoryTestServer(t)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'mtest%'`) }()

	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/knowledge",
		`{"scope":"global","kind":"note","title":"mtestrelaxedprobe","body":"the egress probe retries"}`)
	if code != http.StatusOK {
		t.Fatalf("create status=%d body=%v", code, out)
	}

	// Both words are in the entry: the AND pass answers, nothing is relaxed.
	code, out = memoryAPI(t, s, token, http.MethodGet,
		"/api/knowledge?scope=global&q=mtestrelaxedprobe%20retries", "")
	if code != http.StatusOK {
		t.Fatalf("exact list status=%d body=%v", code, out)
	}
	if relaxed, ok := out["relaxed"].(bool); !ok || relaxed {
		t.Fatalf("exact list relaxed=%v want false: %v", out["relaxed"], out)
	}

	// The second word matches nothing, so the list widens and says so.
	code, out = memoryAPI(t, s, token, http.MethodGet,
		"/api/knowledge?scope=global&q=mtestrelaxedprobe%20nosuchword", "")
	if code != http.StatusOK {
		t.Fatalf("relaxed list status=%d body=%v", code, out)
	}
	if relaxed, ok := out["relaxed"].(bool); !ok || !relaxed {
		t.Fatalf("relaxed list relaxed=%v want true: %v", out["relaxed"], out)
	}
	if n, _ := out["count"].(float64); n < 1 {
		t.Fatalf("relaxed list returned nothing: %v", out)
	}
}

// knowledgeTestMux mounts the knowledge routes this slice owns under the
// contract's paths. Production mounts them in server.go; a test-local mux keeps
// the handlers exercised before that wiring lands, and a path that drifts from
// the contract fails here first.
func knowledgeTestMux(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/knowledge", s.listKnowledge)
	mux.HandleFunc("POST /api/knowledge", s.createKnowledge)
	mux.HandleFunc("GET /api/knowledge/stats", s.knowledgeStats)
	mux.HandleFunc("POST /api/knowledge/bulk", s.bulkKnowledge)
	mux.HandleFunc("GET /api/knowledge/{id}", s.getKnowledge)
	mux.HandleFunc("PATCH /api/knowledge/{id}", s.patchKnowledge)
	mux.HandleFunc("DELETE /api/knowledge/{id}", s.deleteKnowledge)
	mux.HandleFunc("POST /api/knowledge/{id}/promote", s.promoteKnowledge)
	mux.HandleFunc("POST /api/knowledge/{id}/demote", s.demoteKnowledge)
	return mux
}

// knowledgeCall issues one request against the test mux and decodes the JSON.
func knowledgeCall(t *testing.T, mux *http.ServeMux, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, reader))
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

// TestKnowledgeListPagesAndStats: total is the filtered set and stays put
// across pages, count is the page, and the stats counters partition the base.
func TestKnowledgeListPagesAndStats(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := knowledgeTestMux(s)
	tag := fmt.Sprintf("mtestpage%d", time.Now().UnixNano())
	for i := range 3 {
		code, out := knowledgeCall(t, mux, http.MethodPost, "/api/knowledge",
			fmt.Sprintf(`{"scope":"global","kind":"note","title":"mtestpage %d %s","tags":["%s"]}`, i, tag, tag))
		if code != http.StatusOK {
			t.Fatalf("create %d status=%d body=%v", i, code, out)
		}
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'mtestpage %'`) }()

	code, out := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge?tag="+tag+"&limit=2&sort=created&order=asc", "")
	if code != http.StatusOK {
		t.Fatalf("page 1 status=%d body=%v", code, out)
	}
	if total, _ := out["total"].(float64); total != 3 {
		t.Fatalf("page 1 total=%v want 3: %v", out["total"], out)
	}
	if n, _ := out["count"].(float64); n != 2 {
		t.Fatalf("page 1 count=%v want 2: %v", out["count"], out)
	}
	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/knowledge?tag="+tag+"&limit=2&offset=2", "")
	if code != http.StatusOK {
		t.Fatalf("page 2 status=%d body=%v", code, out)
	}
	if total, _ := out["total"].(float64); total != 3 {
		t.Fatalf("page 2 total=%v want 3: %v", out["total"], out)
	}
	if n, _ := out["count"].(float64); n != 1 {
		t.Fatalf("page 2 count=%v want 1: %v", out["count"], out)
	}
	if off, _ := out["offset"].(float64); off != 2 {
		t.Fatalf("page 2 offset=%v want 2", out["offset"])
	}
	// Past the end: no rows, still the real total.
	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/knowledge?tag="+tag+"&offset=99", "")
	if code != http.StatusOK {
		t.Fatalf("past end status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 0 {
		t.Fatalf("past end count=%v want 0: %v", out["count"], out)
	}
	if total, _ := out["total"].(float64); total != 3 {
		t.Fatalf("past end total=%v want 3: %v", out["total"], out)
	}

	// An explicit zero offset is a real page request, not an error.
	if code, out := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge?tag="+tag+"&offset=0", ""); code != http.StatusOK {
		t.Fatalf("offset=0 status=%d body=%v", code, out)
	}

	for _, tc := range []struct{ name, query string }{
		{"bad sort", "sort=bogus"},
		{"bad order", "order=sideways"},
		{"bad source", "source=bogus"},
		{"bad offset", "offset=abc"},
		{"bad created_after", "created_after=yesterday"},
	} {
		if code, _ := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge?"+tc.query, ""); code != http.StatusBadRequest {
			t.Errorf("%s: status=%d want 400", tc.name, code)
		}
	}

	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/stats", "")
	if code != http.StatusOK {
		t.Fatalf("stats status=%d body=%v", code, out)
	}
	total, _ := out["total"].(float64)
	if total < 3 {
		t.Fatalf("stats total=%v want at least the three rows just written", out["total"])
	}
	for _, key := range []string{"by_scope", "by_status", "by_kind", "by_source"} {
		dim, _ := out[key].(map[string]any)
		if dim == nil {
			t.Fatalf("stats missing %s: %v", key, out)
		}
		var sum float64
		for _, n := range dim {
			v, _ := n.(float64)
			sum += v
		}
		if sum != total {
			t.Fatalf("%s sums to %v, total=%v", key, sum, total)
		}
	}
}

// TestKnowledgeGetAndDryRunRoutes: the single-entry read 404s honestly, and a
// dry-run create reports the redactions a real write would make without
// storing anything.
func TestKnowledgeGetAndDryRunRoutes(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := knowledgeTestMux(s)
	title := fmt.Sprintf("mtestdry%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"scope":"global","kind":"technique","title":"%s","body":"mail ops@example.com from 10.9.8.7 with password=hunter2"}`, title)

	code, out := knowledgeCall(t, mux, http.MethodPost, "/api/knowledge?dry_run=true", body)
	if code != http.StatusOK {
		t.Fatalf("dry run status=%d body=%v", code, out)
	}
	if dry, _ := out["dry_run"].(bool); !dry {
		t.Fatalf("dry run flag missing: %v", out)
	}
	entry, _ := out["entry"].(map[string]any)
	if id, _ := entry["id"].(float64); id != 0 {
		t.Fatalf("dry run returned an id %v; it stored a row", entry["id"])
	}
	redactions, _ := out["redactions"].(float64)
	if redactions < 3 {
		t.Fatalf("dry run redactions=%v want the email, the IP and the password", out["redactions"])
	}
	previewBody, _ := entry["body"].(string)
	for _, leak := range []string{"ops@example.com", "10.9.8.7", "hunter2"} {
		if strings.Contains(previewBody, leak) {
			t.Fatalf("%q survived the preview: %q", leak, previewBody)
		}
	}
	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/knowledge?q="+title, "")
	if code != http.StatusOK {
		t.Fatalf("list after dry run status=%d body=%v", code, out)
	}
	if n, _ := out["count"].(float64); n != 0 {
		t.Fatalf("dry run stored a row: %v", out)
	}

	code, out = knowledgeCall(t, mux, http.MethodPost, "/api/knowledge", body)
	if code != http.StatusOK {
		t.Fatalf("create status=%d body=%v", code, out)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title=$1`, title) }()
	if got, _ := out["redactions"].(float64); got != redactions {
		t.Fatalf("preview counted %v redactions, the write made %v", redactions, got)
	}
	id := memoryEntryID(t, out)

	code, out = knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/"+strconv.FormatInt(id, 10), "")
	if code != http.StatusOK {
		t.Fatalf("get status=%d body=%v", code, out)
	}
	if got, _ := out["entry"].(map[string]any); got["title"] != title {
		t.Fatalf("get returned the wrong entry: %v", got)
	}
	if code, _ := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/999999999", ""); code != http.StatusNotFound {
		t.Fatalf("get unknown status=%d want 404", code)
	}
	if code, _ := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/nope", ""); code != http.StatusBadRequest {
		t.Fatalf("get bad id status=%d want 400", code)
	}
}

// TestKnowledgeDemoteRoute: a promoted entry comes back as a task candidate,
// the response admits the text is still generalised, and a task-scoped entry
// is refused.
func TestKnowledgeDemoteRoute(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := knowledgeTestMux(s)
	taskA, err := m.CreateTaskWithOptions("mtest demote", "find ssrf", db.TaskCreateOptions{Name: "mtest demote a"})
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := strconv.ParseInt(taskA.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(aID) }()
	taskB, err := m.CreateTaskWithOptions("mtest demote b", "find ssrf", db.TaskCreateOptions{Name: "mtest demote b"})
	if err != nil {
		t.Fatal(err)
	}
	bID, _ := strconv.ParseInt(taskB.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(bID) }()

	cand, _, err := m.pg.AddKnowledge(context.Background(), db.KnowledgeInput{
		Scope: "task", TaskID: aID, Kind: "technique",
		Title: fmt.Sprintf("mtestdemote%d", time.Now().UnixNano()),
		Body:  "the admin panel at 198.51.100.7 trusts X-Forwarded-For", Source: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/knowledge/" + strconv.FormatInt(cand.ID, 10)
	// A task-scoped entry has nowhere to be demoted to.
	if code, _ := knowledgeCall(t, mux, http.MethodPost, path+"/demote", fmt.Sprintf(`{"task_id":%d}`, bID)); code != http.StatusBadRequest {
		t.Fatalf("demote of a task entry status=%d want 400", code)
	}
	if code, out := knowledgeCall(t, mux, http.MethodPost, path+"/promote", `{"scope":"global"}`); code != http.StatusOK {
		t.Fatalf("promote status=%d body=%v", code, out)
	}

	code, out := knowledgeCall(t, mux, http.MethodPost, path+"/demote", fmt.Sprintf(`{"task_id":%d}`, bID))
	if code != http.StatusOK {
		t.Fatalf("demote status=%d body=%v", code, out)
	}
	entry, _ := out["entry"].(map[string]any)
	if entry["scope"] != "task" || entry["status"] != "candidate" {
		t.Fatalf("demote did not return a task candidate: %v", entry)
	}
	if tid, _ := entry["task_id"].(float64); int64(tid) != bID {
		t.Fatalf("demote landed on task %v want %d", entry["task_id"], bID)
	}
	if gen, _ := out["generalised"].(bool); !gen {
		t.Fatalf("demote must admit the text stays generalised: %v", out)
	}
	if body, _ := entry["body"].(string); strings.Contains(body, "198.51.100.7") {
		t.Fatalf("demote restored an identifier it cannot know: %q", body)
	}
	if code, _ := knowledgeCall(t, mux, http.MethodPost, path+"/demote", fmt.Sprintf(`{"task_id":%d}`, bID)); code != http.StatusBadRequest {
		t.Fatalf("second demote status=%d want 400", code)
	}
	if code, _ := knowledgeCall(t, mux, http.MethodPost, path+"/demote", `{}`); code != http.StatusBadRequest {
		t.Fatalf("demote without task_id status=%d want 400", code)
	}
	if code, _ := knowledgeCall(t, mux, http.MethodPost, "/api/knowledge/999999999/demote", fmt.Sprintf(`{"task_id":%d}`, bID)); code != http.StatusNotFound {
		t.Fatalf("demote unknown status=%d want 404", code)
	}
	if code, _ := knowledgeCall(t, mux, http.MethodPost, path+"/demote", `{"task_id":999999999}`); code != http.StatusNotFound {
		t.Fatalf("demote to unknown task status=%d want 404", code)
	}
}

// TestKnowledgeBulkReportsPerID: one bad id fails alone, every requested id
// gets its own row, and an unknown action is refused before anything runs.
func TestKnowledgeBulkReportsPerID(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	mux := knowledgeTestMux(s)
	suffix := fmt.Sprintf("mtestbulk%d", time.Now().UnixNano())
	var ids []int64
	for i := range 2 {
		code, out := knowledgeCall(t, mux, http.MethodPost, "/api/knowledge",
			fmt.Sprintf(`{"scope":"global","kind":"note","title":"%s %d"}`, suffix, i))
		if code != http.StatusOK {
			t.Fatalf("create %d status=%d body=%v", i, code, out)
		}
		ids = append(ids, memoryEntryID(t, out))
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE $1`, suffix+"%") }()

	payload := fmt.Sprintf(`{"ids":[%d,999999999,%d],"action":"retire"}`, ids[0], ids[1])
	code, out := knowledgeCall(t, mux, http.MethodPost, "/api/knowledge/bulk", payload)
	if code != http.StatusOK {
		t.Fatalf("bulk retire status=%d body=%v", code, out)
	}
	results, _ := out["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("bulk results=%d want one per id: %v", len(results), out)
	}
	for i, wantOK := range []bool{true, false, true} {
		row, _ := results[i].(map[string]any)
		if ok, _ := row["ok"].(bool); ok != wantOK {
			t.Fatalf("result %d ok=%v want %v: %v", i, row["ok"], wantOK, row)
		}
		if !wantOK {
			if msg, _ := row["error"].(string); msg == "" {
				t.Fatalf("failed result carries no error: %v", row)
			}
		}
	}
	// The batch did not abort: both real ids are retired.
	for _, id := range ids {
		code, out := knowledgeCall(t, mux, http.MethodGet, "/api/knowledge/"+strconv.FormatInt(id, 10), "")
		if code != http.StatusOK {
			t.Fatalf("get %d status=%d", id, code)
		}
		if entry, _ := out["entry"].(map[string]any); entry["status"] != "retired" {
			t.Fatalf("entry %d status=%v want retired", id, entry["status"])
		}
	}

	// A task-scoped entry cannot be adopted through the bulk path either.
	task, err := m.CreateTaskWithOptions("mtest bulk task", "goal", db.TaskCreateOptions{Name: "mtest bulk"})
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()
	taskEntry, _, err := m.pg.AddKnowledge(context.Background(), db.KnowledgeInput{
		Scope: "task", TaskID: taskID, Kind: "note", Title: suffix + " task", Source: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	code, out = knowledgeCall(t, mux, http.MethodPost, "/api/knowledge/bulk",
		fmt.Sprintf(`{"ids":[%d],"action":"adopt"}`, taskEntry.ID))
	if code != http.StatusOK {
		t.Fatalf("bulk adopt status=%d body=%v", code, out)
	}
	if rows, _ := out["results"].([]any); len(rows) != 1 {
		t.Fatalf("bulk adopt results=%v", out)
	} else if row, _ := rows[0].(map[string]any); row["ok"] != false {
		t.Fatalf("bulk adopted a task entry: %v", row)
	}

	for _, tc := range []struct{ name, body string }{
		{"unknown action", fmt.Sprintf(`{"ids":[%d],"action":"explode"}`, ids[0])},
		{"no ids", `{"ids":[],"action":"delete"}`},
		{"promote without scope", fmt.Sprintf(`{"ids":[%d],"action":"promote"}`, ids[0])},
		{"too many", `{"ids":[` + strings.TrimSuffix(strings.Repeat("1,", 101), ",") + `],"action":"delete"}`},
	} {
		if code, _ := knowledgeCall(t, mux, http.MethodPost, "/api/knowledge/bulk", tc.body); code != http.StatusBadRequest {
			t.Errorf("%s: status=%d want 400", tc.name, code)
		}
	}
}

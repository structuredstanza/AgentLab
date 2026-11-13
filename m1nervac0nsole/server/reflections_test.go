package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// reflectionServer builds a server over the real test database and creates two
// tasks whose reflections are cleaned up by the task cascade.
func reflectionServer(t *testing.T) (*Server, int64, int64) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	ids := make([]int64, 2)
	for i := range ids {
		tk, err := m.CreateTask("reflection curation", "goal", nil, 0, 0)
		if err != nil {
			t.Fatalf("create task %d: %v", i, err)
		}
		ids[i] = mustTaskID(t, tk.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_ = m.pg.DeleteTask(id)
		}
	})
	return &Server{m: m}, ids[0], ids[1]
}

// addReflection writes one row straight through the store.
func addReflection(t *testing.T, s *Server, taskID int64, kind, source, summary, detail string) db.Reflection {
	t.Helper()
	r, _, err := s.m.PG().AddReflection(context.Background(), db.ReflectionInput{
		TaskID: taskID, Kind: kind, Source: source, Summary: summary, Detail: detail})
	if err != nil {
		t.Fatalf("add reflection %q: %v", summary, err)
	}
	return r
}

// TestListReflectionsHandlerCrossTask covers the cross-task page, its paging
// fields, the shared tokenizer behind q, and the narrowing filters over HTTP.
// The shared test database holds other tasks' rows, so each assertion is scoped
// by a unique marker term.
func TestListReflectionsHandlerCrossTask(t *testing.T) {
	s, taskA, taskB := reflectionServer(t)
	marker := "zqhandler" + strconv.FormatInt(time.Now().UnixNano(), 10)
	addReflection(t, s, taskA, "learning", "worker", marker+" repeated scanning of the mail port", "")
	addReflection(t, s, taskA, "opsec", "engine", marker+" rate limiting appeared after ten requests", "")
	addReflection(t, s, taskB, "noise", "planner", marker+" scanning burst from a single client", "")
	addReflection(t, s, taskA, "learning", "worker", "zqratelimiting appeared on the mail port", "")
	addReflection(t, s, taskB, "mistake", "worker", "zqratelimiting appeared on the api port", "")

	get := func(query string) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.listReflections(rec, httptest.NewRequest(http.MethodGet, "/api/reflections"+query, nil))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := get("?q=" + marker + "&limit=2")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, out)
	}
	if out["total"] != float64(3) || out["count"] != float64(2) || out["limit"] != float64(2) {
		t.Fatalf("page fields: %v", out)
	}
	rows, _ := out["reflections"].([]any)
	if len(rows) != 2 {
		t.Fatalf("page rows: %v", rows)
	}
	first, _ := rows[0].(map[string]any)
	second, _ := rows[1].(map[string]any)
	taskIDs := map[any]bool{first["task_id"]: true, second["task_id"]: true}
	if len(taskIDs) != 2 {
		t.Fatalf("newest two rows should come from both tasks: %v", taskIDs)
	}

	_, out = get("?q=" + marker + "&limit=2&offset=2")
	if out["total"] != float64(3) || out["count"] != float64(1) {
		t.Fatalf("second page: %v", out)
	}

	// q runs through MemorySearchTerms, so an inflection stems onto the stored
	// lexeme.
	_, out = get("?q=zqratelimited")
	if out["total"] != float64(2) {
		t.Fatalf("stemmed query total: %v", out)
	}
	_, out = get("?q=" + marker + "&task_id=" + strconv.FormatInt(taskA, 10))
	if out["total"] != float64(2) {
		t.Fatalf("task filter: %v", out)
	}
	_, out = get("?q=" + marker + "&kind=noise")
	if out["total"] != float64(1) {
		t.Fatalf("kind filter: %v", out)
	}
	_, out = get("?q=" + marker + "&source=engine")
	if out["total"] != float64(1) {
		t.Fatalf("source filter: %v", out)
	}
	_, out = get("?q=" + marker + "&since=2999-01-01")
	if out["total"] != float64(0) {
		t.Fatalf("since filter: %v", out)
	}

	for _, bad := range []string{"?kind=bogus", "?source=bogus", "?offset=-1", "?limit=x", "?since=yesterday"} {
		if code, out := get(bad); code != http.StatusBadRequest {
			t.Fatalf("%s should be rejected, got %d %v", bad, code, out)
		}
	}
}

// TestReflectionStatsHandler checks the breakdowns the curation header reads.
func TestReflectionStatsHandler(t *testing.T) {
	s, taskA, taskB := reflectionServer(t)
	addReflection(t, s, taskA, "learning", "worker", "learned one", "")
	addReflection(t, s, taskB, "opsec", "engine", "learned two", "")

	rec := httptest.NewRecorder()
	s.reflectionStats(rec, httptest.NewRequest(http.MethodGet, "/api/reflections/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total    int            `json:"total"`
		ByKind   map[string]int `json:"by_kind"`
		BySource map[string]int `json:"by_source"`
		ByTask   []struct {
			TaskID int64 `json:"task_id"`
			Count  int   `json:"count"`
		} `json:"by_task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total < 2 || out.ByKind["learning"] < 1 || out.BySource["engine"] < 1 {
		t.Fatalf("stats: %+v", out)
	}
	byTask := map[int64]int{}
	for _, row := range out.ByTask {
		byTask[row.TaskID] = row.Count
	}
	if byTask[taskA] != 1 || byTask[taskB] != 1 {
		t.Fatalf("by_task: %v", byTask)
	}
}

// TestPatchAndDeleteReflectionHandler: patch edits summary/detail and refuses
// to touch anything else; delete removes the row and reports a missing one.
func TestPatchAndDeleteReflectionHandler(t *testing.T) {
	s, taskA, _ := reflectionServer(t)
	refl := addReflection(t, s, taskA, "mistake", "worker", "probed before the session warmed", "empty jar")

	req := httptest.NewRequest(http.MethodPatch, "/api/reflections/1",
		strings.NewReader(`{"summary":"probed with token=supersecretvalue123","detail":"warm jar","kind":"noise"}`))
	req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
	rec := httptest.NewRecorder()
	s.patchReflection(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	var patched struct {
		Reflection db.Reflection `json:"reflection"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatal(err)
	}
	if patched.Reflection.Kind != refl.Kind || patched.Reflection.Source != refl.Source ||
		patched.Reflection.TaskID != refl.TaskID {
		t.Fatalf("patch changed a write-time fact: %+v", patched.Reflection)
	}
	if strings.Contains(patched.Reflection.Summary, "supersecretvalue123") {
		t.Fatalf("edited summary kept a secret: %q", patched.Reflection.Summary)
	}
	if patched.Reflection.Detail != "warm jar" {
		t.Fatalf("detail not updated: %q", patched.Reflection.Detail)
	}

	for _, body := range []string{`{}`, `not json`} {
		req := httptest.NewRequest(http.MethodPatch, "/api/reflections/1", strings.NewReader(body))
		req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
		rec := httptest.NewRecorder()
		s.patchReflection(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s should be rejected, got %d", body, rec.Code)
		}
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/reflections/1", nil)
	req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
	rec = httptest.NewRecorder()
	s.deleteReflection(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/reflections/1", nil)
	req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
	rec = httptest.NewRecorder()
	s.deleteReflection(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestGraduateReflectionHandler: graduation writes a task-scoped candidate with
// source=reflection into the reflection's own task, visible through the
// existing knowledge list, tagged with its origin.
func TestGraduateReflectionHandler(t *testing.T) {
	s, taskA, taskB := reflectionServer(t)
	refl := addReflection(t, s, taskA, "opsec", "worker",
		"back off after a 429 from the login form", "sleep 60 then retry once")

	req := httptest.NewRequest(http.MethodPost, "/api/reflections/1/graduate",
		strings.NewReader(`{"kind":"technique","tags":["rate-limit"]}`))
	req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
	rec := httptest.NewRecorder()
	s.graduateReflection(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("graduate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Entry      db.KnowledgeEntry `json:"entry"`
		Redactions int               `json:"redactions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	entry := out.Entry
	if entry.Scope != "task" || entry.Status != "candidate" || entry.Source != "reflection" {
		t.Fatalf("graduated entry: %+v", entry)
	}
	if entry.TaskID != taskA {
		t.Fatalf("graduated into task %d, want %d", entry.TaskID, taskA)
	}
	if entry.Title != refl.Summary {
		t.Fatalf("default title: %q, want %q", entry.Title, refl.Summary)
	}
	if entry.Body != refl.Detail || entry.Kind != "technique" {
		t.Fatalf("body/kind: %+v", entry)
	}
	found := false
	for _, tag := range entry.Tags {
		if tag == fmt.Sprintf("reflection:%d", refl.ID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("origin tag missing: %v", entry.Tags)
	}

	listed, err := s.m.PG().ListKnowledge(context.Background(), db.KnowledgeFilter{TaskID: taskA})
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, e := range listed {
		if e.ID == entry.ID {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("graduated entry %d not in the task's knowledge list", entry.ID)
	}
	other, err := s.m.PG().ListKnowledge(context.Background(), db.KnowledgeFilter{TaskID: taskB})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range other {
		if e.ID == entry.ID {
			t.Fatalf("graduated entry leaked into another task")
		}
	}

	// A body-supplied title wins, and a bad kind or a missing reflection is
	// refused before anything is written.
	req = httptest.NewRequest(http.MethodPost, "/api/reflections/1/graduate",
		strings.NewReader(`{"kind":"note","title":"429 backoff rule"}`))
	req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
	rec = httptest.NewRecorder()
	s.graduateReflection(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("titled graduate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var titled struct {
		Entry db.KnowledgeEntry `json:"entry"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &titled); err != nil {
		t.Fatal(err)
	}
	if titled.Entry.Title != "429 backoff rule" {
		t.Fatalf("explicit title ignored: %q", titled.Entry.Title)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/reflections/1/graduate",
		strings.NewReader(`{"kind":"bogus"}`))
	req.SetPathValue("id", strconv.FormatInt(refl.ID, 10))
	rec = httptest.NewRecorder()
	s.graduateReflection(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad kind status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/reflections/999999999/graduate",
		strings.NewReader(`{"kind":"note"}`))
	req.SetPathValue("id", "999999999")
	rec = httptest.NewRecorder()
	s.graduateReflection(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing reflection status=%d body=%s", rec.Code, rec.Body.String())
	}
}

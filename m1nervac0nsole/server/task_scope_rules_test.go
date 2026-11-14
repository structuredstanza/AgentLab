package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// The rule routes are thin over the store, but they must exist, round-trip, and
// not collide with the scope-row routes they sit beside.
func TestScopeRuleRoutes(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_PG_DSN") == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	m, s, _ := memoryTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tasks/{id}/scope/rules", s.taskScopeRuleList)
	mux.HandleFunc("POST /api/tasks/{id}/scope/rules", s.taskScopeRuleAdd)
	mux.HandleFunc("DELETE /api/tasks/{id}/scope/rules/{rid}", s.taskScopeRuleDelete)

	task, err := m.CreateTaskWithOptions("mtest scope rules", "rules over rows", db.TaskCreateOptions{Name: "mtest scope rules"})
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })
	base := "/api/tasks/" + task.ID + "/scope/rules"

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, base,
		strings.NewReader(`{"effect":"exclude","pattern":"blocked.invalid","note":"vendor"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("add status %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("add body %q (%v)", rec.Body.String(), err)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base, nil))
	var listed struct {
		Rules []db.TaskScopeRule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Rules) != 1 || listed.Rules[0].Pattern != "blocked.invalid" || listed.Rules[0].Effect != "exclude" {
		t.Fatalf("listed = %+v", listed.Rules)
	}

	// A bad effect is a 400, not a 500.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, base, strings.NewReader(`{"effect":"maybe","pattern":"x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad effect status %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, base+"/"+itoa(created.ID), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, base+"/"+itoa(created.ID), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete status %d", rec.Code)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

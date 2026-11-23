package server

import (
	"net/http"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

func TestTaskSpeedProfileAPI(t *testing.T) {
	m, s, token := memoryTestServer(t)
	task, err := m.CreateTaskWithOptions("speed api", "goal", db.TaskCreateOptions{Name: "speed api"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.pg.DeleteTask(mustTaskID(t, task.ID)) }()
	path := "/api/tasks/" + task.ID

	// Metadata edits need an operator session: no token, no write.
	if code, _ := memoryAPI(t, s, "", http.MethodPatch, path, `{"speed_profile":"stealth"}`); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PATCH = %d, want 401", code)
	}
	if code, _ := memoryAPI(t, s, "", http.MethodPost, "/api/tasks", `{"goal":"g","speed_profile":"stealth"}`); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST = %d, want 401", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPatch, path, `{"speed_profile":"warp"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid PATCH = %d, want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPost, "/api/tasks", `{"goal":"g","speed_profile":"warp"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid POST = %d, want 400", code)
	}

	code, out := memoryAPI(t, s, token, http.MethodGet, path, "")
	if code != http.StatusOK || out["speed_profile"] != "standard" {
		t.Fatalf("default DTO = %d %v, want standard", code, out["speed_profile"])
	}
	code, out = memoryAPI(t, s, token, http.MethodPatch, path, `{"speed_profile":"unbound"}`)
	if code != http.StatusOK || out["speed_profile"] != "unbound" {
		t.Fatalf("PATCH = %d %v, want unbound", code, out["speed_profile"])
	}
	if got, err := m.pg.TaskSpeedProfile(mustTaskID(t, task.ID)); err != nil || got != "unbound" {
		t.Fatalf("persisted profile=%q,%v want unbound", got, err)
	}
	code, out = memoryAPI(t, s, token, http.MethodGet, path, "")
	if code != http.StatusOK || out["speed_profile"] != "unbound" {
		t.Fatalf("detail DTO = %d %v, want unbound", code, out["speed_profile"])
	}
}

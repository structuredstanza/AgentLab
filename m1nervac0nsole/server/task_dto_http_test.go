package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTaskDTOHTTPFieldsRoundtrip(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	do := func(method, path string, body any) (int, map[string]any) {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// 1. Create task with explicit plan_quiet_mode=false and llm_rotate=true
	rotateOn := true
	quietOff := false
	createReq := map[string]any{
		"description":     "probe dto fields",
		"goal":            "Probe the target at http://127.0.0.1:9090/v1 for testing DTO roundtrip fields; verify and return.",
		"llm_rotate":      rotateOn,
		"plan_quiet_mode": quietOff,
	}
	code, out := do("POST", "/api/tasks", createReq)
	if code != 201 {
		t.Fatalf("create task: %d (%v)", code, out)
	}
	taskID, _ := out["id"].(string)
	if taskID == "" {
		t.Fatalf("missing id in response: %v", out)
	}

	// Verify plan_quiet_mode and llm_rotate on createTask response
	if q, ok := out["plan_quiet_mode"].(bool); !ok || q != false {
		t.Fatalf("expected plan_quiet_mode=false, got %v (%T)", out["plan_quiet_mode"], out["plan_quiet_mode"])
	}
	if r, ok := out["llm_rotate"].(bool); !ok || r != true {
		t.Fatalf("expected llm_rotate=true, got %v (%T)", out["llm_rotate"], out["llm_rotate"])
	}

	// 2. PATCH task metadata to toggle plan_quiet_mode back to true
	patchCode, patchOut := do("PATCH", "/api/tasks/"+taskID, map[string]any{"plan_quiet_mode": true})
	if patchCode != 200 {
		t.Fatalf("patch plan_quiet_mode: %d (%v)", patchCode, patchOut)
	}
	if q, ok := patchOut["plan_quiet_mode"].(bool); !ok || q != true {
		t.Fatalf("expected patched plan_quiet_mode=true, got %v", patchOut["plan_quiet_mode"])
	}

	// 3. Pause task and verify paused_at in GET /api/tasks/{id}
	pauseCode, pauseOut := do("POST", "/api/tasks/control/batch", map[string]any{"action": "pause", "task_ids": []string{taskID}})
	if pauseCode != 200 {
		t.Fatalf("pause task: %d (%v)", pauseCode, pauseOut)
	}
	getCode, getOut := do("GET", "/api/tasks/"+taskID, nil)
	if getCode != 200 {
		t.Fatalf("get task: %d (%v)", getCode, getOut)
	}
	if p, ok := getOut["paused"].(bool); !ok || !p {
		t.Fatalf("expected paused=true, got %v", getOut["paused"])
	}
	if pAt, ok := getOut["paused_at"].(string); !ok || pAt == "" {
		t.Fatalf("expected paused_at RFC3339 timestamp string, got %v", getOut["paused_at"])
	}
}

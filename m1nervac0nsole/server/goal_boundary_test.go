package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

func TestGoalBoundary(t *testing.T) {
	for host, want := range map[string]string{
		"10.129.250.7":      "10.129.250.0/24",
		"2001:db8:1:2::5":   "2001:db8:1:2::/64",
		"app.example.com":   "*.example.com",
		"www.example.co.uk": "*.example.co.uk",
		"co.uk":             "co.uk",
		"localhost":         "localhost",
	} {
		if got := goalBoundary(host); got != want {
			t.Errorf("goalBoundary(%q) = %q, want %q", host, got, want)
		}
	}
}

// The target in the task text is authorized with its boundary, exactly once,
// by "goal".
func TestAuthorizeGoalBoundary(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) - skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("goal boundary fixture", "seed", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	s := &Server{m: &Manager{pg: d}}
	tk := &Task{ID: strconv.FormatInt(task.ID, 10)}

	s.seedGoalBoundary(tk, "10.129.250.7", true)
	s.seedGoalBoundary(tk, "10.129.250.9", true) // same /24: no duplicate
	s.seedGoalBoundary(tk, "app.example.com", true)

	rules, err := d.ListPolicyRules(context.Background(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rules {
		if r.Effect != "include" || !r.Authorized || r.Protocol != "any" {
			t.Errorf("rule %+v must be an authorized include", r)
		}
		got[r.Pattern] = true
	}
	if len(rules) != 2 || !got["10.129.250.0/24"] || !got["*.example.com"] {
		t.Fatalf("rules = %+v", rules)
	}
	var by string
	if err := d.QueryRow(`SELECT approved_by FROM task_scope_rules WHERE id=$1`, rules[0].ID).Scan(&by); err != nil || by != "goal" {
		t.Fatalf("approved_by = %q, %v", by, err)
	}
	// Server without a database must not panic.
	(&Server{m: &Manager{}}).seedGoalBoundary(tk, "10.0.0.1", true)
}

func TestTaskLaunchSeedsGoalApprovalByCaller(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	previous, found, err := m.pg.GetSetting(settingConcurrencyOn)
	if err != nil {
		t.Fatal(err)
	}
	// With no model configured, both launches queue instead of starting work.
	if err := m.pg.SetSetting(settingConcurrencyOn, "true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if found {
			_ = m.pg.SetSetting(settingConcurrencyOn, previous)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingConcurrencyOn)
		}
	})
	s := &Server{m: m, ctx: t.Context(), engine: NewEngine(m)}
	const payload = `{"description":"Approval fixture","goal":"Document the expected fixture boundary for https://192.0.2.12 without making any network requests."}`
	for _, tc := range []struct {
		actor      string
		authorized bool
	}{{"agent", false}, {"goal", true}} {
		t.Run(tc.actor, func(t *testing.T) {
			var id string
			if tc.authorized {
				rec := httptest.NewRecorder()
				s.createTask(rec, httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(payload)))
				var task TaskDTO
				if err := json.Unmarshal(rec.Body.Bytes(), &task); err != nil || rec.Code != http.StatusCreated {
					t.Fatalf("create task: status=%d, body=%s, err=%v", rec.Code, rec.Body, err)
				}
				id = task.ID
			} else {
				res, err := s.toolSpawnTask().Call(t.Context(), json.RawMessage(payload), nil)
				if err != nil || res.IsError {
					t.Fatalf("spawn_task: %v, %s", err, res.Flatten())
				}
				var ok bool
				id, ok = strings.CutPrefix(res.Flatten(), "task created: ")
				if !ok {
					t.Fatalf("spawn_task response = %q", res.Flatten())
				}
			}
			taskID := mustTaskID(t, id)
			t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })
			rules, err := m.pg.ListPolicyRules(t.Context(), taskID)
			if err != nil || len(rules) != 1 {
				t.Fatalf("seeded rules = %+v, err=%v, want one", rules, err)
			}
			r := rules[0]
			if r.Effect != "include" || r.Pattern != "192.0.2.0/24" || r.Protocol != "any" || r.Authorized != tc.authorized {
				t.Fatalf("seeded rule = %+v, want include 192.0.2.0/24 any (authorized=%t)", r, tc.authorized)
			}
			var by string
			var hasTime bool
			err = m.pg.QueryRowContext(t.Context(), `SELECT approved_by, approved_at IS NOT NULL FROM task_scope_rules WHERE id=$1`, r.ID).Scan(&by, &hasTime)
			if err != nil || by != tc.actor || hasTime != tc.authorized {
				t.Fatalf("seeded audit = %q, has approval time=%t, err=%v", by, hasTime, err)
			}
		})
	}
}

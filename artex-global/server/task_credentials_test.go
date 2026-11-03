package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Task credentials (#3): declared at creation, listed/upserted/deleted via the
// API, and recorded by the agent path (ExplorationStore upsert, source=agent).
func TestTaskCredentialsFlow(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	snapshot := func() [6]int {
		t.Helper()
		var counts [6]int
		err := s.m.PG().QueryRow(`SELECT
			(SELECT count(*) FROM tasks),
			(SELECT count(*) FROM explorations),
			(SELECT count(*) FROM exploration_nodes),
			(SELECT count(*) FROM task_credentials),
			(SELECT count(*) FROM task_llm_profiles),
			(SELECT count(*) FROM task_intercept_rules)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5])
		if err != nil {
			t.Fatal(err)
		}
		return counts
	}
	before, beforeTasks, beforeActive := snapshot(), len(s.m.List()), s.m.ActiveTask()
	t.Cleanup(func() {
		for _, task := range s.m.List() {
			if task.Description == "credential rejection test" || task.Description == "credential storage failure test" {
				id, _ := json.Number(task.ID).Int64()
				_ = s.m.PG().DeleteTask(id)
			}
		}
	})

	// Create a task carrying two credentials: one complete, one "agent generates".
	var created struct {
		ID string `json:"id"`
	}
	resp := request("POST", "/api/tasks", `{
		"description": "credential rejection test",
		"goal": "Verify credential handling against the lab target at http://127.0.0.1:9/v1 and record the outcome.",
		"credentials": [
			{"domain": "target.example.com", "username": "alias@test", "password": "s3cret!", "note": "program alias account"},
			{"domain": "target.example.com", "username": "", "password": ""}
		]
	}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("an entry without a username must be rejected, got HTTP %d: %s", resp.Code, resp.Body.String())
	}
	if after := snapshot(); after != before || len(s.m.List()) != beforeTasks || s.m.ActiveTask() != beforeActive {
		t.Fatalf("rejected creation mutated state: before=%v after=%v manager_tasks=%d->%d active_changed=%v",
			before, after, beforeTasks, len(s.m.List()), s.m.ActiveTask() != beforeActive)
	}

	// A storage failure after the first valid insert must roll back the entire task.
	if _, err := s.m.PG().Exec(`ALTER TABLE task_credentials ADD CONSTRAINT credential_creation_failure_fixture CHECK (username <> 'storage-failure') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.m.PG().Exec(`ALTER TABLE task_credentials DROP CONSTRAINT IF EXISTS credential_creation_failure_fixture`)
	})
	resp = request("POST", "/api/tasks", `{
		"description":"credential storage failure test",
		"goal":"Verify credential handling against the lab target at http://127.0.0.1:9/v1 and record the outcome.",
		"credentials":[
			{"domain":"target.example.com","username":"first","password":"must-not-appear"},
			{"domain":"target.example.com","username":"storage-failure","password":"must-not-appear"}
		]
	}`)
	if resp.Code != http.StatusInternalServerError || strings.Contains(resp.Body.String(), "must-not-appear") {
		t.Fatalf("storage failure was not safely reported: HTTP %d %s", resp.Code, resp.Body.String())
	}
	if after := snapshot(); after != before || len(s.m.List()) != beforeTasks || s.m.ActiveTask() != beforeActive {
		t.Fatalf("storage failure published a partial task: before=%v after=%v", before, after)
	}

	resp = request("POST", "/api/tasks", `{
		"description": "credential flow test",
		"goal": "Verify credential handling against the lab target at http://127.0.0.1:9/v1 and record the outcome.",
		"credentials": [
			{"domain": "target.example.com", "username": "alias@test", "password": "\t s3cret! \u00a0", "note": "program alias account"},
			{"domain": "app.target.example.com", "username": "agent-account", "password": ""}
		]
	}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("create with credentials failed, HTTP %d: %s", resp.Code, resp.Body.String())
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("bad create response: %s", resp.Body.String())
	}
	taskNum := json.Number(created.ID)
	id, err := taskNum.Int64()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.PG().Exec(`DELETE FROM tasks WHERE id=$1`, id) })

	// List: both rows, user source, order stable.
	resp = request("GET", fmt.Sprintf("/api/tasks/%s/credentials", created.ID), "")
	if resp.Code != http.StatusOK {
		t.Fatalf("list failed, HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var list []db.TaskCredential
	if err := json.Unmarshal(resp.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 credentials, got %d: %s", len(list), resp.Body.String())
	}
	if list[0].Domain != "target.example.com" || list[0].Username != "alias@test" || list[0].Password != "\t s3cret! \u00a0" || list[0].Note != "program alias account" {
		t.Fatalf("declared credential mismatch: %+v", list[0])
	}
	if list[1].Password != "" {
		t.Fatalf("agent-generates entry must keep an empty password until recorded, got %q", list[1].Password)
	}

	// The agent path records the generated password onto the empty entry.
	task, ok := s.m.Task(created.ID)
	if !ok {
		t.Fatal("committed task was not published")
	}
	if _, err := task.Store.UpsertTaskCredential(id, db.TaskCredentialInput{
		Domain: "app.target.example.com", Username: "agent-account", Password: " \tgenerated-strong-pass\u2003 ",
		Source: "agent",
	}); err != nil {
		t.Fatal(err)
	}
	list, err = s.m.PG().TaskCredentials(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[1].Password != " \tgenerated-strong-pass\u2003 " || list[1].Source != "agent" {
		t.Fatalf("agent record must update in place, got %+v", list[1])
	}

	// Manual add + delete through the API.
	resp = request("POST", fmt.Sprintf("/api/tasks/%s/credentials", created.ID),
		`{"domain":"other.example.com","username":"relay","password":"\t otp-verified "}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("manual add failed, HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var added db.TaskCredential
	if err := json.Unmarshal(resp.Body.Bytes(), &added); err != nil {
		t.Fatal(err)
	}
	if added.Password != "\t otp-verified " {
		t.Fatalf("manual password changed: %q", added.Password)
	}
	resp = request("DELETE", fmt.Sprintf("/api/tasks/%s/credentials/%d", created.ID, added.ID), "")
	if resp.Code != http.StatusOK {
		t.Fatalf("delete failed, HTTP %d: %s", resp.Code, resp.Body.String())
	}
	list, _ = s.m.PG().TaskCredentials(id)
	if len(list) != 2 {
		t.Fatalf("after delete want 2 credentials, got %d", len(list))
	}

	// A delete from another task must not cross tasks.
	resp = request("DELETE", fmt.Sprintf("/api/tasks/%s/credentials/999999", created.ID), "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("foreign credential delete must 404, got HTTP %d", resp.Code)
	}
}

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

func TestUnboundEvidenceMessageNamesFindings(t *testing.T) {
	msg := unboundEvidenceMessage([]*pgdb.DBFinding{
		{ID: 122, Name: "SQL login hash dump"},
		{ID: 126, VulnClass: "sqli"},
		{ID: 129, Name: "bound finding", EvidenceVersion: 1},
	})
	for _, want := range []string{"#122 SQL login hash dump", "#126 sqli", "2 finding(s)"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "#129") {
		t.Fatalf("message names an already bound finding: %q", msg)
	}
	if got := unboundEvidenceMessage(nil); got != "" {
		t.Fatalf("a task without findings must not be blocked: %q", got)
	}
	if got := unboundEvidenceMessage([]*pgdb.DBFinding{{ID: 1, EvidenceVersion: 3}}); got != "" {
		t.Fatalf("a task with bound evidence must not be blocked: %q", got)
	}
	// A rejected finding is no longer a claim, so its missing evidence must not
	// block archiving a task whose findings were all dismissed.
	for _, status := range []string{pgdb.FindingFalsePositive, pgdb.FindingDuplicate, pgdb.FindingIgnored} {
		if got := unboundEvidenceMessage([]*pgdb.DBFinding{{ID: 9, Status: status}}); got != "" {
			t.Fatalf("%s finding must not block archiving: %q", status, got)
		}
	}
	if got := unboundEvidenceMessage([]*pgdb.DBFinding{{ID: 9, Status: pgdb.FindingConfirmed}}); got == "" {
		t.Fatal("a confirmed finding without bound evidence must still block archiving")
	}
}

// TestTaskArchiveEvidenceGate is DB-backed: it needs the real store to create
// findings with evidence_version 0 and to queue archives, so it skips without
// M1NERVAC0NSOLE_PG_DSN like the other archive tests.
func TestTaskArchiveEvidenceGate(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	create := func(name string) *Task {
		t.Helper()
		task, err := m.CreateTask(name, "verify the evidence gate", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		taskID, err := strconv.ParseInt(task.ID, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, taskID)
			_ = m.pg.DeleteTask(taskID)
		})
		return task
	}
	blocked := create("archive evidence blocked")
	clean := create("archive evidence clean")
	rejected := create("archive evidence rejected")
	blockedID, _ := strconv.ParseInt(blocked.ID, 10, 64)
	findingID, err := m.pg.AddFinding(blockedID, 0, "credential", "SQL login hashes", "high", "five hashes", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A finding rejected as a false positive is no longer a claim: its missing
	// evidence must not make the task unarchivable without force.
	rejectedID, _ := strconv.ParseInt(rejected.ID, 10, 64)
	rejectedFinding, err := m.pg.AddFinding(rejectedID, 0, "sqli", "false alarm", "low", "not reproducible", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.SetFindingStatus(rejectedFinding, pgdb.FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	for _, task := range []*Task{blocked, clean, rejected} {
		taskID, _ := strconv.ParseInt(task.ID, 10, 64)
		if err := m.pg.SetPaused(taskID, true); err != nil {
			t.Fatal(err)
		}
	}

	// Start with an already-cancelled context so the background archive worker
	// exits and these route-contract assertions only observe queued rows.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dataDir := t.TempDir()
	s := New(ctx, m, dataDir, dataDir, dataDir)
	t.Cleanup(func() { drainFixtureServer(s, m) })
	s.archiveWG.Wait()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		s.Handler().ServeHTTP(recorder, req)
		return recorder
	}
	archivePath := "/api/tasks/" + blocked.ID + "/archive"
	blockedText := "#" + strconv.FormatInt(findingID, 10) + " SQL login hashes"

	recorder := request(http.MethodPost, archivePath, "{}")
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), blockedText) {
		t.Fatalf("unbound evidence archive status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	// The UI's plain archive call sends no body; that must reach the same gate.
	recorder = request(http.MethodPost, archivePath, "")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("empty body archive status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	// A task whose only finding was rejected is archivable without force.
	rejectedPath := "/api/tasks/" + rejected.ID + "/archive"
	recorder = request(http.MethodPost, rejectedPath, "{}")
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("rejected finding archive status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	// One blocked task must not fail the whole batch.
	body, _ := json.Marshal(map[string]any{"task_ids": []string{blocked.ID, clean.ID}})
	recorder = request(http.MethodPost, "/api/tasks/archive/batch", string(body))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("batch status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var batch struct {
		Items []struct {
			ID     string `json:"id"`
			OK     bool   `json:"ok"`
			Queued bool   `json:"queued"`
			Error  string `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Items) != 2 {
		t.Fatalf("batch items=%+v", batch.Items)
	}
	for _, item := range batch.Items {
		switch item.ID {
		case blocked.ID:
			if item.OK || item.Queued || !strings.Contains(item.Error, blockedText) {
				t.Fatalf("blocked batch item=%+v", item)
			}
		case clean.ID:
			if !item.OK || !item.Queued || item.Error != "" {
				t.Fatalf("clean batch item=%+v", item)
			}
		default:
			t.Fatalf("unexpected batch item=%+v", item)
		}
	}

	recorder = request(http.MethodPost, archivePath, `{"force":true}`)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("forced archive status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

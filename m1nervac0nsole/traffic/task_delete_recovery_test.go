package traffic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func seedRecoveryExchange(t *testing.T, tr *Traffic, id string, taskID int64, host string) {
	t.Helper()
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,task_id,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?,'')`, id, 1, nullIfZero(taskID), host, "GET", "/p", "https://"+host+"/p", 200, "text/plain", 1, 1); err != nil {
		t.Fatal(err)
	}
}

// DeleteTask stages its task-scoped deletion, commits PostgreSQL, then commits
// SQLite. A process exit between the two leaves the rows in the hot store with
// nothing pointing at them, so the journal carries the exact IDs: recovery can
// finish that deletion, and nothing else.
func TestTaskDeleteStageResolvesFromPostgresAfterCrash(t *testing.T) {
	dir := t.TempDir()
	tr, err := OpenWithTransport(dir, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	const host = "gone.example"
	seedRecoveryExchange(t, tr, "1-0001", 42, host)
	seedRecoveryExchange(t, tr, "1-0002", 42, host)
	seedRecoveryExchange(t, tr, "1-0003", 43, host) // another run at the same host

	stage, err := tr.StageDeleteTask(42)
	if err != nil {
		t.Fatal(err)
	}
	// process exit: SQLite rolls back, the staging journal stays on disk
	if err := stage.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	stage.done = true
	stage.traffic.wmu.Unlock()
	_ = tr.Close()

	tr2, err := OpenWithTransport(dir, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr2.Close() })
	// A task-42 capture written after the journal was created: it is not in the
	// journal, so finishing the deletion must leave it alone.
	seedRecoveryExchange(t, tr2, "1-0004", 42, host)

	var asked int64
	if err := tr2.RecoverHostDeleteStages(func(_, taskID int64) (bool, error) {
		asked = taskID
		return true, nil // PostgreSQL: the task row is gone
	}); err != nil {
		t.Fatal(err)
	}
	if asked != 42 {
		t.Fatalf("recovery asked about task %d, want 42", asked)
	}
	var rows int
	if err := tr2.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE task_id=42`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("%d task-42 rows survived, want only the post-journal capture", rows)
	}
	var survivor string
	if err := tr2.DB().QueryRow(`SELECT id FROM exchanges WHERE task_id=42`).Scan(&survivor); err != nil {
		t.Fatal(err)
	}
	if survivor != "1-0004" {
		t.Fatalf("recovery deleted %s, which the journal never named", survivor)
	}
	if err := tr2.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE task_id=43`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatal("the other run's row at the same host was deleted")
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "_delete_staging")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("recovery left a staging journal behind: %v", entries)
	}
}

// The task still exists: the SQLite transaction rolled back with every row in
// place, so recovery must delete nothing.
func TestTaskDeleteStageKeepsRowsWhenTaskStillExists(t *testing.T) {
	dir := t.TempDir()
	tr, err := OpenWithTransport(dir, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	const host = "kept.example"
	seedRecoveryExchange(t, tr, "1-0001", 42, host)

	stage, err := tr.StageDeleteTask(42)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	stage.done = true
	stage.traffic.wmu.Unlock()

	if err := tr.RecoverHostDeleteStages(func(_, _ int64) (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE task_id=42`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("%d rows, want the staged row kept", rows)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "_delete_staging")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("stale journal was kept: %v", entries)
	}
}

// A version-2 journal names no host, so recovery must never fall back to one:
// another run's rows at the same host have to survive even when the journal is
// the only thing left to read.
func TestExchangeJournalNeverWidensToAHost(t *testing.T) {
	tr, _ := openTraffic(t)
	const host = "shared.example"
	seedRecoveryExchange(t, tr, "1-0001", 42, host)
	seedRecoveryExchange(t, tr, "1-0002", 43, host)

	stage, err := tr.StageDeleteTask(42)
	if err != nil {
		t.Fatal(err)
	}
	stage.tx.Rollback() //nolint:errcheck // simulated exit: rows come back
	stage.done = true
	stage.traffic.wmu.Unlock()

	raw, err := os.ReadFile(filepath.Join(stage.stageDir, hostDeleteStageJournalName))
	if err != nil {
		t.Fatal(err)
	}
	var journal hostDeleteStageJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatal(err)
	}
	if journal.Version != hostDeleteStageVersionExchanges {
		t.Fatalf("journal version = %d, want %d", journal.Version, hostDeleteStageVersionExchanges)
	}
	if len(journal.Hosts) != 0 {
		t.Fatalf("an ID-scoped journal named hosts: %v", journal.Hosts)
	}
	if len(journal.ExchangeIDs) != 1 || journal.ExchangeIDs[0] != "1-0001" {
		t.Fatalf("journal ids = %v, want the task-42 row only", journal.ExchangeIDs)
	}
}

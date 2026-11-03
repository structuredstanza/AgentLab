package traffic

import "testing"

func seedRecoveryExchange(t *testing.T, tr *Traffic, id, host string) {
	t.Helper()
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, 1, host, "GET", "/p", "https://"+host+"/p", 200, "text/plain", 1, 1, ""); err != nil {
		t.Fatal(err)
	}
}

// DeleteTask stages its host deletion, commits PostgreSQL, then commits SQLite.
// A process exit between the two left the rows in the hot store with nothing
// pointing at them: recovery could not tell whether to restore or purge, and
// discarded the journal. With the task id recorded, it asks PostgreSQL.
func TestTaskDeleteStageResolvesFromPostgresAfterCrash(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const host = "gone.example"
	seedRecoveryExchange(t, tr, "1-0001", host)
	seedRecoveryExchange(t, tr, "1-0002", host)

	stage, err := tr.StageDeleteHostsExact([]string{host}, 42)
	if err != nil {
		t.Fatal(err)
	}
	// process exit: SQLite rolls back, the staging tree stays on disk
	if err := stage.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	stage.done = true
	stage.traffic.wmu.Unlock()
	_ = tr.Close()

	tr2, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr2.Close() })

	var asked int64
	if err := tr2.RecoverHostDeleteStages(func(_, taskID int64) (bool, error) {
		asked = taskID
		return true, nil // PostgreSQL: the task row is gone
	}); err != nil {
		t.Fatal(err)
	}
	if asked != 42 {
		t.Fatalf("recovery asked about task %d, want 42 (the journal lost the id)", asked)
	}
	var rows int
	if err := tr2.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("%d rows survived a completed task delete", rows)
	}
}

package traffic

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedOwnedExchange inserts one index row plus, unless it is a legacy row, its
// body row and blob reference. taskID 0 records NULL ownership, which is what an
// unattributed capture and an extension ingest both produce.
func seedOwnedExchange(t *testing.T, tr *Traffic, id string, taskID int64, host, legacyPath string, respBody []byte, respBlob string, respLen int) {
	t.Helper()
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,task_id,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, 1, nullIfZero(taskID), host, "GET", "/"+id, "https://"+host+"/"+id, 200, "text/plain", 0, respLen, legacyPath); err != nil {
		t.Fatal(err)
	}
	if legacyPath != "" {
		return
	}
	if _, err := tr.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, id, "GET /"+id+" HTTP/1.1", nil, nil, "HTTP/1.1 200 OK", respBody, nullIfEmpty(respBlob)); err != nil {
		t.Fatal(err)
	}
	if respBlob != "" {
		if _, err := tr.DB().Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, respBlob, id); err != nil {
			t.Fatal(err)
		}
	}
	if tr.fts {
		var rowID int64
		if err := tr.DB().QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, id).Scan(&rowID); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.DB().Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, ftsToken(id)); err != nil {
			t.Fatal(err)
		}
	}
}

func ftsToken(id string) string { return "token" + strings.ReplaceAll(id, "-", "") }

// writeTrafficBlob puts data in the content-addressed store the way a spilled
// body lands there, and returns its hash and path.
func writeTrafficBlob(t *testing.T, tr *Traffic, data []byte) (hash, path string) {
	t.Helper()
	sum := sha256.Sum256(data)
	hash = hex.EncodeToString(sum[:])
	path = filepath.Join(tr.dir, "_blobs", "sha256", hash[:2], hash+".bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return hash, path
}

// A task delete is scoped by the ownership the recorder wrote, never by host. A
// run, another run and unattributed history share one host and one spilled body;
// deleting the first must leave the others, the shared blob and the legacy host
// tree byte-identical.
func TestStageDeleteTaskRemovesOnlyItsOwnRows(t *testing.T) {
	tr, dir := openTraffic(t)
	const host = "shared.example"
	shared := []byte(strings.Repeat("shared response body\n", 2000))
	hash, blobFile := writeTrafficBlob(t, tr, shared)
	preview := shared[:blobPreview]

	seedOwnedExchange(t, tr, "7-0001", 7, host, "", preview, hash, len(shared))
	seedOwnedExchange(t, tr, "9-0001", 9, host, "", preview, hash, len(shared))
	seedOwnedExchange(t, tr, "0-0001", 0, host, "", preview, hash, len(shared))
	// A legacy row at the same host: its bodies live in the host tree, which a
	// task operation must never move.
	legacyRel := host + "/GET/0-0002"
	legacyDir := filepath.Join(dir, filepath.FromSlash(legacyRel))
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyBody := []byte("legacy response body\n")
	if err := os.WriteFile(filepath.Join(legacyDir, "request.http"), []byte("GET /old HTTP/1.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "response.http"), legacyBody, 0o600); err != nil {
		t.Fatal(err)
	}
	seedOwnedExchange(t, tr, "0-0002", 0, host, legacyRel, nil, "", len(legacyBody))
	// A task-7 capture at a host with no asset row of any kind.
	seedOwnedExchange(t, tr, "7-0002", 7, "solo.example", "", []byte("inline"), "", 6)

	stage, err := tr.StageDeleteTask(7)
	if err != nil {
		t.Fatal(err)
	}
	if stage.Deleted() != 2 {
		t.Fatalf("staged %d rows, want the two task-7 rows", stage.Deleted())
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"7-0001", "7-0002"} {
		for _, query := range []string{
			`SELECT count(*) FROM exchanges WHERE id=?`,
			`SELECT count(*) FROM exchange_bodies WHERE id=?`,
			`SELECT count(*) FROM blob_refs WHERE exchange_id=?`,
		} {
			var n int
			if err := tr.DB().QueryRow(query, id).Scan(&n); err != nil || n != 0 {
				t.Fatalf("%s survived the task delete: %s count=%d err=%v", id, query, n, err)
			}
		}
	}
	for _, id := range []string{"9-0001", "0-0001", "0-0002"} {
		var n int
		if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id=?`, id).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s was deleted by another task's delete: count=%d err=%v", id, n, err)
		}
	}
	if _, err := os.Stat(blobFile); err != nil {
		t.Fatalf("the blob another run still references was collected: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(legacyDir, "response.http")); err != nil || !bytes.Equal(got, legacyBody) {
		t.Fatalf("the legacy host tree changed: %q err=%v", got, err)
	}
	if tr.fts {
		var n int
		if err := tr.DB().QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH ?`, ftsQuote(ftsToken("7-0001"))).Scan(&n); err != nil || n != 0 {
			t.Fatalf("the deleted exchange is still full-text searchable: count=%d err=%v", n, err)
		}
		if err := tr.DB().QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH ?`, ftsQuote(ftsToken("9-0001"))).Scan(&n); err != nil || n != 1 {
			t.Fatalf("the other run's exchange lost its full-text entry: count=%d err=%v", n, err)
		}
	}

	// A row that still points at a pre-SQLite tree cannot be deleted by a task
	// operation, because the tree it belongs to is not the task's to move.
	if _, err := tr.DB().Exec(`UPDATE exchanges SET task_id=7 WHERE id='0-0002'`); err != nil {
		t.Fatal(err)
	}
	stage, err = tr.StageDeleteTask(7)
	if err != nil {
		t.Fatal(err)
	}
	if stage.Deleted() != 0 {
		t.Fatalf("staged %d legacy rows, want none", stage.Deleted())
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id='0-0002'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the legacy row was deleted: count=%d err=%v", n, err)
	}
}

// A rolled-back task delete must leave the index, the bodies, the blob
// references and the blob file exactly as they were.
func TestStageDeleteTaskRollbackRestoresEverything(t *testing.T) {
	tr, _ := openTraffic(t)
	const host = "rollback.example"
	body := []byte(strings.Repeat("rollback body\n", 1000))
	hash, blobFile := writeTrafficBlob(t, tr, body)
	seedOwnedExchange(t, tr, "7-0001", 7, host, "", body[:blobPreview], hash, len(body))

	stage, err := tr.StageDeleteTask(7)
	if err != nil {
		t.Fatal(err)
	}
	if stage.Deleted() != 1 {
		t.Fatalf("staged %d rows, want 1", stage.Deleted())
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}

	for _, query := range []string{
		`SELECT count(*) FROM exchanges WHERE id='7-0001'`,
		`SELECT count(*) FROM exchange_bodies WHERE id='7-0001'`,
		`SELECT count(*) FROM blob_refs WHERE exchange_id='7-0001'`,
	} {
		var n int
		if err := tr.DB().QueryRow(query).Scan(&n); err != nil || n != 1 {
			t.Fatalf("rollback lost data: %s count=%d err=%v", query, n, err)
		}
	}
	if _, err := os.Stat(blobFile); err != nil {
		t.Fatalf("rollback lost the blob: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(tr.dir, "_delete_staging"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rollback left a staging journal behind: %v", entries)
	}
}

// Archive compaction deletes the IDs the package actually contains. A capture
// after the snapshot stays hot, and an equal live row count cannot authorize
// deleting a row that was never exported.
func TestArchiveCompactionDeletesOnlyExportedIDs(t *testing.T) {
	tr, _ := openTraffic(t)
	const host = "archive-task.example"
	seedOwnedExchange(t, tr, "7-0001", 7, host, "", []byte("one"), "", 3)
	seedOwnedExchange(t, tr, "7-0002", 7, host, "", []byte("two"), "", 3)
	seedOwnedExchange(t, tr, "9-0001", 9, host, "", []byte("nine"), "", 4)

	archiveDir := filepath.Join(t.TempDir(), "traffic")
	count, ids, err := tr.ExportTask(7, archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || len(ids) != 2 {
		t.Fatalf("ExportTask=(%d,%v), want the two task-7 rows", count, ids)
	}
	manifest, err := os.ReadFile(filepath.Join(archiveDir, "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), "9-0001") {
		t.Fatalf("the package contains another run's exchange: %s", manifest)
	}
	if !strings.Contains(string(manifest), `"task_id":7`) {
		t.Fatalf("the package lost the task ownership: %s", manifest)
	}
	for _, id := range []string{"7-0001", "7-0002"} {
		if !strings.Contains(string(manifest), `"id":"`+id+`"`) {
			t.Fatalf("the package is missing %s: %s", id, manifest)
		}
	}

	// One exported row vanishes and a new task-7 capture replaces it, so the live
	// count still equals the exported count.
	seedOwnedExchange(t, tr, "7-0003", 7, host, "", []byte("late"), "", 4)
	if _, err := tr.DB().Exec(`DELETE FROM exchange_bodies WHERE id='7-0001'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`DELETE FROM exchanges WHERE id='7-0001'`); err != nil {
		t.Fatal(err)
	}

	stage, err := tr.StageDeleteExchangesForArchive(ids, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if stage.Deleted() != 1 {
		t.Fatalf("staged %d rows, want only the exported row that still exists", stage.Deleted())
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id='7-0002'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the exported row survived compaction: count=%d err=%v", n, err)
	}
	for _, id := range []string{"7-0003", "9-0001"} {
		if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id=?`, id).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s was deleted although the package never carried it: count=%d err=%v", id, n, err)
		}
	}
}

// An export by task and the matching restore round-trip the ownership, so a
// restored run's traffic is still its own.
func TestExportTaskRoundTripsTaskOwnership(t *testing.T) {
	tr, _ := openTraffic(t)
	const host = "roundtrip.example"
	seedOwnedExchange(t, tr, "7-0001", 7, host, "", []byte("round trip"), "", 10)

	archiveDir := filepath.Join(t.TempDir(), "traffic")
	if _, _, err := tr.ExportTask(7, archiveDir); err != nil {
		t.Fatal(err)
	}
	stage, err := tr.StageDeleteTask(7)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}
	if imported, err := tr.ImportArchive(archiveDir); err != nil || imported != 1 {
		t.Fatalf("ImportArchive=(%d,%v), want 1", imported, err)
	}
	var task sql.NullInt64
	if err := tr.DB().QueryRow(`SELECT task_id FROM exchanges WHERE id='7-0001'`).Scan(&task); err != nil {
		t.Fatal(err)
	}
	if !task.Valid || task.Int64 != 7 {
		t.Fatalf("restored task_id = %v, want 7", task)
	}
	if _, resp, err := tr.Get("7-0001"); err != nil || !strings.Contains(resp, "round trip") {
		t.Fatalf("restored body=%q err=%v", resp, err)
	}
}

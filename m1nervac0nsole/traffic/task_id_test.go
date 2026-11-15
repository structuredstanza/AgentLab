package traffic

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// fixedTask answers with one task for every request, which is what a run's
// session does.
type fixedTask int64

func (f fixedTask) TaskID(*mproxy.ConnContext, *http.Request) int64 { return int64(f) }

// TestRecordedExchangeCarriesItsTask is the point of the column: a request
// recorded through the proxy is attributed to the run that made it, taken from
// the session the origin transport already authorized it with.
func TestRecordedExchangeCarriesItsTask(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	// newGatewayHook resolves every request to the session of task 1.
	rec := startRecorder(t, newGatewayHook(t))
	res, err := rec.client.Get(originURL(srv) + "/x")
	if err != nil {
		t.Fatalf("GET through the recorder: %v", err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()

	var task sql.NullInt64
	if err := rec.tr.DB().QueryRow(`SELECT task_id FROM exchanges`).Scan(&task); err != nil {
		t.Fatalf("reading task_id: %v", err)
	}
	if !task.Valid || task.Int64 != 1 {
		t.Fatalf("recorded task_id = %v, want 1", task)
	}
}

// TestExchangeWithoutSessionRecordsNull proves an exchange no run owns still
// records, with a NULL task rather than a guessed one.
func TestExchangeWithoutSessionRecordsNull(t *testing.T) {
	tr, _ := openTraffic(t) // no origin transport, so no session to resolve
	tr.record(newFlow("api.example.com", "GET", "/x", nil, []byte("ok")))

	var task sql.NullInt64
	if err := tr.DB().QueryRow(`SELECT task_id FROM exchanges`).Scan(&task); err != nil {
		t.Fatalf("reading task_id: %v", err)
	}
	if task.Valid {
		t.Fatalf("an exchange with no session recorded task %d", task.Int64)
	}
	if n, err := tr.Count(); err != nil || n != 1 {
		t.Fatalf("exchange count = %d, err=%v, want 1", n, err)
	}
}

// TestPageFiltersByTask proves the task filter narrows the listing to one run's
// exchanges and that no filter still returns everything.
func TestPageFiltersByTask(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.taskOf = fixedTask(7)
	tr.record(newFlow("api.example.com", "GET", "/seven", nil, []byte("a")))
	tr.taskOf = fixedTask(9)
	tr.record(newFlow("api.example.com", "GET", "/nine", nil, []byte("b")))

	rows, total, err := tr.Page(PageQuery{TaskID: 7, RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("task 7 page = %d rows (total %d), err=%v, want 1", len(rows), total, err)
	}
	if rows[0].TaskID != 7 || rows[0].URLTemplate != "/seven" {
		t.Fatalf("task 7 page returned %+v", rows[0])
	}
	if _, total, err := tr.Page(PageQuery{RespMin: -1, RespMax: -1}, 0, 10); err != nil || total != 2 {
		t.Fatalf("unfiltered total = %d, err=%v, want 2", total, err)
	}
	if _, total, err := tr.Page(PageQuery{TaskID: 11, RespMin: -1, RespMax: -1}, 0, 10); err != nil || total != 0 {
		t.Fatalf("task 11 total = %d, err=%v, want 0", total, err)
	}
}

// TestTaskIDMigrationIsIdempotent covers an install whose index predates the
// column: it is added once, the rows already there keep NULL, and opening the
// same database again re-applies nothing.
func TestTaskIDMigrationIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "_index"), 0o755); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open("sqlite", filepath.Join(dir, "_index", "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	// The index exactly as it shipped before task_id existed.
	if _, err := old.Exec(`CREATE TABLE exchanges (
  id TEXT PRIMARY KEY, ts INTEGER, host TEXT, method TEXT, url_template TEXT, url TEXT,
  status INTEGER, content_type TEXT, req_len INTEGER, resp_len INTEGER, path TEXT
)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES('old',1,'old.example.com','GET','/','http://old.example.com/',200,'text/plain',0,2,'')`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 2; i++ {
		tr, err := OpenWithTransport(dir, "127.0.0.1:0", nil)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var columns int
		if err := tr.DB().QueryRow(`SELECT count(*) FROM pragma_table_info('exchanges') WHERE name='task_id'`).Scan(&columns); err != nil {
			t.Fatalf("open %d: reading the column list: %v", i, err)
		}
		if columns != 1 {
			t.Fatalf("open %d: task_id columns = %d, want 1", i, columns)
		}
		var task sql.NullInt64
		if err := tr.DB().QueryRow(`SELECT task_id FROM exchanges WHERE id='old'`).Scan(&task); err != nil {
			t.Fatalf("open %d: reading the old row: %v", i, err)
		}
		if task.Valid {
			t.Fatalf("open %d: a row recorded before the column has task %d", i, task.Int64)
		}
		tr.Close()
	}
}

// TestArchiveKeepsTheTaskID proves an exported exchange keeps its task, and an
// archive written before the field existed imports with no task instead of
// failing.
func TestArchiveKeepsTheTaskID(t *testing.T) {
	tr, _ := openTraffic(t)
	const (
		id   = "archive-task-1"
		host = "archive-task.example"
	)
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,task_id,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?,'')`, id, 1, 7, host, "GET", "/", "https://"+host+"/", 200, "text/plain", 0, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body) VALUES(?,?,?,?,?)`,
		id, "GET / HTTP/1.1", nil, "HTTP 200", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	archiveDir := filepath.Join(t.TempDir(), "traffic")
	if _, err := tr.ExportHosts([]string{host}, archiveDir); err != nil {
		t.Fatalf("ExportHosts: %v", err)
	}

	manifest := filepath.Join(archiveDir, "traffic.json")
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"task_id":7`) {
		t.Fatalf("the exported exchange lost its task: %s", body)
	}

	// Rewrite it as an archive written before task_id existed.
	stripped := strings.Replace(string(body), `"task_id":7,`, "", 1)
	if stripped == string(body) {
		t.Fatalf("could not strip task_id from %s", body)
	}
	if err := os.WriteFile(manifest, []byte(stripped), 0o600); err != nil {
		t.Fatal(err)
	}

	stage, err := tr.StageDeleteHostsExact([]string{host})
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}
	if imported, err := tr.ImportArchive(archiveDir); err != nil || imported != 1 {
		t.Fatalf("importing an archive without task_id: imported=%d err=%v", imported, err)
	}
	var task sql.NullInt64
	if err := tr.DB().QueryRow(`SELECT task_id FROM exchanges WHERE id=?`, id).Scan(&task); err != nil {
		t.Fatalf("reading the imported task_id: %v", err)
	}
	if task.Valid {
		t.Fatalf("an archive without task_id imported task %d", task.Int64)
	}
}

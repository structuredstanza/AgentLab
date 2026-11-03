package traffic

import (
	"errors"
	"testing"
)

// When a host gained exchanges after the snapshot, the compaction must refuse
// AND leave the evidence in place; the archive worker turns the sentinel error
// into an operator-visible warning, so its identity matters.
func TestGrowthGuardLeavesEvidenceAndReportsAWarning(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })

	const host = "warn.example"
	seed := func(id, path string) {
		if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, 1, host, "GET", path, "https://"+host+path, 200, "text/plain", 1, 1, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body) VALUES(?,?,?,?,?)`,
			id, "GET "+path, []byte("r"), "HTTP/1.1 200 OK", []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	seed("1-0001", "/archived")
	_, counts, err := tr.ExportHostsCounted([]string{host}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed("1-0002", "/during-compression")

	_, err = tr.StageDeleteHostsExactForArchive([]string{host}, 9, 9, counts)
	if !errors.Is(err, ErrTrafficGrewDuringArchive) {
		t.Fatalf("err = %v, want ErrTrafficGrewDuringArchive", err)
	}
	// the worker matches on errors.Is, so the sentinel must survive wrapping
	if err.Error() == ErrTrafficGrewDuringArchive.Error() {
		t.Fatal("the error carries no host/count detail for the operator")
	}
	var rows int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("%d rows left, want both preserved", rows)
	}
}

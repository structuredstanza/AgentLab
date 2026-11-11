package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/traffic"
)

func TestLegacyArchiveRecordAndBindKeepExactBodies(t *testing.T) {
	s, in, dir := evidenceFixture(t)
	request := []byte{0, 0xff, '\n', '\n', 'x'}
	response := bytes.Repeat([]byte{0xfe, '\r', '\n', 0}, 1024)
	reqSum, respSum := sha256.Sum256(request), sha256.Sum256(response)
	reqHash, respHash := hex.EncodeToString(reqSum[:]), hex.EncodeToString(respSum[:])
	blob := filepath.Join(dir, "traffic", "_blobs", "sha256", respHash[:2], respHash+".bin")
	if err := os.MkdirAll(filepath.Dir(blob), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, response, 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"legacy-record", "legacy-bind"} {
		path := filepath.Join(dir, "traffic", id)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "request.http"), append([]byte("POST /legacy HTTP/1.1\r\nHost: old.local\r\n\r\n"), request...), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "response.http"), []byte(fmt.Sprintf("HTTP/1.1 200 OK\nContent-Type: application/octet-stream\n\n@blob sha256:%s (len=%d)", respHash, len(response))), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,1,'old.local','POST','/legacy','http://old.local/legacy',200,'application/octet-stream',?,?,?)`, id, len(request), len(response), id); err != nil {
			t.Fatal(err)
		}
	}
	archive := t.TempDir()
	if count, err := s.Traffic.ExportHosts([]string{"old.local"}, archive); err != nil || count != 2 {
		t.Fatalf("export: %d %v", count, err)
	}
	fresh, err := traffic.Open(t.TempDir(), ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	if count, err := fresh.ImportArchive(archive); err != nil || count != 2 {
		t.Fatalf("import: %d %v", count, err)
	}
	local := *s
	local.Traffic = fresh
	ctx := context.Background()
	result, err := local.Record(ctx, in, []db.TrafficRef{{TrafficID: "legacy-record", Role: "proof"}})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := local.Bind(ctx, result.FindingID, []db.TrafficRef{{TrafficID: "legacy-bind", Role: "verification"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.Bindings) != 2 {
		t.Fatalf("Record and Bind did not retain both references: %+v", bound)
	}
	for _, binding := range bound.Bindings {
		if err := local.WithBinding(ctx, result.FindingID, binding.ID, func(b db.FindingTrafficBinding) error {
			v := b.Snapshot
			if v.ReqHash != reqHash || v.RespHash != respHash || v.ReqLen != int64(len(request)) || v.RespLen != int64(len(response)) {
				t.Fatalf("evidence hashes or lengths changed: %+v", v)
			}
			if v.ReqHead != "POST /legacy HTTP/1.1\nHost: old.local\n" || v.RespHead != "HTTP/1.1 200 OK\nContent-Type: application/octet-stream\n" {
				t.Fatalf("evidence headers contain body data: %+v", v)
			}
			for _, side := range []string{"request", "response"} {
				file, _, err := local.OpenBody(v, side)
				if err != nil {
					return err
				}
				body, readErr := io.ReadAll(file)
				closeErr := file.Close()
				if readErr != nil {
					return readErr
				}
				if closeErr != nil {
					return closeErr
				}
				expected := request
				if side == "response" {
					expected = response
				}
				if !bytes.Equal(body, expected) {
					t.Fatalf("restored %s evidence bytes changed", side)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

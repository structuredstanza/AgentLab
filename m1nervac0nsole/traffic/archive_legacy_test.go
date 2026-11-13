package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyArchivePreservesExactBodies(t *testing.T) {
	for _, kind := range []string{"lf", "crlf", "empty", "pointer", "preview", "literal-marker"} {
		t.Run(kind, func(t *testing.T) {
			tr, dir := openTraffic(t)
			body := []byte{0, 0xff, '\n', '\n', 'x', '\r', '\n', 0xfe}
			stored := body
			newline := "\n"
			hash := ""
			if kind == "crlf" {
				newline = "\r\n"
			}
			if kind == "empty" {
				body, stored = nil, nil
			}
			if kind == "pointer" || kind == "preview" {
				body = bytes.Repeat([]byte{0, 0xff, '\n', 'x'}, 1024)
				sum := sha256.Sum256(body)
				hash = hex.EncodeToString(sum[:])
				path := filepath.Join(dir, "_blobs", "sha256", hash[:2], hash+".bin")
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				stored = []byte(fmt.Sprintf("@blob sha256:%s (len=%d)", hash, len(body)))
				if kind == "preview" {
					stored = append(append([]byte(nil), body[:12]...), append([]byte("\n…[truncated] "), stored...)...)
				}
			}
			if kind == "literal-marker" {
				body = []byte("@blob sha256:" + strings.Repeat("a", 64) + " (len=77)")
				stored = body
			}
			const host = "legacy-archive.example"
			rel := filepath.Join(host, "POST", "legacy-one")
			if err := os.MkdirAll(filepath.Join(dir, rel), 0755); err != nil {
				t.Fatal(err)
			}
			reqHead := "POST /capture HTTP/1.1" + newline + "Host: " + host + newline
			respHead := "HTTP/1.1 200 OK" + newline + "Content-Type: application/octet-stream" + newline
			if err := os.WriteFile(filepath.Join(dir, rel, "request.http"), append([]byte(reqHead+newline), stored...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, rel, "response.http"), append([]byte(respHead+newline), body...), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "legacy-one", 1, host, "POST", "/capture", "https://"+host+"/capture", 200, "application/octet-stream", len(body), len(body), rel); err != nil {
				t.Fatal(err)
			}
			archive := t.TempDir()
			if count, err := tr.ExportHosts([]string{host}, archive); err != nil || count != 1 {
				t.Fatalf("export: %d %v", count, err)
			}
			fresh, _ := openTraffic(t)
			if count, err := fresh.ImportArchive(archive); err != nil || count != 1 {
				t.Fatalf("import: %d %v", count, err)
			}
			err := fresh.ReadEvidence(context.Background(), []string{"legacy-one"}, func(e EvidenceExchange) error {
				req, err := io.ReadAll(e.Request)
				if err != nil {
					return err
				}
				resp, err := io.ReadAll(e.Response)
				if err != nil {
					return err
				}
				if !bytes.Equal(req, body) || !bytes.Equal(resp, body) {
					t.Fatalf("body bytes changed: request=%d response=%d expected=%d", len(req), len(resp), len(body))
				}
				if e.ReqHead != strings.ReplaceAll(reqHead, "\r\n", "\n") || e.RespHead != strings.ReplaceAll(respHead, "\r\n", "\n") {
					t.Fatalf("invalid header split: %q %q", e.ReqHead, e.RespHead)
				}
				if e.ReqHash != hash {
					t.Fatalf("legacy blob reference lost: %q want %q", e.ReqHash, hash)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOldArchiveWholeHeaderRecoveryAndMissingBodyRejection(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			tr, _ := openTraffic(t)
			archive := t.TempDir()
			head := "POST / HTTP/1.1\nHost: old.example\n\nabc\n\ndef"
			length := 8
			if broken {
				length++
			}
			snapshot := ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{{ID: "old-v1", Host: "old.example", ReqHead: head, ReqLen: length, RespHead: "HTTP/1.1 204 No Content\n", RespLen: 0}}}
			raw, _ := json.Marshal(snapshot)
			if err := os.WriteFile(filepath.Join(archive, "traffic.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			count, err := tr.ImportArchive(archive)
			if broken {
				if err == nil || count != 0 {
					t.Fatalf("incomplete archive accepted: %d %v", count, err)
				}
				var rows int
				if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id='old-v1'`).Scan(&rows); err != nil || rows != 0 {
					t.Fatalf("failed import committed a row: %d %v", rows, err)
				}
				return
			}
			if err != nil || count != 1 {
				t.Fatalf("old archive recovery: %d %v", count, err)
			}
			if err := tr.ReadEvidence(context.Background(), []string{"old-v1"}, func(e EvidenceExchange) error {
				body, err := io.ReadAll(e.Request)
				if string(body) != "abc\n\ndef" {
					t.Fatalf("old archive body=%q", body)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

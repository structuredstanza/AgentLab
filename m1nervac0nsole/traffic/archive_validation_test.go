package traffic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyArchiveRejectsIncompleteCapture(t *testing.T) {
	for _, kind := range []string{"missing-request", "missing-response", "short-inline", "missing-blob", "short-blob", "corrupt-blob", "marker-length", "marker-overflow", "invalid-path", "oversize-header"} {
		t.Run(kind, func(t *testing.T) {
			tr, dir := openTraffic(t)
			rel := "legacy"
			path := filepath.Join(dir, rel)
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte("data"), 64)
			sum := sha256.Sum256(body)
			hash := hex.EncodeToString(sum[:])
			stored := body
			if strings.Contains(kind, "blob") || strings.HasPrefix(kind, "marker") {
				length := fmt.Sprint(len(body))
				if kind == "marker-length" {
					length = "999"
				}
				if kind == "marker-overflow" {
					length = "18446744073709551616"
				}
				stored = []byte("@blob sha256:" + hash + " (len=" + length + ")")
				if kind != "missing-blob" {
					blob := filepath.Join(dir, "_blobs", "sha256", hash[:2], hash+".bin")
					if err := os.MkdirAll(filepath.Dir(blob), 0700); err != nil {
						t.Fatal(err)
					}
					content := append([]byte(nil), body...)
					if kind == "short-blob" {
						content = content[:len(content)-1]
					}
					if kind == "corrupt-blob" {
						content[0] ^= 0xff
					}
					if err := os.WriteFile(blob, content, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind == "short-inline" {
				stored = stored[:len(stored)-1]
			}
			header := []byte("POST / HTTP/1.1\nHost: invalid.example\n\n")
			if kind == "oversize-header" {
				header = bytes.Repeat([]byte("x"), (1<<20)+1)
			}
			if kind != "missing-request" {
				if err := os.WriteFile(filepath.Join(path, "request.http"), append(header, stored...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "missing-response" {
				if err := os.WriteFile(filepath.Join(path, "response.http"), []byte("HTTP/1.1 204 No Content\n\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "invalid-path" {
				rel = "../outside"
			}
			if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('invalid',1,'invalid.example','POST','/','https://invalid.example/',204,'text/plain',?,0,?)`, len(body), rel); err != nil {
				t.Fatal(err)
			}
			if _, err := tr.ExportHosts([]string{"invalid.example"}, t.TempDir()); err == nil {
				t.Fatal("incomplete or corrupt legacy capture was archived")
			}
		})
	}
}

func TestArchiveReferenceValidationAndCurrentWins(t *testing.T) {
	for _, kind := range []string{"unlisted", "missing", "checksum", "length", "existing-corrupt", "ambiguous", "current-wins"} {
		t.Run(kind, func(t *testing.T) {
			tr, dir := openTraffic(t)
			body := []byte("complete blob")
			sum := sha256.Sum256(body)
			hash := hex.EncodeToString(sum[:])
			item := ArchiveExchange{ID: "archive-blob", Host: "archive.example", ReqHead: "POST / HTTP/1.1\n", ReqLen: len(body), ReqBlob: hash, RespHead: "HTTP/1.1 204 No Content\n"}
			archive := t.TempDir()
			if err := os.MkdirAll(filepath.Join(archive, "blobs"), 0700); err != nil {
				t.Fatal(err)
			}
			content := append([]byte(nil), body...)
			if kind == "checksum" {
				content[0] ^= 0xff
			}
			if kind != "missing" {
				if err := os.WriteFile(filepath.Join(archive, "blobs", hash+".bin"), content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "length" {
				item.ReqLen++
			}
			if kind == "ambiguous" {
				item.ReqHead += "\nother body"
				item.ReqBody = []byte("body")
			}
			if kind == "existing-corrupt" {
				path := filepath.Join(dir, "_blobs", "sha256", hash[:2], hash+".bin")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "current-wins" {
				if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('archive-blob',1,'archive.example','POST','/','https://archive.example/',204,'text/plain',0,0,'')`); err != nil {
					t.Fatal(err)
				}
				item.ReqBlob = "invalid stale content"
			}
			snapshot := ArchiveSnapshot{Version: 1, Exchanges: []ArchiveExchange{item}, Blobs: []string{hash}}
			if kind == "unlisted" {
				snapshot.Blobs = nil
			}
			raw, _ := json.Marshal(snapshot)
			if err := os.WriteFile(filepath.Join(archive, "traffic.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			count, err := tr.ImportArchive(archive)
			if kind == "current-wins" {
				if err != nil || count != 0 {
					t.Fatalf("stale archive overrode current row: %d %v", count, err)
				}
				return
			}
			if err == nil || count != 0 {
				t.Fatalf("invalid archived evidence accepted: %d %v", count, err)
			}
			var rows int
			if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE id='archive-blob'`).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("failed import committed rows: %d %v", rows, err)
			}
		})
	}
}

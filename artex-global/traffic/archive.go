package traffic

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ArchiveSnapshot is the portable traffic subset embedded in one task archive.
// Large content-addressed bodies are copied alongside this manifest rather than
// base64-encoded, preserving deduplication and allowing the tar writer to stream.
type ArchiveSnapshot struct {
	Version   int               `json:"version"`
	Exchanges []ArchiveExchange `json:"exchanges"`
	Blobs     []string          `json:"blobs"`
}

type ArchiveExchange struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqLen      int    `json:"req_len"`
	RespLen     int    `json:"resp_len"`
	ReqHead     string `json:"req_head"`
	ReqBody     []byte `json:"req_body,omitempty"`
	ReqBlob     string `json:"req_blob,omitempty"`
	RespHead    string `json:"resp_head"`
	RespBody    []byte `json:"resp_body,omitempty"`
	RespBlob    string `json:"resp_blob,omitempty"`
}

// ExportHosts writes an exact-host snapshot to dir. It holds the traffic writer
// lock while reading SQLite and blobs, so each body and its index row come from
// one consistent point in time.
func (t *Traffic) ExportHosts(hosts []string, dir string) (int64, error) {
	n, _, err := t.ExportHostsCounted(hosts, dir)
	return n, err
}

// ExportHostsCounted is ExportHosts plus the per-host row counts actually written
// to the package. StageDeleteHostsExactForArchive compares against them so rows
// captured after the snapshot are never deleted.
func (t *Traffic) ExportHostsCounted(hosts []string, dir string) (int64, map[string]int64, error) {
	if t == nil || len(hosts) == 0 {
		return 0, nil, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return 0, nil, err
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	unique := uniqueArchiveHosts(hosts)
	placeholders := make([]string, len(unique))
	args := make([]any, len(unique))
	for i, host := range unique {
		placeholders[i] = "?"
		args[i] = host
	}
	rows, err := t.db.Query(`SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path
FROM exchanges WHERE host IN (`+strings.Join(placeholders, ",")+`) ORDER BY ts,id`, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	out, err := os.Create(filepath.Join(dir, "traffic.json"))
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = out.Close() }() // idempotent; the success path closes explicitly
	// Field order is not significant to the reader, so older archives stay
	// readable and this one is byte-compatible in meaning.
	if _, err := out.Write([]byte(`{"version":1,"exchanges":[`)); err != nil {
		return 0, nil, err
	}
	var written int
	var writtenHosts []string
	blobs := map[string]int64{}
	var blobList []string
	for rows.Next() {
		var item ArchiveExchange
		var legacyPath string
		if err := rows.Scan(&item.ID, &item.TS, &item.Host, &item.Method, &item.URLTemplate,
			&item.URL, &item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &legacyPath); err != nil {
			return 0, nil, err
		}
		var reqBlob, respBlob sql.NullString
		err := t.db.QueryRow(`SELECT req_head,req_body,req_blob,resp_head,resp_body,resp_blob
FROM exchange_bodies WHERE id=?`, item.ID).Scan(&item.ReqHead, &item.ReqBody, &reqBlob, &item.RespHead, &item.RespBody, &respBlob)
		if errors.Is(err, sql.ErrNoRows) && legacyPath != "" {
			if err := func() error {
				request, err := t.openLegacySide(legacyPath, "request.http", int64(item.ReqLen))
				if err != nil {
					return err
				}
				defer request.close()
				response, err := t.openLegacySide(legacyPath, "response.http", int64(item.RespLen))
				if err != nil {
					return err
				}
				defer response.close()
				item.ReqHead, item.ReqBlob = request.head, request.hash
				item.RespHead, item.RespBlob = response.head, response.hash
				item.ReqBody, err = io.ReadAll(request.preview)
				if err != nil {
					return err
				}
				item.RespBody, err = io.ReadAll(response.preview)
				return err
			}(); err != nil {
				return 0, nil, err
			}
		} else if err != nil {
			return 0, nil, err
		} else {
			item.ReqBlob, item.RespBlob = reqBlob.String, respBlob.String
		}
		if err := normalizeArchiveExchange(&item); err != nil {
			return 0, nil, err
		}
		if err := collectArchiveBlobs(blobs, item); err != nil {
			return 0, nil, err
		}
		// Stream each exchange straight to the file so only one is ever in
		// memory. Buffering them and calling json.Marshal afterwards held a
		// second, base64-inflated copy of every body at the same time.
		if written > 0 {
			if _, err := out.Write([]byte(",")); err != nil {
				return 0, nil, err
			}
		}
		line, err := json.Marshal(item)
		if err != nil {
			return 0, nil, err
		}
		if _, err := out.Write(line); err != nil {
			return 0, nil, err
		}
		written++
		writtenHosts = append(writtenHosts, item.Host)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	for hash, expected := range blobs {
		source, err := t.blobPath(hash)
		if err != nil {
			return 0, nil, err
		}
		data, err := os.ReadFile(source)
		if err != nil {
			return 0, nil, err
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != expected || hex.EncodeToString(sum[:]) != hash {
			return 0, nil, fmt.Errorf("traffic blob length or checksum mismatch: %s", hash)
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", hash+".bin"), data, 0o600); err != nil {
			return 0, nil, err
		}
		blobList = append(blobList, hash)
	}
	sort.Strings(blobList)
	tail, err := json.Marshal(blobList)
	if err != nil {
		return 0, nil, err
	}
	for _, chunk := range [][]byte{[]byte(`],"blobs":`), tail, []byte("}")} {
		if _, err := out.Write(chunk); err != nil {
			return 0, nil, err
		}
	}
	if err := out.Sync(); err != nil {
		return 0, nil, err
	}
	if err := out.Close(); err != nil {
		return 0, nil, err
	}
	counts := make(map[string]int64, len(writtenHosts))
	for _, host := range writtenHosts {
		counts[host]++
	}
	return int64(written), counts, nil
}

// ImportArchive imports only missing exchange IDs. Current hot rows always win,
// and repeated restore attempts are safe after a partial external failure.
func (t *Traffic) ImportArchive(dir string) (int64, error) {
	if t == nil {
		return 0, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "traffic.json"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != 1 {
		return 0, fmt.Errorf("unsupported traffic archive version %d", snapshot.Version)
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	listed := make(map[string]bool, len(snapshot.Blobs))
	for _, hash := range snapshot.Blobs {
		listed[hash] = true
	}
	blobs := make(map[string]int64)
	seen := make(map[string]bool)
	var pending []ArchiveExchange
	for _, item := range snapshot.Exchanges {
		if seen[item.ID] {
			continue
		}
		seen[item.ID] = true
		var existing int
		err := t.db.QueryRow(`SELECT 1 FROM exchanges WHERE id=?`, item.ID).Scan(&existing)
		if err == nil {
			continue
		} // Current rows win even over stale corrupt content.
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		if err := normalizeArchiveExchange(&item); err != nil {
			return 0, err
		}
		if err := collectArchiveBlobs(blobs, item); err != nil {
			return 0, err
		}
		pending = append(pending, item)
	}
	for hash, expected := range blobs {
		if !listed[hash] {
			return 0, fmt.Errorf("archived traffic blob is not listed: %s", hash)
		}
		data, err := os.ReadFile(filepath.Join(dir, "blobs", hash+".bin"))
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != expected || hex.EncodeToString(sum[:]) != hash {
			return 0, fmt.Errorf("traffic blob length or checksum mismatch: %s", hash)
		}
		destination := filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin")
		if _, err := os.Stat(destination); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
				return 0, err
			}
			if err := writeNewArchiveBlob(destination, data); err != nil {
				return 0, err
			}
		} else if err != nil {
			return 0, err
		} else if err := verifyArchiveBlob(destination, hash, expected); err != nil {
			return 0, err
		}
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var imported int64
	for _, item := range pending {
		res, err := tx.Exec(`INSERT OR IGNORE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, item.ID, item.TS, item.Host, item.Method, item.URLTemplate,
			item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen)
		if err != nil {
			return imported, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, item.ReqHead, item.ReqBody, nullIfEmpty(item.ReqBlob),
			item.RespHead, item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
			return imported, err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, hash, item.ID); err != nil {
					return imported, err
				}
			}
		}
		if t.fts {
			var rowID int64
			if err := tx.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, item.ID).Scan(&rowID); err != nil {
				return imported, err
			}
			content := strings.Join([]string{item.URL, item.ReqHead, string(item.ReqBody), item.RespHead, string(item.RespBody)}, "\n")
			if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, content); err != nil {
				return imported, err
			}
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return imported, err
	}
	return imported, nil
}

func uniqueArchiveHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func normalizeArchiveExchange(item *ArchiveExchange) error {
	var err error
	item.ReqHead, item.ReqBody, item.ReqBlob, err = normalizeArchiveSide(item.ReqHead, item.ReqBody, item.ReqBlob, item.ReqLen)
	if err != nil {
		return fmt.Errorf("traffic %s request: %w", item.ID, err)
	}
	item.RespHead, item.RespBody, item.RespBlob, err = normalizeArchiveSide(item.RespHead, item.RespBody, item.RespBlob, item.RespLen)
	if err != nil {
		return fmt.Errorf("traffic %s response: %w", item.ID, err)
	}
	return nil
}

func collectArchiveBlobs(blobs map[string]int64, item ArchiveExchange) error {
	for _, side := range [2]struct {
		hash   string
		length int
	}{{item.ReqBlob, item.ReqLen}, {item.RespBlob, item.RespLen}} {
		if side.hash == "" {
			continue
		}
		if previous, found := blobs[side.hash]; found && previous != int64(side.length) {
			return fmt.Errorf("conflicting traffic blob lengths: %s", side.hash)
		}
		blobs[side.hash] = int64(side.length)
	}
	return nil
}

func verifyArchiveBlob(path, hash string, expected int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	length, err := io.Copy(digest, file)
	if err != nil {
		return err
	}
	if length != expected || hex.EncodeToString(digest.Sum(nil)) != hash {
		return fmt.Errorf("traffic blob length or checksum mismatch: %s", hash)
	}
	return nil
}

func writeNewArchiveBlob(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path) // Only this call's exclusively-created partial file.
		return err
	}
	return nil
}

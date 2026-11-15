package traffic

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// ExternalExchange is one captured request/response pair handed in from
// outside the MITM proxy (currently the browser-extension ingest endpoint).
// Header maps are lowercased-name oriented on the extension side but any
// casing is accepted; bodies are raw text (binary capture is skipped by the
// extension, not handled here).
type ExternalExchange struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	// Failed marks a capture where no response arrived at all (blocked, aborted,
	// DNS failure). Without it status 0 is indistinguishable from an omitted
	// field, and the old default rewrote a blocked request to "HTTP 200".
	Failed          bool              `json:"failed"`
	RequestHeaders  map[string]string `json:"requestHeaders"`
	RequestBody     string            `json:"requestBody"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	ResponseBody    string            `json:"responseBody"`
	// Partial marks a capture whose ResponseBody is only the first part of the
	// response: a probe over the capture cap, or one whose body was not read to
	// the end. The exchange is stored anyway, with RespLen as the full length and
	// partialMarker in the stored response head, so the row says a body existed
	// and was not captured in full instead of the exchange vanishing.
	Partial bool `json:"partial,omitempty"`
	// RespLen is the response's full length when it is known and larger than
	// ResponseBody. Zero stores len(ResponseBody).
	RespLen int `json:"respLen,omitempty"`
}

// partialMarker is the line a partially captured exchange's stored response head
// carries where the rest of the body would be: the row keeps the first part of
// the body and the response's full length, so it must say the body is a prefix.
// It follows streamedMarker's shape (traffic.go), which marks a body that was not
// captured at all, and stays searchable through the full-text index.
const partialMarker = "X-M1nervac0nsole-Capture: body not captured in full: partial"

// RecordExternal stores an externally captured exchange through the same
// spill/blob/index path as proxy traffic, so ingested entries are
// indistinguishable from proxy-captured ones on the Traffic page and in
// full-text search.
func (t *Traffic) RecordExternal(e ExternalExchange) error {
	u, err := url.Parse(e.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid url %q", e.URL)
	}
	method := strings.ToUpper(strings.TrimSpace(e.Method))
	if method == "" {
		return fmt.Errorf("empty method for %q", e.URL)
	}
	status := e.Status
	if status == 0 && !e.Failed {
		status = 200 // an omitted status keeps the historical "assume success"
	}

	host := u.Hostname()
	reqHead := fmt.Sprintf("%s %s %s\n%s", method, u.RequestURI(), "HTTP/1.1", headerLines(toHeaderMap(e.RequestHeaders)))
	respHead := fmt.Sprintf("HTTP %d\n%s", status, headerLines(toHeaderMap(e.ResponseHeaders)))
	if e.Failed {
		// No response arrived: record why, instead of printing a bogus "HTTP 0".
		respHead = fmt.Sprintf("(no response) %s\n%s", e.ResponseHeaders["x-capture-error"], headerLines(toHeaderMap(e.ResponseHeaders)))
	}
	respCT := e.ResponseHeaders["content-type"]
	// A partial capture keeps its declared full length in resp_len, so the row
	// never reports the prefix as the response's size; the marker says the body
	// is not the whole thing.
	respLen := len(e.ResponseBody)
	if e.RespLen > respLen {
		respLen = e.RespLen
	}
	if e.Partial {
		respHead += partialMarker + "\n"
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	// Bodies are spilled before the transaction opens, matching record().
	reqB := t.spill([]byte(e.RequestBody), e.RequestHeaders["content-type"])
	respB := t.spill([]byte(e.ResponseBody), respCT)
	// A body cut at the capture reserve is labelled like any other partial, so
	// the row stays exportable instead of reading as a truncated body.
	respHead += cutMarker(reqB, respB)

	n := t.seq.Add(1)
	now := time.Now()
	id := fmt.Sprintf("%d-%08d", now.Unix(), n) // no modulo: keeps every id unique

	// An ingested exchange carries no session: the extension posts over the API,
	// not through the proxy, so no run owns it and task_id stays NULL.
	if err := t.insertExchange(id, now.Unix(), 0, host, method, db.TemplatePath(u.EscapedPath()), u.String(), status, respCT, len(e.RequestBody), respLen, reqHead, reqB, respHead, respB); err != nil {
		log.Printf("[traffic] failed to ingest %s: %v", u.String(), err)
		return err
	}
	return nil
}

// insertExchange writes the index row, the body row, blob references and the
// FTS entry inside one transaction. record() and RecordExternal share it so
// both capture paths stay byte-identical in storage layout.
func (t *Traffic) insertExchange(id string, ts int64, taskID int64, host, method, urlTemplate, rawURL string, status int, contentType string, reqLen, respLen int, reqHead string, reqB storedBody, respHead string, respB storedBody) error {
	tx, err := t.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	res, err := tx.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,task_id,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?,'')`,
		id, ts, nullIfZero(taskID), host, method, urlTemplate, rawURL, status, contentType, reqLen, respLen)
	if err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("fetching rowid: %w", err)
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`,
		id, reqHead, reqB.inline, nullIfEmpty(reqB.hash), respHead, respB.inline, nullIfEmpty(respB.hash)); err != nil {
		return fmt.Errorf("writing body: %w", err)
	}

	for _, h := range []string{reqB.hash, respB.hash} {
		if h == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, id); err != nil {
			return fmt.Errorf("registering blob reference: %w", err)
		}
	}

	if t.fts {
		idx := strings.Join([]string{rawURL, reqHead, reqB.index, respHead, respB.index}, "\n")
		if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			return fmt.Errorf("writing full-text index: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

func toHeaderMap(flat map[string]string) map[string][]string {
	m := make(map[string][]string, len(flat))
	for k, v := range flat {
		m[k] = []string{v}
	}
	return m
}

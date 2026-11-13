package traffic

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
)

// EvidenceExchange exposes complete captured bodies only during the callback.
// Readers are closed before releasing the writer lock, so host deletion cannot
// remove a blob between its index lookup and its evidence copy.
type EvidenceExchange struct {
	ID, URL, Method, ContentType string
	TS                           int64
	Status                       int
	ReqHead, RespHead            string
	ReqLen, RespLen              int64
	ReqHash, RespHash            string
	Request, Response            io.Reader
}

func (t *Traffic) ReadEvidence(ctx context.Context, ids []string, consume func(EvidenceExchange) error) error {
	if t == nil {
		return errors.New("traffic recording storage is unavailable")
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := t.readEvidence(id, consume); err != nil {
			return fmt.Errorf("traffic %s: %w", id, err)
		}
	}
	return nil
}

func (t *Traffic) readEvidence(id string, consume func(EvidenceExchange) error) error {
	e := EvidenceExchange{ID: id}
	var legacy string
	if err := t.db.QueryRow(`SELECT ts,url,method,status,content_type,req_len,resp_len,path FROM exchanges WHERE id=?`, id).
		Scan(&e.TS, &e.URL, &e.Method, &e.Status, &e.ContentType, &e.ReqLen, &e.RespLen, &legacy); err != nil {
		return err
	}
	var req, resp []byte
	var reqBlob, respBlob sql.NullString
	err := t.db.QueryRow(`SELECT req_head,req_body,req_blob,resp_head,resp_body,resp_blob FROM exchange_bodies WHERE id=?`, id).
		Scan(&e.ReqHead, &req, &reqBlob, &e.RespHead, &resp, &respBlob)
	if errors.Is(err, sql.ErrNoRows) && legacy != "" {
		request, err := t.openLegacySide(legacy, "request.http", e.ReqLen)
		if err != nil {
			return err
		}
		defer request.close()
		response, err := t.openLegacySide(legacy, "response.http", e.RespLen)
		if err != nil {
			return err
		}
		defer response.close()
		e.ReqHead, e.Request, e.ReqHash = request.head, request.body, request.hash
		e.RespHead, e.Response, e.RespHash = response.head, response.body, response.hash
		return consume(e)
	}
	if err != nil {
		return err
	}
	e.Request = bytes.NewReader(req)
	e.Response = bytes.NewReader(resp)
	if reqBlob.Valid && reqBlob.String != "" {
		f, _, err := t.Blob(reqBlob.String)
		if err != nil {
			return err
		}
		defer f.Close()
		e.Request = f
		e.ReqHash = reqBlob.String
	}
	if respBlob.Valid && respBlob.String != "" {
		f, _, err := t.Blob(respBlob.String)
		if err != nil {
			return err
		}
		defer f.Close()
		e.Response = f
		e.RespHash = respBlob.String
	}
	return consume(e)
}

func splitLegacyEvidence(r io.Reader) (string, *bufio.Reader, bool, error) {
	b := bufio.NewReader(r)
	var head bytes.Buffer
	lineStart := 0
	for {
		fragment, err := b.ReadSlice('\n')
		if len(fragment) > (1<<20)-head.Len() {
			return "", nil, false, errors.New("legacy traffic header is too large")
		}
		head.Write(fragment)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		line := head.Bytes()[lineStart:]
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			head.Truncate(lineStart)
			return head.String(), b, true, nil
		}
		if bytes.HasSuffix(line, []byte("\r\n")) {
			head.Truncate(head.Len() - 2)
			head.WriteByte('\n')
		}
		lineStart = head.Len()
		if errors.Is(err, io.EOF) {
			return head.String(), b, false, nil
		}
		if err != nil {
			return "", nil, false, err
		}
	}
}

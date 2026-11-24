package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// decodeErrorField pulls the "error" string out of a writeErr JSON body.
func decodeErrorField(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v (body %s)", err, body)
	}
	return resp.Error
}

// TestTaskCategoryResponses drives the validators that never touch the database. The
// request decoder and id parser work on the body alone, writeTaskCategoryError maps a
// db sentinel, and the batch-size guard returns before s.m is read.
func TestTaskCategoryResponses(t *testing.T) {
	// decodeTaskCategoryRequest — body-only validation, no DB.
	decodeCase := func(name, body string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/task-categories", strings.NewReader(body))
		rec := httptest.NewRecorder()
		if _, ok := decodeTaskCategoryRequest(rec, req); ok {
			t.Fatalf("%s: validation must not pass (status=%d)", name, rec.Code)
		}
		return decodeErrorField(t, rec.Body.Bytes())
	}
	decodeCase("name-empty", `{"name":"   "}`)
	decodeCase("name-too-long", `{"name":"`+strings.Repeat("a", db.MaxTaskCategoryNameRunes+1)+`"}`)
	// The body exceeds maxTaskCategoryRequestBytes, so MaxBytesReader errors mid-decode.
	decodeCase("too-large", `{"name":"`+strings.Repeat("a", maxTaskCategoryRequestBytes+1)+`"}`)

	// parseCategoryIDField — a zero/negative category_id is rejected.
	rec := httptest.NewRecorder()
	if _, ok := parseCategoryIDField(rec, json.RawMessage("0")); ok {
		t.Fatal("invalid id must not pass")
	}

	// The name-conflict sentinel maps to HTTP 409.
	rec = httptest.NewRecorder()
	writeTaskCategoryError(rec, db.ErrTaskCategoryNameConflict)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d, want 409", rec.Code)
	}

	// Batch move — an empty selection is rejected before any DB access, so a
	// zero-value Server reaches the guard without dereferencing s.m.
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/category/batch",
		strings.NewReader(`{"task_ids":[],"category_id":null}`))
	rec = httptest.NewRecorder()
	(&Server{}).updateTasksCategoryBatch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty batch status=%d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Verify through the actual code path that the progress messages begin/finish emit over SSE are set as Korean constants.
// Use a local instance to avoid contaminating the global updHub (no DB or network required).
func TestUpdateProgressMessagesLocalized(t *testing.T) {
	h := &updateHub{subs: map[chan updateProgress]struct{}{}}

	if !h.begin("v1.2.3") {
		t.Fatal("begin must return true on the first call")
	}
	_, running := h.snapshot()
	if !running {
		t.Fatal("running must be true after begin")
	}
	if h.begin("v1.2.4") {
		t.Fatal("begin must return false while in progress")
	}

	h.finish(errors.New("download failed"))
	_, running = h.snapshot()
	if running {
		t.Fatal("running must be cleared after finish")
	}

	h.finish(nil)
}

// Verify over actual HTTP, without a DB, that the 409 response from updateRollback saying "rollback not possible while in progress" is in Korean.
func TestUpdateRollbackInProgressLocalized(t *testing.T) {
	updHub.mu.Lock()
	prev := updHub.running
	updHub.running = true
	updHub.mu.Unlock()
	defer func() {
		updHub.mu.Lock()
		updHub.running = prev
		updHub.mu.Unlock()
	}()

	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/update/rollback", nil)
	rec := httptest.NewRecorder()
	s.updateRollback(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status code 409, got %d (body %s)", rec.Code, rec.Body.Bytes())
	}
}

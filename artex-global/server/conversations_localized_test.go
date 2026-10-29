package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// conversations.go handler tests: conversation API error responses.

// TestDecodeConversationRequestTooLargeLocalized checks an oversized conversation body is rejected with 413
// and a JSON error body. The exact error wording is not pinned.
func TestDecodeConversationRequestTooLargeLocalized(t *testing.T) {
	// A valid JSON body exceeding the 64KB limit. MaxBytesReader returns the over-limit error mid-read.
	body := `{"title":"` + strings.Repeat("a", maxConversationRequestBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/conversations", strings.NewReader(body))
	rec := httptest.NewRecorder()
	var dst struct {
		Title string `json:"title"`
	}
	if decodeConversationRequest(rec, req, &dst) {
		t.Fatal("the body exceeded the limit, but decodeConversationRequest returned true")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status code = %d, expected = %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v (body=%q)", err, rec.Body.String())
	}
}

// TestConversationDefaultTitlesLocalized checks that the two default titles differ, since the auto-title branch keys on convDefaultTitle.
func TestConversationDefaultTitlesLocalized(t *testing.T) {
	if convDefaultTitle == convAttachmentTitle {
		t.Fatal("the default title and the attachment default title must not be the same")
	}
}

// TestIsDefaultConversationTitle pins the judgment of the automatic title branch. The generated default
// (convDefaultTitle) and empty titles are eligible for automatic titling and are not user-chosen titles. Generated
// This guards against a regression where the default value and the sentinel are the same constant, so the two drift apart and the automatic title never gets applied.
func TestIsDefaultConversationTitle(t *testing.T) {
	if !isDefaultConversationTitle("") {
		t.Fatal("an empty title must be eligible for auto-titling")
	}
	if !isDefaultConversationTitle(convDefaultTitle) {
		t.Fatalf("the generated default %q must be eligible for auto-titling", convDefaultTitle)
	}
	if isDefaultConversationTitle("사용자가 지은 제목") {
		t.Fatal("a user-chosen title must not be eligible for auto-titling")
	}
}

// TestTranscriptErrorSummaryLocalized checks the activity transcript error wrapper keeps the original error text.
func TestTranscriptErrorSummaryLocalized(t *testing.T) {
	cases := []struct {
		name  string
		label string
		errm  string
	}{
		{"chat_turn", "", "connection reset"},
		{"main_agent", "main agent", "connection reset"},
	}
	for _, c := range cases {
		got := transcriptErrorSummary(c.label, c.errm)
		if !strings.Contains(got, c.errm) {
			t.Fatalf("%s: original err was not preserved: %q", c.name, got)
		}
	}
}

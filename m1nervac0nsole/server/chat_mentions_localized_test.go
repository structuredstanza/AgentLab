package server

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestChatMentionErrorsLocalized checks the user-facing @mention (citation) error responses.
// Wire token labels and agent-input snapshot markers are intentionally not checked here.
func TestChatMentionErrorsLocalized(t *testing.T) {
	// parseChatMentions — a non-positive id inside a valid wire token.
	if _, err := parseChatMentions("@[finding#0]"); err == nil {
		t.Fatal("an invalid citation ID must not pass")
	}

	// parseChatMentions — exceeding the per-message mention cap (11 distinct ids).
	var b strings.Builder
	for i := 1; i <= 11; i++ {
		fmt.Fprintf(&b, "@[finding#%d] ", i)
	}
	if _, err := parseChatMentions(b.String()); err == nil {
		t.Fatal("exceeding the citation cap must not pass")
	}

	// composeChatMentionMessage — a mention is present but the database is nil.
	if _, err := composeChatMentionMessage(nil, "@[finding#1]"); err == nil {
		t.Fatal("citation resolution must not pass without a DB")
	}

	// searchChatMentions — invalid kind and over-long query are rejected before
	// the database handle is touched, so &Server{} is enough to reach the branch.
	for _, q := range []string{"kind=unsupported", "q=" + url.QueryEscape(strings.Repeat("char", 201))} {
		w := httptest.NewRecorder()
		(&Server{}).searchChatMentions(w, httptest.NewRequest("GET", "/api/chat/mentions?"+q, nil))
		if w.Code != 400 {
			t.Fatalf("expected a validation failure (400) but got %d (%s)", w.Code, q)
		}
	}

	// Every mention kind must have a display label.
	for _, kind := range []string{"finding", "asset", "company", "endpoint", "ip", "app", "root_domain", "subdomain", "service"} {
		if chatMentionKindLabel[kind] == "" {
			t.Fatalf("kind label is missing: %s", kind)
		}
	}
}

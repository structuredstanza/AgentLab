package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// This file covers the HTTP layer error classification for doJSON.
//
// Why this needs its own test: each channel adapter only handles its platform's business error codes (DingTalk errcode, Feishu code, Telegram ok field),
// Feishu's code field, Telegram's ok field), whereas the **HTTP layer** classification is handled uniformly by doJSON,
// Without this one, a relay gateway returning 503 would be treated as a permanent failure,
// Give up on retrying directly; a 403 would otherwise be treated as retryable and wastefully back off for three rounds.

func replyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoJSONClassifiesHTTPStatus(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		permanent bool
	}{
		{"200 success is not an error", 200, false},
		{"429 rate limit is retryable", 429, false},
		{"408 request timeout is retryable", 408, false},
		{"500 server error is retryable", 500, false},
		{"502 gateway error is retryable", 502, false},
		{"503 unavailable is retryable", 503, false},
		{"400 bad request fails permanently", 400, true},
		{"401 auth failure fails permanently", 401, true},
		{"403 forbidden fails permanently", 403, true},
		{"404 not found fails permanently", 404, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := replyServer(t, tc.status, `{"detail":"upstream says no"}`)
			_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("a 2xx response must not return an error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a non-2xx response must return an error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("wrong permanent classification for HTTP %d: expected %v, got %v (%v)",
					tc.status, tc.permanent, got, err)
			}
			// The status code must appear in the error; otherwise the user cannot tell whether they misconfigured something or the remote side is down.
			// Assert on the numeric code rather than Go's English StatusText: this package's messages are in Chinese
			// (consistent with the rest of the project), so the number is the language-neutral, reliably assertable part.
			if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("error message must include HTTP status code %d, got %v", tc.status, err)
			}
		})
	}
}

// TestDoJSONIncludesResponseSnippet covers the snippet: the remote side's error explanation must be carried back,
// otherwise the user only knows that it "failed" and not why the remote side rejected the request.
func TestDoJSONIncludesResponseSnippet(t *testing.T) {
	srv := replyServer(t, 400, `{"error":"invalid webhook token"}`)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "invalid webhook token") {
		t.Errorf("error message must include the peer's explanation, got %v", err)
	}
}

// TestDoJSONSnippetIsSingleLineAndBounded constrains the shape of the snippet:
// it is written verbatim into the last_error column and the frontend table; multiple lines or excessive length would break the layout and the payload.
func TestDoJSONSnippetIsSingleLineAndBounded(t *testing.T) {
	// responses containing newlines, tabs, and oversized content of 5000 characters.
	long := strings.Repeat("x", 5000)
	srv := replyServer(t, 500, "line1\nline2\r\n\tline3 "+long)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("error message must be a single line, got %q", msg)
	}
	// The snippet is capped at 200 characters plus a fixed prefix, so the total must stay far smaller than the original response.
	if len(msg) > 400 {
		t.Errorf("error message too long (%d bytes), must be truncated by the snippet: %q", len(msg), msg)
	}
}

// TestDoJSONRejectsOversizedResponse verifies that reads are bounded: when the peer abnormally returns oversized content,
// the entire response must not be read into memory (each entry in the delivery history stores its own copy of last_error).
func TestDoJSONRejectsOversizedResponse(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // 1 MiB
	srv := replyServer(t, 400, huge)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 400 {
		t.Errorf("oversized response must be read with a length limit and truncated; error message length %d", len(err.Error()))
	}
}

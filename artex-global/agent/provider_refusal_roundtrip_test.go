package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
)

type fakeRoundTripper struct {
	status      int
	contentType string
	body        string
}

func (f fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	if f.contentType != "" {
		h.Set("Content-Type", f.contentType)
	}
	return &http.Response{
		StatusCode: f.status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(f.body)),
	}, nil
}

// Refusal metadata is observed without changing the body consumed by the provider.
func TestRoundTripRefusalSniff(t *testing.T) {
	refusalChat := `{"choices":[{"message":{"refusal":"I can't help with that"},"finish_reason":"content_filter"}]}`
	okChat := `{"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}]}`

	cases := []struct {
		name        string
		format      llm.Format
		contentType string
		body        string
		withSink    bool
		want        bool
	}{
		{"openai non-streaming refusal", llm.FormatOpenAI, "application/json", refusalChat, true, true},
		{"openai non-streaming ok", llm.FormatOpenAI, "application/json", okChat, true, false},
		{"anthropic not handled here", llm.FormatAnthropic, "application/json", `{"stop_reason":"refusal"}`, true, false},
		{"no sink on context", llm.FormatOpenAI, "application/json", refusalChat, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := quotaAwareTransport{base: fakeRoundTripper{status: 200, contentType: c.contentType, body: c.body}, format: c.format}
			ctx := context.Background()
			if c.withSink {
				ctx = llmrec.WithRefusalSink(ctx)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/v1", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			if string(got) != c.body {
				t.Fatalf("response body was consumed/altered: got %q want %q", got, c.body)
			}
			if c.withSink && llmrec.RefusalObserved(ctx) != c.want {
				t.Fatalf("RefusalObserved = %v, want %v", llmrec.RefusalObserved(ctx), c.want)
			}
		})
	}
}

type errBodyRoundTripper struct{}

func (errBodyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(io.MultiReader(strings.NewReader(`{"choices":[`), errReader{})),
	}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// A body read failure must surface as an error, never be swallowed into an empty
// success or a refusal verdict.
func TestRoundTripPropagatesBodyReadError(t *testing.T) {
	tr := quotaAwareTransport{base: errBodyRoundTripper{}, format: llm.FormatOpenAI}
	ctx := llmrec.WithRefusalSink(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/v1", nil)
	if _, err := tr.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("expected propagated read error, got %v", err)
	}
	if llmrec.RefusalObserved(ctx) {
		t.Fatal("read failure must not be recorded as refusal")
	}
}

package llmrec

import (
	"context"
	"io"
	"strings"
	"testing"
)

// The tee mirrors the whole response body into memory and then into a DB text
// column. Nothing bounds it, so a gateway error page or a long stream is
// retained in full — three times over when the transport retries.
func TestCaptureIsBounded(t *testing.T) {
	ctx, c := NewCapture(context.Background())
	_ = ctx

	const bodySize = 32 << 20 // a 32 MiB upstream body
	rc := io.NopCloser(strings.NewReader(strings.Repeat("x", bodySize)))
	tb := c.TeeResponse(502, rc)
	if _, err := io.Copy(io.Discard, tb); err != nil {
		t.Fatal(err)
	}
	got := len(c.RawResponse())
	t.Logf("captured %d bytes of a %d-byte body", got, bodySize)
	if got > 1<<20 {
		t.Fatalf("capture retained %d bytes; want it bounded", got)
	}
	if !strings.Contains(c.RawResponse(), "truncated") {
		t.Errorf("the snapshot does not say it was cut: %q", c.RawResponse()[got-80:])
	}

	// a normal response is kept whole and carries no marker
	_, c2 := NewCapture(context.Background())
	body := strings.Repeat("y", 1000)
	if _, err := io.Copy(io.Discard, c2.TeeResponse(200, io.NopCloser(strings.NewReader(body)))); err != nil {
		t.Fatal(err)
	}
	if got := c2.RawResponse(); !strings.Contains(got, body) || strings.Contains(got, "truncated") {
		t.Fatalf("a small body was altered: %d bytes", len(got))
	}
}

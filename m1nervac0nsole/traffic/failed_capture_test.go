package traffic

import (
	"strings"
	"testing"
)

// A capture with no response at all (blocked by a WAF, aborted, DNS failure)
// must not be recorded as HTTP 200. The old default rewrote status 0 to 200,
// which turned a blocked request into apparent success.
func TestFailedCaptureKeepsItsStatusAndSaysWhy(t *testing.T) {
	tr, err := OpenWithTransport(t.TempDir(), "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })

	if err := tr.RecordExternal(ExternalExchange{
		Method: "GET", URL: "https://target.invalid/blocked", Status: 0, Failed: true,
		RequestHeaders:  map[string]string{"x-probe": "1"},
		ResponseHeaders: map[string]string{"x-capture-error": "net::ERR_BLOCKED_BY_CLIENT"},
	}); err != nil {
		t.Fatal(err)
	}
	// an omitted status still keeps the historical default
	if err := tr.RecordExternal(ExternalExchange{
		Method: "GET", URL: "https://target.invalid/normal",
	}); err != nil {
		t.Fatal(err)
	}

	var failed, normal int
	var head string
	if err := tr.DB().QueryRow(`SELECT status FROM exchanges WHERE url LIKE '%/blocked'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := tr.DB().QueryRow(`SELECT status FROM exchanges WHERE url LIKE '%/normal'`).Scan(&normal); err != nil {
		t.Fatal(err)
	}
	if err := tr.DB().QueryRow(`SELECT resp_head FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE url LIKE '%/blocked')`).Scan(&head); err != nil {
		t.Fatal(err)
	}

	if failed != 0 {
		t.Errorf("blocked request stored as status %d, want 0", failed)
	}
	if normal != 200 {
		t.Errorf("status-omitted request stored as %d, want the historical 200", normal)
	}
	if !strings.Contains(head, "no response") || !strings.Contains(head, "ERR_BLOCKED_BY_CLIENT") {
		t.Errorf("stored head does not explain the failure: %q", head)
	}
}

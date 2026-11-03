package traffic

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

// Exchange ids are <unix-second>-<seq>. The suffix used to be taken modulo
// 10000, so a burst inside one second reused ids and INSERT OR REPLACE
// silently overwrote captures that were already stored.
func TestExternalIngestKeepsEveryExchangeWithinOneSecond(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })

	const n = 10050 // one full wrap of the old %10000 suffix
	for time.Now().Nanosecond() > 50_000_000 {
		time.Sleep(5 * time.Millisecond) // start just after a second boundary
	}
	for i := 0; i < n; i++ {
		u, _ := url.Parse(fmt.Sprintf("https://probe.example/item/%d", i))
		if err := tr.RecordExternal(ExternalExchange{
			Method: "GET", URL: u.String(), Status: 200,
			RequestHeaders:  map[string]string{"content-type": "text/plain"},
			ResponseHeaders: map[string]string{"content-type": "text/plain"},
			RequestBody:     "r", ResponseBody: "s",
		}); err != nil {
			t.Fatal(err)
		}
	}
	var rows, distinct int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM exchanges WHERE host='probe.example'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := tr.DB().QueryRow(`SELECT count(DISTINCT url) FROM exchanges WHERE host='probe.example'`).Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	if rows != n || distinct != n {
		t.Fatalf("stored %d rows / %d distinct URLs of %d submitted: captures were overwritten", rows, distinct, n)
	}
}

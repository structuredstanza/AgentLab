package traffic

import (
	"strings"
	"testing"
)

func TestRecordExternalStoresLikeProxyTraffic(t *testing.T) {
	tr, _ := openTraffic(t)

	big := strings.Repeat("A", 2<<20) // spills to the blob store
	err := tr.RecordExternal(ExternalExchange{
		Method:          "POST",
		URL:             "https://api.example.com/v1/login",
		Status:          200,
		RequestHeaders:  map[string]string{"content-type": "application/json", "authorization": "Bearer xyz"},
		RequestBody:     `{"user":"u1","password":"p1"}`,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    `{"token":"tok"}`,
	})
	if err != nil {
		t.Fatalf("RecordExternal small: %v", err)
	}
	if err := tr.RecordExternal(ExternalExchange{
		Method:          "GET",
		URL:             "https://api.example.com/v1/items?page=1",
		Status:          404,
		ResponseHeaders: map[string]string{"content-type": "text/html"},
		ResponseBody:    big,
	}); err != nil {
		t.Fatalf("RecordExternal spilled: %v", err)
	}

	if n, _ := tr.Count(); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
	rows, total, err := tr.Page(PageQuery{Query: "login", RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("filtered page = %d rows (total %d), want 1", len(rows), total)
	}
	req, resp, err := tr.Get(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req, "POST /v1/login") || !strings.Contains(req, "Bearer xyz") || !strings.Contains(req, `"user":"u1"`) {
		t.Fatalf("request side incomplete: %q", req)
	}
	if !strings.Contains(resp, `{"token":"tok"}`) {
		t.Fatalf("response side incomplete: %q", resp)
	}

	// The spilled entry must be FTS-searchable by its body content too.
	rows, total, err = tr.Page(PageQuery{Body: strings.Repeat("A", 64), RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("spilled-body FTS search = %d rows (total %d), want 1", len(rows), total)
	}
}

// A partial capture keeps the prefix it was handed, the response's full declared
// length, and a marker saying the body is not the whole response; a complete
// capture stores its exact body and no marker.
func TestRecordExternalStoresPartialBodyWithDeclaredLength(t *testing.T) {
	tr, _ := openTraffic(t)
	const declared = 4 << 20
	prefix := strings.Repeat("P", maxInlineBody)
	if err := tr.RecordExternal(ExternalExchange{
		Method:          "GET",
		URL:             "https://api.example.com/partial",
		Status:          200,
		ResponseHeaders: map[string]string{"content-type": "text/plain"},
		ResponseBody:    prefix,
		Partial:         true,
		RespLen:         declared,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tr.RecordExternal(ExternalExchange{
		Method:          "GET",
		URL:             "https://api.example.com/complete",
		Status:          200,
		ResponseHeaders: map[string]string{"content-type": "text/plain"},
		ResponseBody:    "exact",
	}); err != nil {
		t.Fatal(err)
	}

	rows, _, err := tr.Page(PageQuery{Query: "partial", RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("partial page = %d rows, err=%v", len(rows), err)
	}
	if rows[0].RespLen != declared {
		t.Fatalf("resp_len = %d, want the declared %d", rows[0].RespLen, declared)
	}
	_, resp, err := tr.Get(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, partialMarker) {
		t.Fatalf("partial response head lacks the marker: %q", clip(resp, 300))
	}
	if !strings.Contains(resp, prefix) {
		t.Fatal("the prefix that was captured was not stored")
	}

	rows, _, err = tr.Page(PageQuery{Query: "complete", RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("complete page = %d rows, err=%v", len(rows), err)
	}
	if rows[0].RespLen != len("exact") {
		t.Fatalf("complete resp_len = %d, want %d", rows[0].RespLen, len("exact"))
	}
	_, resp, err = tr.Get(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp, partialMarker) || !strings.HasSuffix(resp, "\n\nexact") {
		t.Fatalf("a complete capture must be stored exactly as before: %q", clip(resp, 300))
	}
}

func TestRecordExternalRejectsBadInput(t *testing.T) {
	tr, _ := openTraffic(t)
	cases := []ExternalExchange{
		{Method: "GET", URL: "not a url"},
		{Method: "GET", URL: ""},
		{Method: "", URL: "https://api.example.com/"},
	}
	for i, c := range cases {
		if err := tr.RecordExternal(c); err == nil {
			t.Fatalf("case %d: expected an error for %+v", i, c)
		}
	}
}

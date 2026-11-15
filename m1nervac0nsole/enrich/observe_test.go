package enrich

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc drives the observation path without a proxy or a database.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The observation offers the body as the probe read it: a body read to the end is
// exact, and one over the cap or cut short is the prefix that was read plus the
// response's full length, so a consumer can tell the two apart.
func TestObservingTransportReportsPrefixWithFullLength(t *testing.T) {
	const overCap = maxObservedBody + 100
	cases := []struct {
		name       string
		declared   int64 // resp.ContentLength; <0 = unknown
		size       int
		readToEOF  bool
		read       int // bytes read when not reading to the end
		complete   bool
		wantLen    int   // len(ResponseBody)
		wantLength int64 // DeclaredLength
	}{
		{name: "complete body", declared: 8, size: 8, readToEOF: true, complete: true, wantLen: 8, wantLength: 8},
		{name: "complete body of unknown length", declared: -1, size: 8, readToEOF: true, complete: true, wantLen: 8, wantLength: 8},
		{name: "over the cap", declared: overCap, size: overCap, readToEOF: true, wantLen: maxObservedBody, wantLength: overCap},
		{name: "over the cap of unknown length", declared: -1, size: overCap, readToEOF: true, wantLen: maxObservedBody, wantLength: overCap},
		{name: "partial read", declared: 4096, size: 4096, read: 1024, wantLen: 1024, wantLength: 4096},
		{name: "partial read of unknown length", declared: -1, size: 4096, read: 1024, wantLen: 1024, wantLength: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Distinctive bytes, so "the prefix that was read" is checkable.
			payload := strings.Repeat("0123456789", tc.size/10+1)[:tc.size]
			var got []Observation
			tr := &observingTransport{
				base: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode:    http.StatusOK,
						ContentLength: tc.declared,
						Header:        http.Header{},
						Body:          io.NopCloser(strings.NewReader(payload)),
					}, nil
				}),
				observe: func(o Observation) { got = append(got, o) },
			}
			req, err := http.NewRequest("GET", "https://target.example/page", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			if tc.readToEOF {
				_, err = io.ReadAll(resp.Body)
			} else {
				_, err = io.ReadAll(io.LimitReader(resp.Body, int64(tc.read)))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}

			if len(got) != 1 {
				t.Fatalf("want one observation, got %d", len(got))
			}
			o := got[0]
			if o.Complete != tc.complete || len(o.ResponseBody) != tc.wantLen || o.DeclaredLength != tc.wantLength {
				t.Fatalf("observation = complete=%v len=%d declared=%d, want complete=%v len=%d declared=%d",
					o.Complete, len(o.ResponseBody), o.DeclaredLength, tc.complete, tc.wantLen, tc.wantLength)
			}
			if tc.complete {
				if o.ResponseBody != payload {
					t.Fatal("a complete body must be offered exactly")
				}
			} else if o.ResponseBody != payload[:tc.wantLen] {
				t.Fatal("an incomplete body must be the prefix that was read")
			}
		})
	}
}

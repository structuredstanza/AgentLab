package egress

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestAcceptedEncodings(t *testing.T) {
	cases := []struct {
		header string
		want   map[string]bool
	}{
		{"", map[string]bool{}},
		{"identity", map[string]bool{}},
		{"gzip", map[string]bool{"gzip": true}},
		{"gzip, deflate;q=0.5, br", map[string]bool{"gzip": true, "deflate": true, "br": true}},
		{"gzip;q=0", map[string]bool{"gzip": false}},
		{"gzip;q=0, *;q=0.1", map[string]bool{"gzip": false, "*": true}},
	}
	for _, tc := range cases {
		got := acceptedEncodings([][2]string{{"Accept-Encoding", tc.header}})
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("acceptedEncodings(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// A q=0 entry is a refusal, and "*" must not override it.
func TestNegotiatedRespectsExplicitRefusal(t *testing.T) {
	accepted := acceptedEncodings([][2]string{{"Accept-Encoding", "gzip;q=0, *"}})
	if negotiated([]string{"gzip"}, accepted) {
		t.Fatal("a coding refused with q=0 was treated as accepted through *")
	}
	if !negotiated([]string{"br"}, accepted) {
		t.Fatal("* did not accept a coding the header did not name")
	}
	if negotiated([]string{"gzip"}, acceptedEncodings(nil)) {
		t.Fatal("an absent Accept-Encoding was treated as accepting gzip")
	}
}

// A chain is applied in header order, so it must be undone last-first.
func TestDecodeContentReversesChain(t *testing.T) {
	plain := []byte("minervacyb chained")
	body := io.NopCloser(bytes.NewReader(encodeForTest(t, "br", encodeForTest(t, "gzip", plain))))
	decoded, err := decodeContent(body, []string{"gzip", "br"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decoded %q, want %q", got, plain)
	}
}

// encodeForTest applies one content coding to plain.
func encodeForTest(t *testing.T, coding string, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch coding {
	case "gzip":
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "deflate":
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	case "br":
		w := brotli.NewWriter(&buf)
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown coding %q", coding)
	}
	return buf.Bytes()
}

// getThroughProxy sends one GET with an explicit Accept-Encoding and returns the
// response head and the raw bytes. Compression is disabled on the client so the
// test sees exactly what the proxy sent, never what Go would decode for it.
func getThroughProxy(t *testing.T, p *Proxy, target, acceptEncoding string) (*http.Response, []byte) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		Proxy:              http.ProxyURL(mustURL(p.Addr())),
		DisableCompression: true,
	}}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

// The proxy offers the browser's "gzip, deflate, br" upstream, so an origin may
// answer with a coding the caller never negotiated. The caller must receive the
// decoded page, not compressed bytes it cannot read; that is the WebFetch
// failure this pins. The browser's Accept-Encoding must still reach the origin.
func TestProxyDecodesUnnegotiatedContentEncoding(t *testing.T) {
	plain := []byte("<html><body>minervacyb</body></html>")
	cases := []struct {
		name, accept, coding string
	}{
		{"absent header, brotli origin", "", "br"},
		{"gzip-only client, brotli origin", "gzip", "br"},
		{"identity client, gzip origin", "identity", "gzip"},
		{"identity client, deflate origin", "identity", "deflate"},
		{"client refused br with q=0", "br;q=0", "br"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := encodeForTest(t, tc.coding, plain)
			var upstreamAccept string
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamAccept = r.Header.Get("Accept-Encoding")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Content-Encoding", tc.coding)
				w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
				w.Write(wire)
			}))
			defer origin.Close()

			p := newTestProxy(t, nil)
			resp, body := getThroughProxy(t, p, origin.URL, tc.accept)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Encoding"); got != "" {
				t.Errorf("client received Content-Encoding %q for a coding it did not negotiate", got)
			}
			if got := resp.Header.Get("Content-Length"); got != "" {
				t.Errorf("client received Content-Length %q for a decoded body", got)
			}
			if string(body) != string(plain) {
				t.Errorf("body = %q, want the decoded page %q", body, plain)
			}
			if upstreamAccept != "gzip, deflate, br" {
				t.Errorf("origin saw Accept-Encoding %q, want the browser identity", upstreamAccept)
			}
		})
	}
}

// A client that did negotiate the coding must receive it untouched: the proxy
// may not decode a body the client asked for and can handle.
func TestProxyPreservesNegotiatedContentEncoding(t *testing.T) {
	plain := []byte("<html><body>minervacyb</body></html>")
	for _, coding := range []string{"gzip", "deflate", "br"} {
		t.Run(coding, func(t *testing.T) {
			wire := encodeForTest(t, coding, plain)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Content-Encoding", coding)
				w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
				w.Write(wire)
			}))
			defer origin.Close()

			p := newTestProxy(t, nil)
			resp, body := getThroughProxy(t, p, origin.URL, coding)

			if got := resp.Header.Get("Content-Encoding"); got != coding {
				t.Errorf("Content-Encoding = %q, want %q preserved", got, coding)
			}
			if !bytes.Equal(body, wire) {
				t.Errorf("body was altered for a client that negotiated %s", coding)
			}
		})
	}
}

// A body-bearing 206 whose coding the caller did not negotiate cannot be
// decoded (a partial coded stream is not a body its Content-Range describes)
// and must not be forwarded coded, so it fails closed and attributable.
func TestProxyFailsClosedOnUnnegotiatedPartialContent(t *testing.T) {
	wire := encodeForTest(t, "br", []byte("<html><body>minervacyb</body></html>"))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Range", "bytes 0-31/64")
		w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(wire)
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	resp, body := getThroughProxy(t, p, origin.URL, "gzip")

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := resp.Header.Get(HeaderEgress); got != egressDecodeFailed {
		t.Fatalf("%s = %q, want %q", HeaderEgress, got, egressDecodeFailed)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("client received Content-Encoding %q on a failure it did not negotiate", got)
	}
	if bytes.Contains(body, wire) {
		t.Fatalf("body leaked the target's coded bytes: %q", body)
	}
	if !strings.Contains(string(body), egressDecodeFailed) {
		t.Fatalf("body %q does not name the failure", body)
	}
}

// A caller that negotiated the coding still gets its 206 untouched: the range
// and its Content-Range stay meaningful.
func TestProxyPreservesNegotiatedPartialContent(t *testing.T) {
	wire := encodeForTest(t, "br", []byte("<html><body>minervacyb</body></html>"))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Range", "bytes 0-31/64")
		w.Header().Set("Content-Length", strconv.Itoa(len(wire)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(wire)
	}))
	defer origin.Close()

	p := newTestProxy(t, nil)
	resp, body := getThroughProxy(t, p, origin.URL, "br")

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br preserved", got)
	}
	if got := resp.Header.Get("Content-Range"); got != "bytes 0-31/64" {
		t.Errorf("Content-Range = %q, want the origin's range preserved", got)
	}
	if !bytes.Equal(body, wire) {
		t.Error("a negotiated 206 body was altered")
	}
}

// A coding the proxy cannot decode must become a proxy-labelled failure. Passing
// the coded bytes through would make the caller store them as the site's answer.
func TestProxyLabelsUndecodableContentEncoding(t *testing.T) {
	cases := []struct {
		name, coding string
		wire         []byte
	}{
		{"corrupt gzip", "gzip", []byte("not a gzip stream")},
		{"unsupported zstd", "zstd", []byte("not zstd either")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", tc.coding)
				w.Header().Set("Content-Length", strconv.Itoa(len(tc.wire)))
				w.Write(tc.wire)
			}))
			defer origin.Close()

			p := newTestProxy(t, nil)
			resp, body := getThroughProxy(t, p, origin.URL, "")

			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", resp.StatusCode)
			}
			if got := resp.Header.Get(HeaderEgress); got != egressDecodeFailed {
				t.Fatalf("%s = %q, want %q", HeaderEgress, got, egressDecodeFailed)
			}
			if strings.Contains(string(body), string(tc.wire)) {
				t.Fatalf("body leaked the target's coded bytes: %q", body)
			}
			if !strings.Contains(string(body), egressDecodeFailed) {
				t.Fatalf("body %q does not name the failure", body)
			}
		})
	}
}

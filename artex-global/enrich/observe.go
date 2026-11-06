package enrich

import (
	"io"
	"net/http"
	"strings"
	"sync"
)

// maxObservedBody caps the response body handed to Options.Observe, matching the
// browser-ingest cap, so one probe cannot bloat the traffic store.
const maxObservedBody = 256 << 10

// Observation is one request/response exchange between the engine's client and
// the masking proxy, as the client saw it. A redirect chain yields one per hop.
type Observation struct {
	Method string
	URL    string
	Status int
	// Failed means no response arrived (proxy down, TLS verification failed,
	// timeout); ResponseHeaders then carries "x-capture-error".
	Failed          bool
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	// Complete is true only when the whole response body was read, matched any
	// declared length, and fit within maxObservedBody. ResponseBody is then the
	// exact body. When Complete is false (and Failed is false) ResponseBody is
	// empty: a prefix is never offered as if it were the response, because a
	// consumer (evidence binding) would take its length for the real size.
	Complete     bool
	ResponseBody string
}

// observingTransport reports every round trip made through base. Redirect hops
// are separate round trips, so they are all observed uniformly, and an
// out-of-boundary redirect (refused before it is sent) is never observed because
// it never happens.
type observingTransport struct {
	base    http.RoundTripper
	observe func(Observation)
	secret  string // scrubbed from error text (the proxy URL may carry credentials)
}

func (t *observingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		t.observe(Observation{
			Method:          req.Method,
			URL:             req.URL.String(),
			Failed:          true,
			RequestHeaders:  flattenHeader(req.Header),
			ResponseHeaders: map[string]string{"x-capture-error": errDetail(err, req.URL.String(), t.secret).Error()},
		})
		return nil, err
	}
	declared := resp.ContentLength
	resp.Body = &observedBody{
		ReadCloser: resp.Body,
		declared:   declared,
		fire: func(complete bool, body string) {
			o := Observation{
				Method:          req.Method,
				URL:             req.URL.String(),
				Status:          resp.StatusCode,
				RequestHeaders:  flattenHeader(req.Header),
				ResponseHeaders: flattenHeader(resp.Header),
				Complete:        complete,
			}
			if complete {
				o.ResponseBody = body
			}
			t.observe(o)
		},
	}
	return resp, nil
}

// observedBody copies the body as it is read (up to the cap) and reports the
// exchange exactly once, when it is closed.
type observedBody struct {
	io.ReadCloser
	declared int64 // resp.ContentLength; <0 = unknown
	fire     func(complete bool, body string)
	once     sync.Once
	buf      []byte
	total    int64
	eof      bool
	readErr  bool
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.total += int64(n)
		if room := maxObservedBody - len(b.buf); room > 0 {
			if n < room {
				room = n
			}
			b.buf = append(b.buf, p[:room]...)
		}
	}
	switch {
	case err == io.EOF:
		b.eof = true
	case err != nil:
		b.readErr = true
	}
	return n, err
}

func (b *observedBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		complete := b.eof && !b.readErr && b.total <= maxObservedBody &&
			(b.declared < 0 || b.total == b.declared)
		b.fire(complete, string(b.buf))
	})
	return err
}

func flattenHeader(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[strings.ToLower(k)] = strings.Join(vs, ", ")
	}
	return out
}

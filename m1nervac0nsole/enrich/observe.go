package enrich

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/egress"
)

// maxObservedBody caps the response body handed to Options.Observe, matching the
// browser-ingest cap, so one probe cannot bloat the traffic store. Bytes past the
// cap are not offered, but the observation still reports the response's full
// length, so the prefix is never mistaken for the whole body.
const maxObservedBody = 256 << 10

// Observation is one request/response exchange between the engine's client and
// the masking proxy, as the client saw it. A redirect chain yields one per hop.
type Observation struct {
	Method string
	URL    string
	Status int
	// Failed means no response arrived (proxy down, TLS verification failed,
	// timeout); ResponseHeaders then carries "x-capture-error".
	Failed bool
	// ProxyFailure means a response did arrive but the egress proxy produced it
	// (it could not dial the target or read its reply). It is not an exchange
	// with the target and must not be stored as one.
	ProxyFailure    bool
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	// Complete is true only when the whole response body was read, matched any
	// declared length, and fit within maxObservedBody. ResponseBody is then the
	// exact body. When Complete is false (and Failed is false) ResponseBody is the
	// first maxObservedBody bytes that were read, and DeclaredLength is the
	// response's full length, or -1 when the response never stated one and the
	// read did not reach the end: a consumer must take the size from
	// DeclaredLength, never from len(ResponseBody), so a stored prefix cannot pass
	// for the whole response.
	Complete       bool
	DeclaredLength int64
	ResponseBody   string
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
	// A response carrying the proxy's failure header is the proxy's, not the
	// target's: the proxy could not reach the target and said so. Marking it
	// Failed keeps it out of the site's status and out of the traffic store.
	proxyFailure := resp.Header.Get(egress.HeaderEgress) != ""
	resp.Body = &observedBody{
		ReadCloser: resp.Body,
		declared:   declared,
		fire: func(complete bool, full int64, body string) {
			o := Observation{
				Method:          req.Method,
				URL:             req.URL.String(),
				Status:          resp.StatusCode,
				Failed:          proxyFailure,
				ProxyFailure:    proxyFailure,
				RequestHeaders:  flattenHeader(req.Header),
				ResponseHeaders: flattenHeader(resp.Header),
				Complete:        complete,
				DeclaredLength:  full,
			}
			// The proxy's own error page is never offered as the target's body.
			if !proxyFailure {
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
	fire     func(complete bool, declared int64, body string)
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
		b.fire(complete, b.fullLength(), string(b.buf))
	})
	return err
}

// fullLength is the response's full body length: what the response declared when
// that covers everything read, else what was measured once the read reached the
// end, else -1. A body over the cap or cut short still reports its real size, so
// the stored prefix is never taken for the whole response.
func (b *observedBody) fullLength() int64 {
	switch {
	case b.declared >= b.total:
		return b.declared
	case b.eof:
		return b.total
	default:
		return -1
	}
}

func flattenHeader(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[strings.ToLower(k)] = strings.Join(vs, ", ")
	}
	return out
}

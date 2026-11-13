package egress

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
)

// acceptedEncodings returns the content codings the client named in its
// Accept-Encoding header and whether each is acceptable. A caller that names no
// coding is treated as unable to decode one: real clients that omit the header
// (curl without --compressed, Go's transport with compression disabled) do not
// decode, and handing them coded bytes is the bug this policy prevents.
//
// The proxy offers the browser's "gzip, deflate, br" upstream regardless of
// what the caller sent, because that header is part of the fingerprint. The
// origin can therefore answer with a coding this client never negotiated; relay
// uses this set to decide whether the body can be forwarded untouched.
func acceptedEncodings(headers [][2]string) map[string]bool {
	accepted := map[string]bool{}
	for _, kv := range headers {
		if !strings.EqualFold(kv[0], "accept-encoding") {
			continue
		}
		for _, part := range strings.Split(kv[1], ",") {
			token, params, _ := strings.Cut(part, ";")
			token = strings.ToLower(strings.TrimSpace(token))
			if token == "" || token == "identity" {
				continue
			}
			q := 1.0
			for _, param := range strings.Split(params, ";") {
				name, value, ok := strings.Cut(param, "=")
				if ok && strings.EqualFold(strings.TrimSpace(name), "q") {
					if v, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
						q = v
					}
				}
			}
			// Keep q=0 entries: "*" must not make an explicitly refused
			// coding acceptable.
			accepted[token] = q > 0
		}
	}
	return accepted
}

// contentCodings normalises a Content-Encoding value into the codings applied,
// in the order the origin applied them.
func contentCodings(header string) []string {
	var codings []string
	for _, c := range strings.Split(header, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		switch c {
		case "", "identity":
			continue
		case "x-gzip":
			c = "gzip"
		}
		codings = append(codings, c)
	}
	return codings
}

// negotiated reports whether the client accepts every coding in the chain. The
// client must decode the whole chain, so one unaccepted coding is enough to
// make the body unreadable to it. A "*" accepts codings the header does not
// name, but never one it explicitly refused with q=0.
func negotiated(codings []string, accepted map[string]bool) bool {
	for _, c := range codings {
		if ok, listed := accepted[c]; listed {
			if !ok {
				return false
			}
			continue
		}
		if !accepted["*"] {
			return false
		}
	}
	return true
}

// decodeContent undoes an encoding chain the client did not negotiate. The
// caller has already removed the headers that describe the coded body.
//
// A construction error means the origin's coding is unsupported or the stream
// is malformed at its start; it is reported before any response head reaches
// the client, so relay can answer with a proxy-labelled failure.
func decodeContent(body io.ReadCloser, codings []string) (*decodingBody, error) {
	var r io.Reader = body
	// Codings are listed in the order they were applied, so undo them last-first.
	for i := len(codings) - 1; i >= 0; i-- {
		switch codings[i] {
		case "gzip":
			zr, err := gzip.NewReader(r)
			if errors.Is(err, io.EOF) {
				r = strings.NewReader("") // an empty body labelled gzip (redirects, 204)
				continue
			}
			if err != nil {
				return nil, err
			}
			r = zr
		case "deflate":
			dr, err := newDeflateReader(r)
			if err != nil {
				return nil, err
			}
			r = dr
		case "br":
			r = brotli.NewReader(r)
		default:
			return nil, fmt.Errorf("unsupported content encoding %q", codings[i])
		}
	}
	return &decodingBody{Reader: r, body: body}, nil
}

// newDeflateReader reads an HTTP "deflate" body. The standard says zlib-wrapped
// deflate, but servers also send a bare RFC 1951 stream; the two-byte zlib
// header is checked to tell them apart.
func newDeflateReader(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(2)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return strings.NewReader(""), nil // empty body
		}
		return nil, err
	}
	if head[0]&0x0f == 8 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
		return zlib.NewReader(br)
	}
	return flate.NewReader(br), nil
}

// decodingBody closes the origin body and remembers the first decode error, so
// relay can label a mid-stream failure as the proxy's decoding rather than as a
// truncated target response.
type decodingBody struct {
	io.Reader
	body io.Closer
	err  error
}

func (d *decodingBody) Read(p []byte) (int, error) {
	n, err := d.Reader.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		d.err = err
	}
	return n, err
}

func (d *decodingBody) Close() error { return d.body.Close() }

package enrich

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// errUnsupportedEncoding marks a Content-Encoding this package cannot decode
// (for example zstd). The probe still records status and headers; it does not
// pull a title out of compressed bytes.
var errUnsupportedEncoding = errors.New("unsupported content encoding")

// decodeBody undoes a response's Content-Encoding chain over raw. The probe
// advertises "gzip, deflate, br" and the masking proxy forwards a coding the
// caller accepted untouched, so the raw bytes still need decoding here for the
// title to be readable. The transport has compression handling disabled, which
// also keeps what Observe sees raw and the same for every encoding.
//
// encoded reports whether any coding was applied. The returned reader yields
// decoded bytes; callers bound how much they read from it, which bounds the
// decompressed size however small the compressed body is.
func decodeBody(contentEncoding string, raw io.Reader) (r io.Reader, encoded bool, err error) {
	var codings []string
	for _, c := range strings.Split(contentEncoding, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" && c != "identity" {
			codings = append(codings, c)
		}
	}
	if len(codings) == 0 {
		return raw, false, nil
	}
	r = raw
	// Codings are listed in the order they were applied, so undo them last-first.
	for i := len(codings) - 1; i >= 0; i-- {
		switch codings[i] {
		case "gzip", "x-gzip":
			zr, zerr := gzip.NewReader(r)
			if zerr == io.EOF {
				r = strings.NewReader("") // an empty body labelled gzip (redirects, 204)
				continue
			}
			if zerr != nil {
				return nil, true, zerr
			}
			r = zr
		case "deflate":
			dr, derr := newDeflateReader(r)
			if derr != nil {
				return nil, true, derr
			}
			r = dr
		case "br":
			r = brotli.NewReader(r)
		default:
			return nil, true, errUnsupportedEncoding
		}
	}
	return r, true, nil
}

// newDeflateReader reads an HTTP "deflate" body. The standard says zlib-wrapped
// deflate, but servers also send a bare RFC 1951 stream; the two-byte zlib
// header is checked to tell them apart.
func newDeflateReader(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(2)
	if err != nil {
		if err == io.EOF {
			return strings.NewReader(""), nil // empty body
		}
		return nil, err
	}
	if head[0]&0x0f == 8 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
		return zlib.NewReader(br)
	}
	return flate.NewReader(br), nil
}

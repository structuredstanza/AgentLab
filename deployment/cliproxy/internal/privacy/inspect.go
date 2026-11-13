package privacy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/andybalholm/brotli"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

const (
	maxAuthBody      = 64 << 10 // Native grants are not limited to the 4 KiB guest control-input cap.
	maxInferenceBody = 8 << 20
	maxDecodedStream = 1 << 20
	maxScanBudget    = 8 << 20
	maxDecodeDepth   = 3
)

// normalize removes default-ignorable code points before compatibility folding.
func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) || defaultIgnorable(r) {
			continue
		}
		b.WriteRune(r)
	}
	return cases.Fold().String(norm.NFKC.String(b.String()))
}

func defaultIgnorable(r rune) bool {
	return r == 0x00AD || r == 0x034F || r == 0x115F || r == 0x1160 ||
		r == 0x17B4 || r == 0x17B5 || r == 0x3164 || r == 0xFFA0 ||
		(r >= 0x180B && r <= 0x180F) || (r >= 0xFE00 && r <= 0xFE0F) ||
		(r >= 0xFFF0 && r <= 0xFFF8) || (r >= 0x1BCA0 && r <= 0x1BCA3) ||
		(r >= 0x1D173 && r <= 0x1D17A) || (r >= 0xE0000 && r <= 0xE0FFF)
}

// scanner searches outbound text for canaries, decoding JSON escapes, base64,
// and compressed streams up to maxDecodeDepth. Decoded output is charged against
// a per-request budget; exhausting it denies the request.
type scanner struct {
	canaries []string
	budget   int64
}

// text reports ErrDenied when v, or any value it decodes to, contains a canary.
func (s *scanner) text(v string, depth int) error {
	n := normalize(v)
	for _, c := range s.canaries {
		if strings.Contains(n, c) {
			return contract.ErrDenied
		}
	}
	if depth <= 0 {
		return nil
	}
	if dec, ok := unescapeJSON(v); ok {
		if err := s.text(dec, depth-1); err != nil {
			return err
		}
	}
	if raw, ok := decodeBase64(v); ok {
		return s.bytes(raw, depth-1)
	}
	return nil
}

func (s *scanner) bytes(b []byte, depth int) error {
	if err := s.text(string(b), depth); err != nil {
		return err
	}
	out, ok, err := s.inflate(b)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if depth <= 0 {
		return contract.ErrDenied
	}
	return s.bytes(out, depth-1)
}

// inflate decodes gzip or zlib input. A stream that does not decode cleanly is
// reported as not compressed, so the raw bytes are still scanned.
func (s *scanner) inflate(b []byte) ([]byte, bool, error) {
	var r io.Reader
	switch {
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		gz, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false, nil
		}
		r = gz
	case len(b) >= 2 && b[0]&0x0f == 8 && (uint16(b[0])<<8|uint16(b[1]))%31 == 0:
		zr, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false, nil
		}
		r = zr
	default:
		return nil, false, nil
	}
	return s.readBounded(r)
}

func (s *scanner) readBounded(r io.Reader) ([]byte, bool, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxDecodedStream+1))
	if err != nil {
		return nil, false, nil
	}
	if len(out) > maxDecodedStream {
		return nil, false, contract.ErrDenied
	}
	s.budget -= int64(len(out))
	if s.budget < 0 {
		return nil, false, contract.ErrDenied
	}
	return out, true, nil
}

// decodeContentEncoding returns the representation a body is inspected in.
// Unknown or stacked encodings are uninspectable and therefore denied.
func decodeContentEncoding(enc string, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	var r io.Reader
	var err error
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		r, err = zlib.NewReader(bytes.NewReader(body))
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	default:
		return nil, contract.ErrDenied
	}
	if err != nil {
		return nil, contract.ErrDenied
	}
	out, err := io.ReadAll(io.LimitReader(r, maxInferenceBody+1))
	if err != nil || len(out) > maxInferenceBody {
		return nil, contract.ErrDenied
	}
	return out, nil
}

// inspectBody parses a decoded body and scans it. It returns every complete
// native object carrying opaque replay state.
func (s *scanner) inspectBody(ct string, body []byte, k kind) (map[string]any, []string, error) {
	if len(body) == 0 {
		if k == kindInference {
			return nil, nil, contract.ErrDenied
		}
		return nil, nil, nil
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, nil, contract.ErrDenied
	}
	switch mt {
	case "application/json":
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, nil, contract.ErrDenied
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, nil, contract.ErrDenied
		}
		var opaque []string
		if k == kindInference && hasUninspectableMedia(v, false) {
			return nil, nil, contract.ErrDenied
		}
		if err := s.walk(v, &opaque); err != nil {
			return nil, nil, err
		}
		top, _ := v.(map[string]any)
		return top, opaque, nil
	case "application/x-www-form-urlencoded":
		if k != kindAuth {
			return nil, nil, contract.ErrDenied
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, nil, contract.ErrDenied
		}
		return nil, nil, s.scanValues(form)
	default:
		return nil, nil, contract.ErrDenied
	}
}

// walk scans every key and string in decoded JSON. It collects each complete
// native object containing an opaque field for receipt-verified replay.
func (s *scanner) walk(v any, opaque *[]string) error {
	switch x := v.(type) {
	case map[string]any:
		typ, _ := x["type"].(string)
		hasOpaque := false
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			val := x[key]
			if err := s.text(key, maxDecodeDepth); err != nil {
				return err
			}
			if isOpaque(key, typ) {
				if _, ok := val.(string); !ok {
					return contract.ErrDenied
				}
				hasOpaque = true
				continue
			}
			if err := s.walk(val, opaque); err != nil {
				return err
			}
		}
		if hasOpaque {
			block, err := json.Marshal(x)
			if err != nil {
				return contract.ErrDenied
			}
			*opaque = append(*opaque, string(block))
		}
	case []any:
		for _, e := range x {
			if err := s.walk(e, opaque); err != nil {
				return err
			}
		}
	case string:
		return s.text(x, maxDecodeDepth)
	}
	return nil
}

func isOpaque(key, typ string) bool {
	switch key {
	case "encrypted_content", "encryptedContent", "thoughtSignature", "thought_signature":
		return true
	case "signature":
		return typ == "thinking"
	case "data":
		return typ == "redacted_thinking"
	}
	return false
}
func hasUninspectableMedia(v any, inContent bool) bool {
	switch x := v.(type) {
	case map[string]any:
		typ, _ := x["type"].(string)
		if inContent && (typ == "image" || typ == "document" || typ == "file" ||
			typ == "input_image" || typ == "input_file" || typ == "image_url") {
			return true
		}
		for key, value := range x {
			if inContent && (key == "inlineData" || key == "fileData" || key == "image_url") {
				return true
			}
			childContent := inContent || key == "content" || key == "parts" || key == "input"
			if hasUninspectableMedia(value, childContent) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if hasUninspectableMedia(value, inContent) {
				return true
			}
		}
	}
	return false
}

func (s *scanner) scanHeaders(h http.Header) error {
	for name, vals := range h {
		if err := s.text(name, maxDecodeDepth); err != nil {
			return err
		}
		if err := s.scanStrings(vals); err != nil {
			return err
		}
	}
	return nil
}

func (s *scanner) scanQuery(raw string) error {
	if raw == "" {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return contract.ErrDenied
	}
	return s.scanValues(q)
}

func (s *scanner) scanValues(m url.Values) error {
	for key, vals := range m {
		if err := s.text(key, maxDecodeDepth); err != nil {
			return err
		}
		if err := s.scanStrings(vals); err != nil {
			return err
		}
	}
	return nil
}

func (s *scanner) scanStrings(vals []string) error {
	for _, v := range vals {
		if err := s.text(v, maxDecodeDepth); err != nil {
			return err
		}
	}
	return nil
}

// unescapeJSON decodes JSON string escapes that survive as literal text, such as
// a double-escaped \\u0061. It reports false when v holds no escapes.
func unescapeJSON(v string) (string, bool) {
	if !strings.Contains(v, `\`) {
		return "", false
	}
	var out string
	if err := json.Unmarshal([]byte(`"`+v+`"`), &out); err != nil {
		return "", false
	}
	return out, true
}

// decodeBase64 tries each standard and URL-safe alphabet, padded or raw.
func decodeBase64(v string) ([]byte, bool) {
	if len(v) < 8 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(v); err == nil {
			return b, true
		}
	}
	return nil, false
}

package llm

import (
	"regexp"
	"strings"
)

// errBodyLimit bounds how much of an upstream error body reaches an error string.
// The body is copied into the returned error, which callers persist (llm_health,
// llm_records) and display, so it must be short and must not carry a credential an
// upstream chose to echo back — OpenAI answers a bad key with the key in the text.
const errBodyLimit = 300

var errSecretShapes = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\b(x-api-key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|secret|key)"?\s*[=:]\s*"?[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
}

// scrubErrorBody turns a raw upstream error body into a bounded, credential-free
// snippet suitable for an error string that ends up in a database column.
func scrubErrorBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	for _, re := range errSecretShapes {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			if i := strings.IndexAny(m, "=:"); i >= 0 {
				return m[:i+1] + " [REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	if len(s) > errBodyLimit {
		s = s[:errBodyLimit] + "…"
	}
	return s
}

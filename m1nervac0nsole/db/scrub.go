package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

// Placeholders substituted by the scrubbers. They are ASCII, stable and short
// enough that a second pass never matches them again.
const (
	scrubRedacted = "<redacted>"
	scrubTarget   = "<target>"
	scrubIP       = "<ip>"
	scrubEmail    = "<email>"
)

// Secret patterns. Order matters: the specific shapes (private key block,
// JWT, cloud key, URL userinfo) run before the generic key=value rule, and the
// opaque-blob rule runs last so it never eats a keyword it could have kept.
var (
	privateKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	jwtRE        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`)
	awsKeyRE     = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	urlUserRE    = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s/:@]+):([^\s/@]+)@`)
	authHeaderRE = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)("?\s*[:=]\s*)(?:(?:bearer|basic|digest|token)\s+)?("[^"]*"|'[^']*'|[^\s,;&"']+)`)
	bearerRE     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})`)
	cookieRE     = regexp.MustCompile(`(?i)\b(set-cookie|cookie)(\s*:\s*)([^\r\n]+)`)
	secretKVRE   = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])(password|passwd|pwd|secret|token|api[_-]?key|apikey|auth)("?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&"']+)`)
	blobRE       = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)
)

// schemeNouns are the prose words that follow "basic" or "bearer" when a line
// describes a scheme instead of quoting a credential. Anything else after the
// scheme is treated as a token, so an unknown lowercase secret still fails
// closed.
var schemeNouns = map[string]bool{
	"authentication": true,
	"authorization":  true,
	"credentials":    true,
	"credential":     true,
	"challenge":      true,
}

// cookieAttrs are the Set-Cookie attribute names. A line made only of these
// describes cookie flags and holds no session value.
var cookieAttrs = map[string]bool{
	"path": true, "domain": true, "expires": true, "max-age": true,
	"samesite": true, "secure": true, "httponly": true, "partitioned": true,
}

// pathSegmentRE is one segment of a slash-separated path or route: a lowercase
// or camel-case word, or an acronym, with an optional numeric suffix ("v2").
var pathSegmentRE = regexp.MustCompile(`^(?:[a-z]+(?:[A-Z][a-z]+)*|(?:[A-Z][a-z]+)+|[A-Z]+)?[0-9]*$`)

// secretBlob reports whether a long opaque run is a secret rather than a
// slash-separated path or API route. It fails closed: base64 also contains
// slashes, so a run is a path only when it has no base64 padding or "+" and
// every segment is word-shaped. A random blob almost never is.
func secretBlob(s string) bool {
	if !strings.Contains(s, "/") {
		return true
	}
	if strings.ContainsAny(s, "+=") {
		return true
	}
	for _, seg := range strings.Split(s, "/") {
		if !pathSegmentRE.MatchString(seg) {
			return true
		}
	}
	return false
}

// cookieHoldsValue reports whether a Cookie/Set-Cookie line carries something
// to redact. It fails closed: only a line made of attribute names
// ("Path=/; HttpOnly") or of prose about them ("lacks HttpOnly") is kept.
func cookieHoldsValue(line string) bool {
	for _, seg := range strings.Split(line, ";") {
		seg = strings.TrimSpace(seg)
		name, _, hasValue := strings.Cut(seg, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		switch {
		case seg == "" || cookieAttrs[name]:
		case hasValue:
			return true
		case !strings.ContainsAny(seg, " \t"):
			// One bare token that is not an attribute is a value whose name
			// was stripped; prose has spaces.
			return true
		}
	}
	return false
}

// scrubEach applies re to text, counting every replacement.
func scrubEach(text string, re *regexp.Regexp, repl func([]string) string) (string, int) {
	return scrubEachWhere(text, re, repl, nil)
}

// scrubEachWhere applies re to text, counting every replacement, and skips the
// matches keep rejects. It rebuilds the string from match indices so a rule's
// leading context group (the character before a key name) survives: matching
// the isolated match text would drop it and glue the replacement onto the
// previous word. The predicate exists because Go's regexp has no lookaround,
// so a rule that must not touch identifier characters on either side of a
// candidate decides that here instead of consuming the neighbouring bytes.
func scrubEachWhere(text string, re *regexp.Regexp, repl func([]string) string, keep func(text string, start, end int) bool) (string, int) {
	matches := re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text, 0
	}
	var b strings.Builder
	last, n := 0, 0
	for _, m := range matches {
		if keep != nil && !keep(text, m[0], m[1]) {
			continue
		}
		groups := make([]string, len(m)/2)
		for i := 0; i < len(m); i += 2 {
			if m[i] >= 0 {
				groups[i/2] = text[m[i]:m[i+1]]
			}
		}
		r := repl(groups)
		b.WriteString(text[last:m[0]])
		b.WriteString(r)
		if r != text[m[0]:m[1]] {
			n++
		}
		last = m[1]
	}
	b.WriteString(text[last:])
	return b.String(), n
}

// redactValue replaces a captured value with the placeholder, keeping the
// surrounding quotes so a JSON or quoted key=value pair stays well-formed.
func redactValue(value string) string {
	if len(value) >= 2 {
		switch {
		case value[0] == '"' && value[len(value)-1] == '"':
			return `"` + scrubRedacted + `"`
		case value[0] == '\'' && value[len(value)-1] == '\'':
			return "'" + scrubRedacted + "'"
		}
	}
	return scrubRedacted
}

// ScrubSecrets redacts credential-shaped substrings and returns how many
// replacements were made. It is applied to every write to the knowledge base
// and the reflection pool, for agent, operator and engine callers alike: a
// secret must never become durable memory.
func ScrubSecrets(text string) (string, int) {
	if text == "" {
		return text, 0
	}
	total := 0
	apply := func(re *regexp.Regexp, repl func([]string) string) {
		var n int
		text, n = scrubEach(text, re, repl)
		total += n
	}
	whole := func([]string) string { return scrubRedacted }
	apply(privateKeyRE, whole)
	apply(jwtRE, whole)
	apply(awsKeyRE, whole)
	apply(urlUserRE, func(m []string) string { return m[1] + m[2] + ":" + scrubRedacted + "@" })
	apply(authHeaderRE, func(m []string) string { return m[1] + m[2] + redactValue(m[3]) })
	apply(bearerRE, func(m []string) string {
		// The token class includes ".", so a sentence-final scheme noun arrives
		// with its full stop attached.
		if schemeNouns[strings.ToLower(strings.TrimRight(m[2], ".,"))] {
			return m[0]
		}
		return m[1] + " " + scrubRedacted
	})
	apply(cookieRE, func(m []string) string {
		// A line that describes attributes ("lacks HttpOnly") holds no value
		// to redact; eating it loses the observation.
		if !cookieHoldsValue(m[3]) {
			return m[0]
		}
		return m[1] + m[2] + scrubRedacted
	})
	apply(secretKVRE, func(m []string) string { return m[1] + m[2] + m[3] + redactValue(m[4]) })
	apply(blobRE, func(m []string) string {
		if !secretBlob(m[0]) {
			return m[0]
		}
		return scrubRedacted
	})
	return text, total
}

// Generalisation patterns. IP literals are matched permissively and then
// validated with net.ParseIP, so a clock time such as 12:30:45 survives.
var (
	ipv4CandidateRE = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6CandidateRE = regexp.MustCompile(`[0-9A-Fa-f:]{2,}`)
	emailRE         = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// identByte reports whether b continues an identifier, so a candidate glued to
// one is code, not an address.
func identByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_'
}

// dottedByte reports whether text[i] continues a dotted number: a digit, or a
// dot that another digit follows. A sentence-final dot is punctuation.
func dottedByte(text string, i int) bool {
	if i < 0 || i >= len(text) {
		return false
	}
	if text[i] >= '0' && text[i] <= '9' {
		return true
	}
	return text[i] == '.' && i+1 < len(text) && text[i+1] >= '0' && text[i+1] <= '9'
}

// scrubIPLiterals generalises routable IPv4 and IPv6 literals. Loopback and
// unspecified addresses name no target, and "::" is C++ and PowerShell scope
// syntax as often as it is an address, so both survive.
func scrubIPLiterals(text string) (string, int) {
	total := 0
	text, n := scrubEachWhere(text, ipv6CandidateRE,
		func([]string) string { return scrubIP },
		func(text string, start, end int) bool {
			// "[IO.File]::" is a PowerShell type qualifier: a "::" glued to a
			// closing bracket is scope syntax, never an address.
			if start > 0 && (identByte(text[start-1]) || text[start-1] == ']') {
				return false
			}
			if end < len(text) && identByte(text[end]) {
				return false
			}
			cand := text[start:end]
			ip := net.ParseIP(cand)
			if ip == nil || ip.To4() != nil || ip.IsLoopback() || ip.IsUnspecified() {
				return false
			}
			return strings.ContainsAny(cand, "0123456789abcdefABCDEF")
		})
	total += n
	// A bare four-part version ("build 1.8.0.191") is indistinguishable from an
	// address and is generalised with it: "curl -v 10.0.0.5" must never keep
	// its target because a keyword came first. Longer and glued versions
	// ("1.8.0.191.2", "v1.8.0.191") are caught by the neighbour checks.
	text, n = scrubEachWhere(text, ipv4CandidateRE,
		func([]string) string { return scrubIP },
		func(text string, start, end int) bool {
			if start > 0 && (identByte(text[start-1]) || dottedByte(text, start-1)) {
				return false
			}
			if end < len(text) && (identByte(text[end]) || dottedByte(text, end)) {
				return false
			}
			ip := net.ParseIP(text[start:end])
			return ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified()
		})
	total += n
	return text, total
}

// ScrubTargetIdentifiers generalises target-specific strings: each identifier
// (case-insensitive, whole token, which also covers it as the suffix of a
// host such as api.example.com), then every IP literal and every email.
// Used when an entry leaves its task (promotion) or when an operator writes a
// company/global entry directly.
func ScrubTargetIdentifiers(text string, identifiers []string) (string, int) {
	total := 0
	for _, id := range identifiers {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		re := targetIdentifierRE(id)
		var n int
		text, n = scrubEach(text, re, func([]string) string { return scrubTarget })
		total += n
	}

	var n int
	text, n = scrubIPLiterals(text)
	total += n
	text, n = scrubEach(text, emailRE, func([]string) string { return scrubEmail })
	total += n
	return text, total
}

// targetIdentifierRESize bounds the compiled-regexp cache. The working set is
// one task's identifiers, so the bound is generous; clearing rather than
// evicting one key keeps the common case (the same identifiers for every field
// of every candidate) a map hit.
const targetIdentifierRESize = 4096

// targetIdentifierRE compiles the whole-token, case-insensitive matcher for one
// identifier, once. Promotion and generalisation run it over every field of
// every candidate, so compiling per call was the hot path.
var targetIdentifierREs sync.Map // map[string]*regexp.Regexp

func targetIdentifierRE(id string) *regexp.Regexp {
	if v, ok := targetIdentifierREs.Load(id); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(id) + `\b`)
	n := 0
	targetIdentifierREs.Range(func(any, any) bool { n++; return n < targetIdentifierRESize })
	if n >= targetIdentifierRESize {
		targetIdentifierREs.Clear()
	}
	targetIdentifierREs.Store(id, re)
	return re
}

// TaskScopeIdentifiers returns the target-identifying strings of one task: its
// included scope domains and network hosts plus the names and domains of the
// companies it is associated with (task_scope kind='company' and the task's
// own company_id). It feeds ScrubTargetIdentifiers when an entry is promoted
// or generalised.
func (d *DB) TaskScopeIdentifiers(ctx context.Context, taskID int64) ([]string, error) {
	if taskID <= 0 {
		return nil, nil
	}
	var exists bool
	if err := d.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, taskID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("task scope identifiers: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("task %d: %w", taskID, sql.ErrNoRows)
	}
	rows, err := d.QueryContext(ctx, `
WITH comp AS (
    SELECT company_id FROM task_scope
    WHERE task_id=$1 AND kind='company' AND company_id IS NOT NULL
    UNION
    SELECT company_id FROM tasks WHERE id=$1 AND company_id IS NOT NULL
)
SELECT ts.domain::text, ts.net::text, ''::text
FROM task_scope ts WHERE ts.task_id=$1 AND ts.effect='include'
UNION ALL
SELECT cs.domain::text, cs.net::text, ''::text
FROM company_scope cs WHERE cs.company_id IN (SELECT company_id FROM comp)
UNION ALL
SELECT ''::text, ''::text, c.name
FROM companies c WHERE c.id IN (SELECT company_id FROM comp)`, taskID)
	if err != nil {
		return nil, fmt.Errorf("task scope identifiers: %w", err)
	}
	defer rows.Close()

	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	for rows.Next() {
		var domain, netText, companyName sql.NullString
		if err := rows.Scan(&domain, &netText, &companyName); err != nil {
			return nil, fmt.Errorf("task scope identifiers: %w", err)
		}
		add(domain.String)
		if netText.Valid && netText.String != "" {
			add(netText.String)
			if host, _, ok := strings.Cut(netText.String, "/"); ok {
				add(host)
			}
		}
		add(companyName.String)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("task scope identifiers: %w", err)
	}
	return out, nil
}

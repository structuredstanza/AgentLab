package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"strings"
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
	bearerRE     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	cookieRE     = regexp.MustCompile(`(?i)\b(set-cookie|cookie)(\s*:\s*)[^\r\n]+`)
	secretKVRE   = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])(password|passwd|pwd|secret|token|api[_-]?key|apikey|auth)("?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&"']+)`)
	blobRE       = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)
)

// scrubEach applies re to text, counting every replacement. It rebuilds the
// string from match indices so a rule's leading context group (the character
// before a key name) survives: matching the isolated match text would drop it
// and glue the replacement onto the previous word.
func scrubEach(text string, re *regexp.Regexp, repl func([]string) string) (string, int) {
	matches := re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text, 0
	}
	var b strings.Builder
	last, n := 0, 0
	for _, m := range matches {
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
	apply(bearerRE, func(m []string) string { return m[1] + " " + scrubRedacted })
	apply(cookieRE, func(m []string) string { return m[1] + m[2] + scrubRedacted })
	apply(secretKVRE, func(m []string) string { return m[1] + m[2] + m[3] + redactValue(m[4]) })
	apply(blobRE, whole)
	return text, total
}

// Generalisation patterns. IP literals are matched permissively and then
// validated with net.ParseIP, so a clock time such as 12:30:45 survives.
var (
	ipv4CandidateRE = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6CandidateRE = regexp.MustCompile(`[0-9A-Fa-f:]{2,}`)
	emailRE         = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

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
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(id) + `\b`)
		var n int
		text, n = scrubEach(text, re, func([]string) string { return scrubTarget })
		total += n
	}

	text, n := scrubEach(text, ipv6CandidateRE, func(m []string) string {
		ip := net.ParseIP(m[0])
		if ip == nil || ip.To4() != nil {
			return m[0]
		}
		return scrubIP
	})
	total += n
	text, n = scrubEach(text, ipv4CandidateRE, func(m []string) string {
		ip := net.ParseIP(m[0])
		if ip == nil || ip.To4() == nil {
			return m[0]
		}
		return scrubIP
	})
	total += n
	text, n = scrubEach(text, emailRE, func([]string) string { return scrubEmail })
	total += n
	return text, total
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

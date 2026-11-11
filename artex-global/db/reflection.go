package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The reflection pool is the per-task learning record: what was noisy, what
// triggered defences, what to look for next, what worked. Reflections are
// strictly task-private - they never cross an engagement boundary - and they
// are data, not instructions, everywhere they are rendered.

// Reflection is one task reflection.
type Reflection struct {
	ID        int64           `json:"id"`
	TaskID    int64           `json:"task_id"`
	IntentID  int64           `json:"intent_id,omitempty"`
	Kind      string          `json:"kind"`   // opsec | noise | lookfor | learning | mistake
	Source    string          `json:"source"` // engine | worker | planner
	DedupeKey string          `json:"dedupe_key"`
	Summary   string          `json:"summary"`
	Detail    string          `json:"detail"`
	Signal    json.RawMessage `json:"signal"`
	CreatedAt time.Time       `json:"created_at"`
}

// ReflectionInput is one write. DedupeKey may be left empty for worker and
// planner writes: it is then derived from kind + the normalised summary, so
// re-submitting the same observation is idempotent.
type ReflectionInput struct {
	TaskID    int64
	IntentID  int64
	Kind      string
	Source    string
	DedupeKey string
	Summary   string
	Detail    string
	Signal    map[string]any
}

// reflectionDedupeKey is the stable identity of a free-form reflection.
func reflectionDedupeKey(kind, summary string) string {
	raw := kind + "|" + strings.ToLower(strings.Join(strings.Fields(summary), " "))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

const reflectionColumns = `id, task_id, COALESCE(intent_id,0), kind, source, dedupe_key,
	summary, detail, COALESCE(signal,'{}'::jsonb), created_at`

func scanReflection(sc interface{ Scan(dest ...any) error }) (Reflection, error) {
	var r Reflection
	var signal []byte
	err := sc.Scan(&r.ID, &r.TaskID, &r.IntentID, &r.Kind, &r.Source, &r.DedupeKey,
		&r.Summary, &r.Detail, &signal, &r.CreatedAt)
	r.Signal = json.RawMessage(signal)
	return r, err
}

// Signal bounds: a signal is a small JSON object of raw counts, never a place
// to store tool output verbatim. Every string inside it is scrubbed and capped,
// and the marshalled object is capped so a hostile tool result cannot inflate
// the row.
const (
	reflectionSignalMaxBytes = 2000
	reflectionSignalStrMax   = 200
	reflectionSignalMinRunes = 8
)

// signalKeySecret reports a signal key that names a credential by itself: a
// JSON pair splits "password=hunter2" into a key and a bare value, so the value
// must be redacted on the key's authority.
func signalKeySecret(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "password", "passwd", "pwd", "secret", "token",
		"api_key", "api-key", "apikey", "auth", "authorization",
		"proxy-authorization", "cookie", "set-cookie":
		return true
	}
	return false
}

// scrubSignalValue walks a decoded JSON value and scrubs every string, keys
// included: engine signals are built from tool summaries and results, which can
// contain credentials or target-controlled text.
func scrubSignalValue(v any) any {
	switch t := v.(type) {
	case string:
		s, _ := ScrubSecrets(t)
		return truncateRunes(s, reflectionSignalStrMax)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			key, _ := ScrubSecrets(k)
			key = truncateRunes(key, reflectionSignalStrMax)
			if signalKeySecret(key) {
				out[key] = scrubRedacted
				continue
			}
			out[key] = scrubSignalValue(val)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, val := range t {
			key, _ := ScrubSecrets(k)
			key = truncateRunes(key, reflectionSignalStrMax)
			if signalKeySecret(key) {
				out[key] = scrubRedacted
				continue
			}
			out[key] = scrubSignalValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = scrubSignalValue(t[i])
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i := range t {
			out[i] = scrubSignalValue(t[i])
		}
		return out
	default:
		return v
	}
}

// longestSignalString returns the longest string in a decoded JSON tree and a
// setter for its slot; set is nil when the tree holds no string.
func longestSignalString(v any) (string, func(string)) {
	switch t := v.(type) {
	case map[string]any:
		var best string
		var varSet func(string)
		for k, val := range t {
			s, set := longestSignalString(val)
			if set == nil {
				continue
			}
			if varSet == nil || len([]rune(s)) > len([]rune(best)) {
				best, varSet = s, func(ns string) { t[k] = ns }
			}
		}
		return best, varSet
	case []any:
		var best string
		var varSet func(string)
		for i, val := range t {
			s, set := longestSignalString(val)
			if set == nil {
				continue
			}
			if varSet == nil || len([]rune(s)) > len([]rune(best)) {
				best, varSet = s, func(ns string) { t[i] = ns }
			}
		}
		return best, varSet
	default:
		return "", nil
	}
}

// encodeSignal scrubs and bounds a signal map. The result is always valid JSON:
// when shrinking cannot bring the object under the byte cap, it degrades to a
// marker object instead of storing a truncated (broken) document.
func encodeSignal(sig map[string]any) ([]byte, error) {
	if sig == nil {
		return []byte("{}"), nil
	}
	v := scrubSignalValue(sig)
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	for len(b) > reflectionSignalMaxBytes {
		s, set := longestSignalString(v)
		if set == nil || len([]rune(s)) <= reflectionSignalMinRunes {
			break
		}
		r := []rune(s)
		set(string(r[:len(r)/2]))
		if b, err = json.Marshal(v); err != nil {
			return nil, err
		}
	}
	if len(b) > reflectionSignalMaxBytes {
		b = []byte(`{"truncated":true}`)
	}
	return b, nil
}

// AddReflection writes one reflection, scrubbing secrets, generalising the
// task's own identifiers, and enforcing the per-task cap. It is idempotent on
// (task, dedupe_key): created reports whether this call inserted the row.
func (d *DB) AddReflection(ctx context.Context, in ReflectionInput) (Reflection, bool, error) {
	if in.TaskID <= 0 {
		return Reflection{}, false, fmt.Errorf("reflection needs a task id: %w", ErrMemoryInvalid)
	}
	if !reflectionKindSet[in.Kind] {
		return Reflection{}, false, fmt.Errorf("reflection kind %q: %w", in.Kind, ErrMemoryInvalid)
	}
	if in.Source == "" || !reflectionSourceSet[in.Source] {
		return Reflection{}, false, fmt.Errorf("reflection source %q: %w", in.Source, ErrMemoryInvalid)
	}
	summary := memoryLine(in.Summary, reflectionSumMax)
	if summary == "" {
		return Reflection{}, false, fmt.Errorf("empty reflection summary: %w", ErrMemoryInvalid)
	}
	detail := memoryBody(in.Detail, reflectionDetMax)
	memoryScrub(&summary, &detail)
	// A reflection is read on later targets, so the origin task's identifiers
	// are generalised at write time too: the reflection keeps the condition and
	// the mechanism, the exploration graph keeps the concrete fact. Running it
	// before the dedupe key is derived also collapses two observations that
	// differ only in the host they name.
	ids, err := d.TaskScopeIdentifiers(ctx, in.TaskID)
	if err != nil {
		return Reflection{}, false, err
	}
	summary, _ = ScrubTargetIdentifiers(summary, ids)
	detail, _ = ScrubTargetIdentifiers(detail, ids)
	// The key is derived AFTER scrubbing so two observations that differ only
	// in the secret they quote ("token=abc" vs "token=xyz") collapse into one.
	key := strings.TrimSpace(in.DedupeKey)
	if key == "" {
		key = reflectionDedupeKey(in.Kind, summary)
	}

	signal, err := encodeSignal(in.Signal)
	if err != nil {
		return Reflection{}, false, fmt.Errorf("reflection signal: %w", err)
	}

	// An idempotent re-submit returns the existing row without consuming a cap
	// slot: only genuinely new reflections are bounded.
	existing := d.QueryRowContext(ctx,
		`SELECT `+reflectionColumns+` FROM task_reflections WHERE task_id=$1 AND dedupe_key=$2`,
		in.TaskID, key)
	if r, err := scanReflection(existing); err == nil {
		return r, false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Reflection{}, false, fmt.Errorf("add reflection: %w", err)
	}

	// shortcut: the cap is advisory under concurrency (check-then-insert);
	// per-task volume is low and one extra row is harmless.
	var count int
	if err := d.QueryRowContext(ctx,
		`SELECT count(*) FROM task_reflections WHERE task_id=$1`, in.TaskID).Scan(&count); err != nil {
		return Reflection{}, false, fmt.Errorf("count reflections: %w", err)
	}
	if count >= MaxReflectionsPerTask {
		return Reflection{}, false, ErrMemoryCapReached
	}

	row := d.QueryRowContext(ctx, `
INSERT INTO task_reflections(task_id,intent_id,kind,source,dedupe_key,summary,detail,signal)
VALUES($1,NULLIF($2,0),$3,$4,$5,$6,$7,$8)
ON CONFLICT (task_id,dedupe_key) DO NOTHING
RETURNING `+reflectionColumns,
		in.TaskID, in.IntentID, in.Kind, in.Source, key, summary, detail, signal)
	r, err := scanReflection(row)
	if err == nil {
		return r, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Reflection{}, false, fmt.Errorf("add reflection: %w", err)
	}
	existing = d.QueryRowContext(ctx,
		`SELECT `+reflectionColumns+` FROM task_reflections WHERE task_id=$1 AND dedupe_key=$2`,
		in.TaskID, key)
	r, err = scanReflection(existing)
	if err != nil {
		return Reflection{}, false, fmt.Errorf("add reflection: %w", err)
	}
	return r, false, nil
}

// ListReflections returns the task's newest reflections, optionally filtered
// by kind. limit<=0 defaults to 6 and is capped at 50.
func (d *DB) ListReflections(ctx context.Context, taskID int64, kinds []string, limit int) ([]Reflection, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("list reflections needs a task id: %w", ErrMemoryInvalid)
	}
	if limit <= 0 {
		limit = 6
	}
	if limit > 50 {
		limit = 50
	}
	if kinds == nil {
		kinds = []string{}
	}
	rows, err := d.QueryContext(ctx, `
SELECT `+reflectionColumns+`
FROM task_reflections
WHERE task_id=$1 AND (cardinality($2::text[]) = 0 OR kind = ANY($2::text[]))
ORDER BY created_at DESC, id DESC
LIMIT $3`, taskID, kinds, limit)
	if err != nil {
		return nil, fmt.Errorf("list reflections: %w", err)
	}
	defer rows.Close()
	out := []Reflection{}
	for rows.Next() {
		r, err := scanReflection(rows)
		if err != nil {
			return nil, fmt.Errorf("list reflections: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list reflections: %w", err)
	}
	return out, nil
}

// ReflectionFilter selects reflections for the curation surface. TaskID 0
// means every task: curation is an owner view, so no visibility rule applies
// here (an agent still reads only its own task through ListReflections).
type ReflectionFilter struct {
	TaskID int64
	Kinds  []string
	Source string
	Query  string
	Since  *time.Time
	Limit  int
	Offset int
}

// ReflectionTaskCount is one row of the per-task breakdown.
type ReflectionTaskCount struct {
	TaskID int64 `json:"task_id"`
	Count  int   `json:"count"`
}

// ReflectionStats is the pool's shape for the curation header.
type ReflectionStats struct {
	Total    int                   `json:"total"`
	ByKind   map[string]int        `json:"by_kind"`
	BySource map[string]int        `json:"by_source"`
	ByTask   []ReflectionTaskCount `json:"by_task"`
}

// reflectionWhere builds the shared WHERE clause so the page and its total
// count can never disagree.
func (d *DB) reflectionWhere(f ReflectionFilter, tsquery string) (string, []any) {
	args := []any{}
	where := []string{}
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.TaskID > 0 {
		add(`task_id = $%d`, f.TaskID)
	}
	if len(f.Kinds) > 0 {
		add(`kind = ANY($%d::text[])`, f.Kinds)
	}
	if f.Source != "" {
		add(`source = $%d`, f.Source)
	}
	if f.Since != nil {
		add(`created_at >= $%d`, *f.Since)
	}
	if tsquery != "" {
		add(`tsv @@ websearch_to_tsquery('english', $%d)`, tsquery)
	}
	if len(where) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// ListReflectionsPage is the cross-task curation query: the same filters the
// operator sees, with a stable newest-first order, a page, and the unpaged
// total. The query reuses MemorySearchTerms, so reflection search and
// knowledge search agree on what a word means.
func (d *DB) ListReflectionsPage(ctx context.Context, f ReflectionFilter) ([]Reflection, int, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	tsquery := ""
	if q := strings.TrimSpace(f.Query); q != "" {
		tsquery = MemorySearchTerms(q)
	}
	whereSQL, args := d.reflectionWhere(f, tsquery)
	var total int
	if err := d.QueryRowContext(ctx,
		`SELECT count(*) FROM task_reflections`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count reflections: %w", err)
	}
	args = append(args, limit, offset)
	rows, err := d.QueryContext(ctx, `
SELECT `+reflectionColumns+`
FROM task_reflections`+whereSQL+fmt.Sprintf(`
ORDER BY created_at DESC, id DESC
LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list reflections page: %w", err)
	}
	defer rows.Close()
	out := []Reflection{}
	for rows.Next() {
		r, err := scanReflection(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("list reflections page: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list reflections page: %w", err)
	}
	return out, total, nil
}

// GetReflection returns one reflection; sql.ErrNoRows when it does not exist.
func (d *DB) GetReflection(ctx context.Context, id int64) (Reflection, error) {
	row := d.QueryRowContext(ctx, `SELECT `+reflectionColumns+` FROM task_reflections WHERE id=$1`, id)
	r, err := scanReflection(row)
	if err != nil {
		return Reflection{}, fmt.Errorf("reflection %d: %w", id, err)
	}
	return r, nil
}

// UpdateReflection patches summary and detail, and only those: kind, source,
// task and signal are write-time facts, not operator-editable text. The edited
// text runs the same scrub and task-identifier generalisation as
// AddReflection, so an edit cannot reintroduce a secret or a target name.
// DedupeKey is deliberately left alone: it records the row's write-time
// identity, so an edit can never collide with a sibling observation.
func (d *DB) UpdateReflection(ctx context.Context, id int64, summary, detail *string) (Reflection, error) {
	cur, err := d.GetReflection(ctx, id)
	if err != nil {
		return Reflection{}, err
	}
	if summary != nil {
		cur.Summary = memoryLine(*summary, reflectionSumMax)
	}
	if detail != nil {
		cur.Detail = memoryBody(*detail, reflectionDetMax)
	}
	if cur.Summary == "" {
		return Reflection{}, fmt.Errorf("empty reflection summary: %w", ErrMemoryInvalid)
	}
	memoryScrub(&cur.Summary, &cur.Detail)
	ids, err := d.TaskScopeIdentifiers(ctx, cur.TaskID)
	if err != nil {
		return Reflection{}, err
	}
	cur.Summary, _ = ScrubTargetIdentifiers(cur.Summary, ids)
	cur.Detail, _ = ScrubTargetIdentifiers(cur.Detail, ids)
	row := d.QueryRowContext(ctx, `
UPDATE task_reflections SET summary=$2, detail=$3
WHERE id=$1
RETURNING `+reflectionColumns, id, cur.Summary, cur.Detail)
	r, err := scanReflection(row)
	if err != nil {
		return Reflection{}, fmt.Errorf("update reflection %d: %w", id, err)
	}
	return r, nil
}

// DeleteReflection removes one row; sql.ErrNoRows when it does not exist.
func (d *DB) DeleteReflection(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM task_reflections WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("delete reflection %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete reflection %d: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("reflection %d: %w", id, sql.ErrNoRows)
	}
	return nil
}

// ReflectionStats counts the pool by kind, source and task, so the curation
// view can show what is in it without paging through it.
func (d *DB) ReflectionStats(ctx context.Context) (ReflectionStats, error) {
	out := ReflectionStats{
		ByKind:   map[string]int{},
		BySource: map[string]int{},
		ByTask:   []ReflectionTaskCount{},
	}
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM task_reflections`).Scan(&out.Total); err != nil {
		return ReflectionStats{}, fmt.Errorf("count reflections: %w", err)
	}
	for _, g := range []struct {
		col string
		dst map[string]int
	}{
		{"kind", out.ByKind},
		{"source", out.BySource},
	} {
		rows, err := d.QueryContext(ctx,
			`SELECT `+g.col+`, count(*) FROM task_reflections GROUP BY `+g.col)
		if err != nil {
			return ReflectionStats{}, fmt.Errorf("reflection stats by %s: %w", g.col, err)
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return ReflectionStats{}, fmt.Errorf("reflection stats by %s: %w", g.col, err)
			}
			g.dst[k] = n
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return ReflectionStats{}, fmt.Errorf("reflection stats by %s: %w", g.col, err)
		}
		rows.Close()
	}
	rows, err := d.QueryContext(ctx, `
SELECT task_id, count(*) FROM task_reflections
GROUP BY task_id
ORDER BY count(*) DESC, task_id`)
	if err != nil {
		return ReflectionStats{}, fmt.Errorf("reflection stats by task: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row ReflectionTaskCount
		if err := rows.Scan(&row.TaskID, &row.Count); err != nil {
			return ReflectionStats{}, fmt.Errorf("reflection stats by task: %w", err)
		}
		out.ByTask = append(out.ByTask, row)
	}
	if err := rows.Err(); err != nil {
		return ReflectionStats{}, fmt.Errorf("reflection stats by task: %w", err)
	}
	return out, nil
}

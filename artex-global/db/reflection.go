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

// AddReflection writes one reflection, scrubbing secrets and enforcing the
// per-task cap. It is idempotent on (task, dedupe_key): created reports
// whether this call inserted the row.
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

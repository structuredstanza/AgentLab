package db

import (
	"context"
	"fmt"
	"time"
)

// The knowledge usage ledger records which entries an agent actually read back:
// the start-of-task block, a per-round block, a recall call, or the curation
// chat. Without it, "refine the memory" is guesswork, because an entry nothing
// ever retrieves looks exactly like a load-bearing one. Writes are telemetry -
// a caller logs a failure and carries on; a lost row never fails a prompt.

// knowledgeSurfaces are the read paths named by the table's CHECK constraint.
var knowledgeSurfaces = map[string]bool{
	"task_start": true, "round": true, "recall": true, "chat": true,
}

// KnowledgeUsageRecord is one read of one entry.
type KnowledgeUsageRecord struct {
	TaskID  int64     `json:"task_id"`
	Surface string    `json:"surface"`
	ShownAt time.Time `json:"shown_at"`
}

// KnowledgeUsageSummary is one entry's read history: the total hit count, the
// most recent read (zero when never read) and the newest rows.
type KnowledgeUsageSummary struct {
	Hits     int                    `json:"hits"`
	LastUsed time.Time              `json:"last_used"`
	Usage    []KnowledgeUsageRecord `json:"usage"`
}

// RecordKnowledgeUsage logs that these entries were shown on one read path.
// One statement for the whole batch, so the hot path pays one round trip; an
// empty set pays none. taskID 0 means the read had no task (the curation chat)
// and is stored as NULL, which the FK's ON DELETE SET NULL produces too.
func (d *DB) RecordKnowledgeUsage(ctx context.Context, taskID int64, surface string, ids []int64) error {
	if !knowledgeSurfaces[surface] {
		return fmt.Errorf("knowledge usage surface %q: %w", surface, ErrMemoryInvalid)
	}
	clean := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			clean = append(clean, id)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	if _, err := d.ExecContext(ctx, `
		INSERT INTO knowledge_usage(knowledge_id, task_id, surface)
		SELECT id, NULLIF($2::bigint, 0), $3 FROM unnest($1::bigint[]) AS id`,
		clean, taskID, surface); err != nil {
		return fmt.Errorf("record knowledge usage: %w", err)
	}
	return nil
}

// GetKnowledgeUsage returns one entry's newest reads (limit<=0 defaults to 50
// and is capped at 200) plus its total hit count and last read, in one query:
// the window count is taken before LIMIT, so it sees every row.
func (d *DB) GetKnowledgeUsage(ctx context.Context, id int64, limit int) (KnowledgeUsageSummary, error) {
	if id <= 0 {
		return KnowledgeUsageSummary{}, fmt.Errorf("knowledge usage needs an entry id: %w", ErrMemoryInvalid)
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `
		SELECT COALESCE(task_id,0), surface, shown_at, count(*) OVER ()
		FROM knowledge_usage WHERE knowledge_id=$1
		ORDER BY shown_at DESC, id DESC LIMIT $2`, id, limit)
	if err != nil {
		return KnowledgeUsageSummary{}, fmt.Errorf("get knowledge usage %d: %w", id, err)
	}
	defer rows.Close()
	out := KnowledgeUsageSummary{Usage: make([]KnowledgeUsageRecord, 0, limit)}
	for rows.Next() {
		var r KnowledgeUsageRecord
		if err := rows.Scan(&r.TaskID, &r.Surface, &r.ShownAt, &out.Hits); err != nil {
			return KnowledgeUsageSummary{}, fmt.Errorf("scan knowledge usage %d: %w", id, err)
		}
		if out.LastUsed.IsZero() {
			out.LastUsed = r.ShownAt
		}
		out.Usage = append(out.Usage, r)
	}
	return out, rows.Err()
}

// KnowledgeUsageHits counts reads for many entries in one query, so a list
// view does not issue one count per row. Ids that were never read are absent
// from the map.
func (d *DB) KnowledgeUsageHits(ctx context.Context, ids []int64) (map[int64]int, error) {
	out := make(map[int64]int, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.QueryContext(ctx, `
		SELECT knowledge_id, count(*)::int FROM knowledge_usage
		WHERE knowledge_id = ANY($1::bigint[]) GROUP BY knowledge_id`, ids)
	if err != nil {
		return nil, fmt.Errorf("knowledge usage hits: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("scan knowledge usage hits: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

package db

import (
	"context"
	"fmt"
)

// The promotion queue: a finished task's task-private candidates ordered by the
// strength of the evidence behind them, so the owner reviews a task at a time
// instead of an entry at a time. Nothing here changes a status - promotion
// stays an owner action (RSI.md rule 4).

// KnowledgeNearestAdopted is the adopted entry closest to a candidate by title,
// so the owner sees a likely duplicate before promoting one more.
type KnowledgeNearestAdopted struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
}

// KnowledgeReviewItem is one candidate in the queue: the entry itself, the
// intent that produced it and what that intent yielded, how many identifiers a
// promotion would generalise, and the nearest adopted entry.
type KnowledgeReviewItem struct {
	Entry          KnowledgeEntry           `json:"entry"`
	OriginIntentID int64                    `json:"origin_intent_id"`
	OriginOutcome  string                   `json:"origin_outcome"` // finding | fact | none | unknown
	Redactions     int                      `json:"redactions"`
	NearestAdopted *KnowledgeNearestAdopted `json:"nearest_adopted"`
}

// KnowledgeReview lists one task's promotion queue: its task-scope candidates,
// strongest evidence first - a confirmed finding (confirmed, resolved or
// fixed), then any fact or unrejected finding, then an intent that yielded
// nothing (a rejected finding alone counts as nothing) - and newest first
// inside each group. The outcome comes from the origin intent's yields edges;
// origin_intent_id 0, or an intent that belongs to another task's exploration,
// reads as unknown.
func (d *DB) KnowledgeReview(ctx context.Context, taskID int64) ([]KnowledgeReviewItem, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("review knowledge needs a task id: %w", ErrMemoryInvalid)
	}
	rows, err := d.QueryContext(ctx, `
WITH outcome AS (
    SELECT k.id AS entry_id,
      CASE
        WHEN n.id IS NULL THEN 'unknown'
        WHEN EXISTS (SELECT 1 FROM exploration_edges e
                     JOIN exploration_nodes f ON f.id=e.dst_id AND f.exploration_id=e.exploration_id
                     JOIN findings fi ON fi.node_id=f.id
                     WHERE e.exploration_id=n.exploration_id AND e.src_id=n.id AND e.rel=$2
                       AND f.kind=$3 AND fi.status IN ('confirmed','resolved','fixed')) THEN 'finding'
        WHEN EXISTS (SELECT 1 FROM exploration_edges e
                     JOIN exploration_nodes f ON f.id=e.dst_id AND f.exploration_id=e.exploration_id
                     LEFT JOIN findings fi ON fi.node_id=f.id
                     WHERE e.exploration_id=n.exploration_id AND e.src_id=n.id AND e.rel=$2
                       AND (f.kind=$4
                            OR (f.kind=$3 AND COALESCE(fi.status,'') NOT IN
                                ('false_positive','duplicate','ignored','risk_accepted')))) THEN 'fact'
        ELSE 'none'
      END AS outcome
    FROM knowledge_entries k
    LEFT JOIN tasks t ON t.id=k.task_id
    LEFT JOIN exploration_nodes n
      ON n.id=k.origin_intent_id AND n.exploration_id=t.exploration_id AND n.kind=$5
    WHERE k.scope='task' AND k.task_id=$1 AND k.status='candidate'
)
SELECT `+knowledgeColumns+`, o.outcome
FROM outcome o JOIN knowledge_entries k ON k.id=o.entry_id
ORDER BY CASE o.outcome WHEN 'finding' THEN 0 WHEN 'fact' THEN 1 WHEN 'none' THEN 2 ELSE 3 END,
         k.created_at DESC, k.id DESC`,
		taskID, RelYields, KindFinding, KindFact, KindIntent)
	if err != nil {
		return nil, fmt.Errorf("review knowledge: %w", err)
	}
	items := []KnowledgeReviewItem{}
	defer rows.Close()
	for rows.Next() {
		var it KnowledgeReviewItem
		it.Entry, err = scanKnowledge(rows, &it.OriginOutcome)
		if err != nil {
			return nil, fmt.Errorf("review knowledge: %w", err)
		}
		it.OriginIntentID = it.Entry.OriginIntentID
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("review knowledge: %w", err)
	}
	rows.Close()
	if len(items) == 0 {
		return items, nil
	}
	if err := d.attachNearestAdopted(ctx, taskID, items); err != nil {
		return nil, err
	}
	// One identifier lookup and one compile per origin task, not per entry: a
	// task's candidates nearly always share one origin.
	scrubbers := map[int64]identifierScrubber{}
	for i := range items {
		origin := items[i].Entry.OriginTaskID
		if origin == 0 {
			origin = items[i].Entry.TaskID
		}
		scrubber, ok := scrubbers[origin]
		if !ok {
			ids, err := d.TaskScopeIdentifiers(ctx, origin)
			if err != nil {
				return nil, err
			}
			scrubber = newIdentifierScrubber(ids)
			scrubbers[origin] = scrubber
		}
		_, _, _, items[i].Redactions = promotionScrub(items[i].Entry, scrubber)
	}
	return items, nil
}

// KnowledgeReviewCounts returns how many task-scope candidates each task has
// waiting, keyed by task id. Tasks with none are absent. One grouped query and
// no parameters: the tasks list needs the number for every row it renders, and
// the full review endpoint is too heavy to call per row.
func (d *DB) KnowledgeReviewCounts(ctx context.Context) (map[int64]int, error) {
	rows, err := d.QueryContext(ctx, `
SELECT task_id, count(*) FROM knowledge_entries
WHERE scope='task' AND status='candidate'
GROUP BY task_id`)
	if err != nil {
		return nil, fmt.Errorf("review knowledge counts: %w", err)
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var taskID int64
		var n int
		if err := rows.Scan(&taskID, &n); err != nil {
			return nil, fmt.Errorf("review knowledge counts: %w", err)
		}
		out[taskID] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("review knowledge counts: %w", err)
	}
	return out, nil
}

// attachNearestAdopted fills NearestAdopted for every item in one query: the
// best full-text match among the adopted entries the task can see from outside
// itself (global, environment, its companies), so a duplicate shows up before
// promotion rather than after it.
func (d *DB) attachNearestAdopted(ctx context.Context, taskID int64, items []KnowledgeReviewItem) error {
	ids := make([]int64, 0, len(items))
	queries := make([]string, 0, len(items))
	for _, it := range items {
		q := MemorySearchTerms(it.Entry.Title)
		if q == "" {
			continue
		}
		ids = append(ids, it.Entry.ID)
		queries = append(queries, q)
	}
	if len(ids) == 0 {
		return nil
	}
	companies, err := d.taskCompanyIDs(ctx, taskID)
	if err != nil {
		return err
	}
	rows, err := d.QueryContext(ctx, `
SELECT c.id, a.id, a.title
FROM unnest($2::bigint[], $3::text[]) AS c(id, q)
JOIN LATERAL (
    SELECT a.id, a.title
    FROM knowledge_entries a
    WHERE `+knowledgeVisibility("a.", 1, 0)+`
      AND a.tsv @@ websearch_to_tsquery('english', c.q)
    ORDER BY ts_rank_cd(a.tsv, websearch_to_tsquery('english', c.q)) DESC, a.id DESC
    LIMIT 1
) a ON true`, companies, ids, queries)
	if err != nil {
		return fmt.Errorf("review knowledge nearest adopted: %w", err)
	}
	defer rows.Close()
	byEntry := map[int64]int{}
	for i, it := range items {
		byEntry[it.Entry.ID] = i
	}
	for rows.Next() {
		var entryID int64
		var near KnowledgeNearestAdopted
		if err := rows.Scan(&entryID, &near.ID, &near.Title); err != nil {
			return fmt.Errorf("review knowledge nearest adopted: %w", err)
		}
		if i, ok := byEntry[entryID]; ok {
			items[i].NearestAdopted = &near
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("review knowledge nearest adopted: %w", err)
	}
	return nil
}

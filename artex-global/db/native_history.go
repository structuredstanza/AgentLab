package db

import (
	"context"
	"encoding/json"
	"fmt"
)

// NativeHistoryMetadata returns only the latest local routing records per
// identity, not model text, tool results, credentials, or a second transcript.
func (d *DB) NativeHistoryMetadata(ctx context.Context, explorationID, conversationID int64, sessionID string) ([]json.RawMessage, error) {
	var source string
	var scope int64
	if explorationID > 0 && conversationID == 0 {
		source = `SELECT id, metadata FROM activity WHERE exploration_id=$1 AND kind='llm_native'`
		scope = explorationID
	} else if conversationID > 0 && explorationID == 0 {
		source = `SELECT id, detail::jsonb AS metadata FROM conversation_activities WHERE conversation_id=$1 AND kind='llm_native'`
		scope = conversationID
	} else {
		return nil, fmt.Errorf("invalid native history activity scope")
	}
	rows, err := d.QueryContext(ctx, `
WITH records AS (`+source+`), latest AS (
 SELECT DISTINCT ON (metadata->>'record', metadata->'identity'->>'profile_id', metadata->'identity'->>'provider', metadata->'identity'->>'model', metadata->'identity'->>'reasoning_effort', metadata->>'thinking_type') id, metadata
 FROM records WHERE metadata->>'session_id'=$2
 ORDER BY metadata->>'record', metadata->'identity'->>'profile_id', metadata->'identity'->>'provider', metadata->'identity'->>'model', metadata->'identity'->>'reasoning_effort', metadata->>'thinking_type', id DESC
)
SELECT metadata FROM latest ORDER BY id`, scope, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

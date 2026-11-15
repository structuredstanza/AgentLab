package db

import (
	"context"
	"fmt"
	"time"
)

// ToolManifestRow is one stored tool manifest. The TOML is kept as written so
// the editor shows the operator's own text, not a re-encoding of it.
type ToolManifestRow struct {
	ID        string
	TOML      string
	UpdatedAt time.Time
}

// ListToolManifests returns every stored manifest in id order.
func (d *DB) ListToolManifests(ctx context.Context) ([]ToolManifestRow, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, toml, updated_at FROM tool_manifests ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tool manifests: %w", err)
	}
	defer rows.Close()
	out := []ToolManifestRow{}
	for rows.Next() {
		var r ToolManifestRow
		if err := rows.Scan(&r.ID, &r.TOML, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list tool manifests: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertToolManifest stores the manifest under id, replacing an earlier version.
func (d *DB) UpsertToolManifest(ctx context.Context, id, toml string) error {
	if _, err := d.ExecContext(ctx, `INSERT INTO tool_manifests(id, toml) VALUES ($1,$2)
ON CONFLICT (id) DO UPDATE SET toml = EXCLUDED.toml, updated_at = now()`, id, toml); err != nil {
		return fmt.Errorf("upsert tool manifest: %w", err)
	}
	return nil
}

// DeleteToolManifest removes a stored manifest and reports whether a row existed.
func (d *DB) DeleteToolManifest(ctx context.Context, id string) (bool, error) {
	res, err := d.ExecContext(ctx, `DELETE FROM tool_manifests WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete tool manifest: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

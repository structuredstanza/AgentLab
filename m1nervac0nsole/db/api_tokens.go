package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrAPITokenInvalid is the single failure for a token that is unknown, expired
// or revoked: one error for all three keeps a caller from probing which state a
// token is in.
var ErrAPITokenInvalid = errors.New("api token is invalid")

// ErrAPITokenNotFound is returned by RevokeAPIToken for an id that is missing or
// already revoked, so the API can answer 404 without hiding a database failure.
var ErrAPITokenNotFound = errors.New("api token not found")

// APIToken is one scoped read-only credential. The plaintext is never stored and
// never returned again after CreateAPIToken; only its sha256 hash is kept.
type APIToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	TaskID     int64      `json:"task_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// hashAPIToken is the stored form of a token: sha256 hex. The plaintext carries
// 256 random bits, so a fast hash is enough: there is no guessable password to
// slow down.
func hashAPIToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken mints a token bound to one task and returns the plaintext (the
// only time it exists in readable form) plus the stored row.
func (d *DB) CreateAPIToken(ctx context.Context, name string, taskID int64, ttl time.Duration) (string, *APIToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("api token: random: %w", err)
	}
	plaintext := "mvn_" + base64.RawURLEncoding.EncodeToString(raw)
	row := &APIToken{Name: name, TaskID: taskID, ExpiresAt: time.Now().Add(ttl)}
	err := d.QueryRowContext(ctx, `INSERT INTO api_tokens(name, task_id, token_hash, expires_at)
VALUES ($1,$2,$3,$4) RETURNING id, created_at`, name, taskID, hashAPIToken(plaintext), row.ExpiresAt).
		Scan(&row.ID, &row.CreatedAt)
	if err != nil {
		return "", nil, fmt.Errorf("create api token: %w", err)
	}
	return plaintext, row, nil
}

// ListAPITokens returns every token, newest first, without the hash.
func (d *DB) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, name, task_id, created_at, expires_at, revoked_at, last_used_at
FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.TaskID, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt); err != nil {
			return nil, fmt.Errorf("list api tokens: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token unusable. Revoking twice is not an error for the
// caller to distinguish, but a missing id is reported so the API can 404.
func (d *DB) RevokeAPIToken(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("api token %d: %w", id, ErrAPITokenNotFound)
	}
	return nil
}

// AuthenticateAPIToken resolves a plaintext token to its row and stamps
// last_used_at. Unknown, expired and revoked tokens all yield ErrAPITokenInvalid.
func (d *DB) AuthenticateAPIToken(ctx context.Context, plaintext string) (*APIToken, error) {
	if plaintext == "" {
		return nil, ErrAPITokenInvalid
	}
	var t APIToken
	err := d.QueryRowContext(ctx, `SELECT id, name, task_id, created_at, expires_at, revoked_at, last_used_at
FROM api_tokens WHERE token_hash=$1`, hashAPIToken(plaintext)).
		Scan(&t.ID, &t.Name, &t.TaskID, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAPITokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("look up api token: %w", err)
	}
	if t.RevokedAt != nil || !t.ExpiresAt.After(time.Now()) {
		return nil, ErrAPITokenInvalid
	}
	if _, err := d.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=now() WHERE id=$1`, t.ID); err != nil {
		return nil, fmt.Errorf("touch api token: %w", err)
	}
	now := time.Now()
	t.LastUsedAt = &now
	return &t, nil
}

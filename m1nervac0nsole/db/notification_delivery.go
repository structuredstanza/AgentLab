package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// This file handles claiming delivery tasks and their state transitions.
//
// Claiming uses a "lease" rather than a long transaction: the row is set to sending and next_attempt_at is pushed into the future as
// the lease expiry time. The transaction is committed before the network delivery is performed, so no database lock is held during delivery——
// A network request may take several seconds (the client timeout is 15 seconds), and holding the row lock for that long would starve other writes to the same database.
//
// The trade-off is that if the process crashes during delivery, the row is left in sending. This is **self-healing**: once the lease expires
// next_attempt_at falls into the past, and the next claim round will pick up the same row again (see the claim condition
// state IN ('pending','sending')). The retry count is already incremented by 1 at the time of claiming, so a crash does not cause
// unbounded retries: after the MaxNotifyAttempts chances are used up, the row moves to failed for manual handling.

// MaxNotifyAttempts is the maximum number of attempts for a single delivery, including the first one.
// It is defined here rather than in the delivery engine because it is a policy of the state machine itself; the engine is merely the executor.
const MaxNotifyAttempts = 3

// MaxDigestBatchSize is the maximum number of deliveries that a single digest batch merges at once.
//
// The reason it exists is resources: within one summary cycle, a scan can surface tens of thousands of vulnerabilities (entirely possible — a single full scan
// can do it), and without an upper bound, the claim would read all rows into memory and render them into one extremely long message,
// which the channel's length limit would then truncate for the most part — wasting memory and **silently losing** the vulnerabilities that were cut off.
// With an upper bound, the excess stays in the database as the next batch and is naturally sent in the following cycle, so nothing is lost.
//
// The basis for 500: it is the order of magnitude that, once rendered into a message, still leaves "readable content" within Telegram's 4096-charyte limit;
// any larger would only move the truncation to a later position.
const MaxDigestBatchSize = 500

// NotificationDelivery is a single delivery task, containing the channel configuration and event snapshot needed for rendering.
type NotificationDelivery struct {
	ID            int64           `json:"id"`
	EventID       int64           `json:"event_id"`
	ChannelID     int64           `json:"channel_id"`
	State         string          `json:"state"`
	Attempts      int             `json:"attempts"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
	LastError     string          `json:"last_error"`
	BatchID       *int64          `json:"batch_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	SentAt        *time.Time      `json:"sent_at,omitempty"`
	Snapshot      json.RawMessage `json:"snapshot,omitempty"`
	// Render context loaded via joins; not included in JSON (the server layer assembles the DTO).
	Channel *NotificationChannel `json:"-"`
	// FindingID/EventKind are carried over from the event so the history list can jump straight to the vulnerability details.
	FindingID int64  `json:"finding_id,string"`
	EventKind string `json:"event_kind"`
	// ChannelName/ChannelKind are redundant fields for list display, saving the frontend a second query.
	ChannelName string `json:"channel_name"`
	ChannelKind string `json:"channel_kind"`
}

const notificationDeliveryCols = `d.id, d.event_id, d.channel_id, d.state, d.attempts, d.next_attempt_at,
       d.last_error, d.batch_id, d.created_at, d.sent_at`

// joinedDeliveryQuery is the unified read shape for a delivery row: the delivery, the event snapshot, and the channel config.
// All three are required to render a message; querying them separately would mean three round trips.
const joinedDeliveryQuery = `SELECT ` + notificationDeliveryCols + `,
       e.snapshot, e.kind, e.finding_id,
       c.id, c.name, c.kind, c.enabled, c.config, c.mode, c.filter, c.rate_per_min
FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id
JOIN notification_channels c ON c.id = d.channel_id`

func scanNotificationDelivery(sc interface{ Scan(...any) error }) (*NotificationDelivery, error) {
	var (
		dl        NotificationDelivery
		lastErr   sql.NullString
		batchID   sql.NullInt64
		sentAt    sql.NullTime
		snapshot  []byte
		eventKind string
		channel   NotificationChannel
		chEnabled bool
	)
	if err := sc.Scan(&dl.ID, &dl.EventID, &dl.ChannelID, &dl.State, &dl.Attempts, &dl.NextAttemptAt,
		&lastErr, &batchID, &dl.CreatedAt, &sentAt,
		&snapshot, &eventKind, &dl.FindingID,
		&channel.ID, &channel.Name, &channel.Kind, &chEnabled, &channel.Config, &channel.Mode, &channel.Filter, &channel.RatePerMin); err != nil {
		return nil, err
	}
	dl.LastError = lastErr.String
	if batchID.Valid {
		dl.BatchID = &batchID.Int64
	}
	if sentAt.Valid {
		dl.SentAt = &sentAt.Time
	}
	dl.Snapshot = json.RawMessage(snapshot)
	dl.EventKind = eventKind
	dl.ChannelName = channel.Name
	dl.ChannelKind = channel.Kind
	channel.Enabled = &chEnabled
	dl.Channel = &channel
	return &dl, nil
}

// claimQuery describes one claim: first select candidates matching sel and lock them, then mark them as sending and
// The lease position in sel is marked with $n, which the caller fills in and passes as an argument.
type claimQuery struct {
	sql  string
	args []any
}

// ClaimRealtimeDeliveries claims a batch of due realtime deliveries for one channel, up to limit items.
//
// Claiming per **single channel** is deliberate, rather than "claim a global batch and pick which to send": the rate-limit gate in the delivery engine is per channel
// Maintenance: only by first knowing how many more rows this channel can send in the current round, and then claiming that same number of rows, does the rate limit avoid being consumed.
// retry count. If the order were reversed and rows were claimed first and then abandoned, rows blocked by the rate limit would already have been counted once against attempts,
// 3 retry budgets would be entirely consumed by pure waiting, eventually falling through to failed.
//
// The condition includes "sending" rows whose lease has already expired, which is where crash self-healing lands. The lease must be significantly longer than the worst-case duration of a single
// Worst-case delivery time (channel HTTP client timeout 15 seconds), otherwise the same row would be picked up by two dispatcher
// at the same time. It also blocks disabled channels at the same time: the disable operation has already marked the outstanding deliveries as skipped,
// and this extra check guards against leaks when disabling and claiming happen concurrently.
func (d *DB) ClaimRealtimeDeliveries(ctx context.Context, channelID int64, limit int, lease time.Duration) ([]*NotificationDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	return d.claimDeliveries(ctx, lease, claimQuery{
		sql: `SELECT dd.id FROM notification_deliveries dd
JOIN notification_channels c ON c.id = dd.channel_id
WHERE dd.channel_id = $1 AND dd.state IN ($2,$3) AND dd.next_attempt_at <= now()
  AND c.enabled AND c.mode = $4
ORDER BY dd.next_attempt_at, dd.id
FOR UPDATE OF dd SKIP LOCKED
LIMIT $5`,
		args: []any{channelID, NotifyStatePending, NotifyStateSending, NotifyModeRealtime, limit},
	}, nil)
}

// DigestBatchDue reports whether this channel has accumulated a due batch: pending deliveries exist, and **the oldest one**
// The age has reached the digest period.
//
// The decision is based on the age of the oldest delivery rather than the wall clock: this way, a newly created channel will not immediately emit a "digest" containing just one item because it was aligned to the top of the hour,
// and a batch that has been pending for a long time will not wait for another round in vain.
//
// It is kept separate from ClaimDigestBatch because the semantics differ: this function only answers "should it be sent,"
// but claiming must take **all** pending issues for the channel (including those that have not yet reached the required age) — otherwise, in one cycle
// would be split into multiple messages, defeating the purpose of the digest.
func (d *DB) DigestBatchDue(ctx context.Context, channelID int64, minAge time.Duration) (bool, error) {
	var due bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM notification_deliveries d
  JOIN notification_channels c ON c.id = d.channel_id
  WHERE d.channel_id = $1 AND d.state IN ($2,$3) AND c.enabled
  GROUP BY d.channel_id
  HAVING min(d.created_at) <= now() - make_interval(secs => $4)
)`, channelID, NotifyStatePending, NotifyStateSending, int64(minAge.Seconds())).Scan(&due)
	return due, err
}

// ClaimDigestBatch claims the pending deliveries for a channel that are currently due, as one digest batch,
// with at most MaxDigestBatchSize items per batch.
//
// All deliveries in the same batch share a batch_id, using the smallest id in the set as the batch number (stable, readable,
// with no extra sequence needed). On retry, COALESCE preserves the original batch number, so that "these N items were sent together"
// still holds after multiple retries.
//
// Take the first N items in ascending id order rather than at random: the earliest-produced deliveries go out first, so when a backlog builds up there is no
// there is no starvation where "new vulnerabilities are sent first and old ones are always queued behind them".
func (d *DB) ClaimDigestBatch(ctx context.Context, channelID int64, limit int, lease time.Duration) ([]*NotificationDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	// limit is an **upper bound on memory**; callers pass MaxDigestBatchSize, and this clamps it once more
	// to guard against a caller passing in a larger value.
	//
	// Deliberately does not accept a "rate-limit quota" as the batch size: rate limits are counted in messages—one batch only sends
	// one message consumes one token, deducted by takeTokens at the server layer — this is a different dimension from "how many bugs are packed in one batch
	// vulnerabilities" — the two are distinct quantities. Once, to make rate_per_min take effect for the digest, the per-round request budget was passed in as the batch size; as a result, a channel with rate=20/min packed only 1 vulnerability per batch,
	// was passed in as the batch size, so a channel with rate=20/min would only fit 1 item per batch, leaving a loophole,
	// digest degrades into a real-time push with a summary text. To change the rate limit, change the want in takeTokens,
	// not this code.
	if limit > MaxDigestBatchSize {
		limit = MaxDigestBatchSize
	}
	out, err := d.claimDeliveries(ctx, lease, claimQuery{
		sql: `SELECT dd.id FROM notification_deliveries dd
JOIN notification_channels c ON c.id = dd.channel_id
WHERE dd.channel_id = $1 AND dd.state IN ($2,$3) AND dd.next_attempt_at <= now() AND c.enabled
ORDER BY dd.id
FOR UPDATE OF dd SKIP LOCKED
LIMIT $4`,
		args: []any{channelID, NotifyStatePending, NotifyStateSending, limit},
	}, func(tx *sql.Tx, ids []int64) error {
		batchID := ids[0]
		for _, id := range ids {
			if id < batchID {
				batchID = id
			}
		}
		ph, idArgs := placeholders(2, ids)
		_, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET batch_id = COALESCE(batch_id, $1)
WHERE id IN (`+ph+`)`, append([]any{batchID}, idArgs...)...)
		return err
	})
	return out, err
}

// claimDeliveries performs "select + set sending to extend the lease + read the full row", all within a single transaction.
// postClaim is an optional extra step (the batch aggregation path uses it to write batch_id).
func (d *DB) claimDeliveries(ctx context.Context, lease time.Duration, cq claimQuery, postClaim func(*sql.Tx, []int64) error) ([]*NotificationDelivery, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	ids, err := selectForClaim(ctx, tx, cq.sql, cq.args...)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, tx.Commit()
	}
	// Set sending and push next_attempt_at into the future: this future moment is the lease expiry time,
	// "Lease not yet expired" and "retry time not yet reached" therefore share the same condition expression, so no new column is needed.
	ph, idArgs := placeholders(3, ids)
	if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, attempts=attempts+1, next_attempt_at=now()+make_interval(secs => $2)
WHERE id IN (`+ph+`)`,
		append([]any{NotifyStateSending, lease.Seconds()}, idArgs...)...); err != nil {
		return nil, err
	}
	if postClaim != nil {
		if err := postClaim(tx, ids); err != nil {
			return nil, err
		}
	}
	out, err := loadDeliveriesTx(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func selectForClaim(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func loadDeliveriesTx(ctx context.Context, tx *sql.Tx, ids []int64) ([]*NotificationDelivery, error) {
	ph, args := placeholders(1, ids)
	rows, err := tx.QueryContext(ctx, joinedDeliveryQuery+` WHERE d.id IN (`+ph+`) ORDER BY d.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationDelivery{}
	for rows.Next() {
		dl, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dl)
	}
	return out, rows.Err()
}

// MarkDeliveriesSent marks a batch of deliveries as sent.
func (d *DB) MarkDeliveriesSent(ctx context.Context, ids []int64) error {
	ph, args := placeholders(2, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, sent_at=now(), last_error='' WHERE id IN (`+ph+`)`, append([]any{NotifyStateSent}, args...)...)
	return err
}

// RescheduleDeliveries returns a batch of deliveries to pending and pushes back their retry time.
//
// Returning deliveries to pending, rather than introducing a new intermediate state, is so that
// the number of remaining chances is expressed in only one place (MaxNotifyAttempts), avoiding the state machine's branches growing with the retry policy.
func (d *DB) RescheduleDeliveries(ctx context.Context, ids []int64, delay time.Duration, errMsg string) error {
	ph, args := placeholders(4, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, next_attempt_at=now()+make_interval(secs => $2), last_error=$3
WHERE id IN (`+ph+`)`,
		append([]any{NotifyStatePending, delay.Seconds(), truncateNotifyError(errMsg)}, args...)...)
	return err
}

// DeferDeliveries returns a batch of deliveries to pending, immediately claimable again, and **revokes the one attempt counted at claim time**.
//
// It serves only one purpose: when a digest is split into segments to respect the channel's length limit, entries that do not fit in this message are held over to the next batch.
// That is not a failure, so it should not consume the retry budget; attempts was already optimistically incremented by 1 at claim time,
// This must be subtracted back. Otherwise a backlog of 500 entries would be split into 25 segments of 20 each,
// The tail entries would be judged failed by MaxNotifyAttempts already in the 3rd segment, even though they never had any error.
//
// GREATEST(...,0) guards against the case where someone manually resent and reset attempts to zero, then this path runs again,
// so the counter never becomes negative.
func (d *DB) DeferDeliveries(ctx context.Context, ids []int64, reason string) error {
	ph, args := placeholders(3, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, attempts=GREATEST(attempts-1, 0), next_attempt_at=now(), last_error=$2
WHERE id IN (`+ph+`)`,
		append([]any{NotifyStatePending, truncateNotifyError(reason)}, args...)...)
	return err
}

// FailDeliveries marks a batch of deliveries as permanently failed, awaiting a manual resend from the delivery history.
func (d *DB) FailDeliveries(ctx context.Context, ids []int64, errMsg string) error {
	// Placeholders start at $3: $1 is state, $2 is last_error.
	ph, args := placeholders(3, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries SET state=$1, last_error=$2 WHERE id IN (`+ph+`)`,
		append([]any{NotifyStateFailed, truncateNotifyError(errMsg)}, args...)...)
	return err
}

// RetryNotificationDelivery manually resends a single delivery: resets it to pending, clears the retry counter,
// and makes it due immediately. Clearing the counter is deliberate: when a person clicks "resend", it means the causes of the earlier failures have been addressed.
// Limiting it by the old count makes no sense.
func (d *DB) RetryNotificationDelivery(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$2, attempts=0, next_attempt_at=now(), last_error=''
WHERE id=$1 AND state IN ($3,$4)`, id, NotifyStatePending, NotifyStateFailed, NotifyStateSkipped)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("delivery %d does not exist or its current state does not allow resending", id)
	}
	return nil
}

// NotificationDeliveryFilter is the query condition for delivery history.
type NotificationDeliveryFilter struct {
	ChannelID int64
	State     string
	EventKind string
}

func (f NotificationDeliveryFilter) where() (string, []any) {
	var conds []string
	var args []any
	if f.ChannelID > 0 {
		args = append(args, f.ChannelID)
		conds = append(conds, fmt.Sprintf("d.channel_id=$%d", len(args)))
	}
	if f.State != "" {
		args = append(args, f.State)
		conds = append(conds, fmt.Sprintf("d.state=$%d", len(args)))
	}
	if f.EventKind != "" {
		args = append(args, f.EventKind)
		conds = append(conds, fmt.Sprintf("e.kind=$%d", len(args)))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListNotificationDeliveries returns delivery history page by page, newest first.
func (d *DB) ListNotificationDeliveries(ctx context.Context, f NotificationDeliveryFilter, page, pageSize int) ([]*NotificationDelivery, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	where, args := f.where()

	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := fmt.Sprintf("%s%s ORDER BY d.id DESC LIMIT $%d OFFSET $%d",
		joinedDeliveryQuery, where, len(args)+1, len(args)+2)
	rows, err := d.QueryContext(ctx, q, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*NotificationDelivery{}
	for rows.Next() {
		dl, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, dl)
	}
	return out, total, rows.Err()
}

// truncateNotifyError trims the error message to a length acceptable for the column. The response body returned by a channel can be very long
// (especially when a generic Webhook posts to a self-hosted service), and without truncation the history list payload would bloat.
func truncateNotifyError(msg string) string {
	const max = 500
	if len(msg) <= max {
		return msg
	}
	// Back off to a character boundary so that no half UTF-8 character is left behind, which would show up as garbled text in the frontend.
	cut := max
	for cut > 0 && !isUTF8Start(msg[cut]) {
		cut--
	}
	return msg[:cut] + "…"
}

func isUTF8Start(b byte) bool { return b&0xC0 != 0x80 }

// placeholders generates a $n placeholder string starting from start, along with the corresponding arguments, for use in IN (...).
// For example, start=3, ids=[7,8] → "$3,$4", [7,8].
func placeholders(start int, ids []int64) (string, []any) {
	ph := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		ph = append(ph, fmt.Sprintf("$%d", start+i))
		args = append(args, id)
	}
	return strings.Join(ph, ","), args
}

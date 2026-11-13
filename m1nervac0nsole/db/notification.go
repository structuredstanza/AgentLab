package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/notify"
)

// This file holds the channel configuration and event layer for IM push. Claiming and state transitions for delivery tasks are in
// db/notification_delivery.go.
//
// Two invariants, which must be kept when changing this file:
//
//  1. The vulnerability-write transaction (RecordFindingTx) calls only InsertNotificationEventTx, as a single blind insert.
//     It reads no notification-related tables and performs no filter matching. Any read introduced here could, because of
//     a user's misconfigured filter, pollute or even abort the vulnerability write transaction.
//  2. Filter matching never errors: malformed configuration is always treated as a "match" (see notify.Match). It is better to
//     never miss a notification.

// ErrNotificationChannelNotFound indicates that the channel does not exist.
var ErrNotificationChannelNotFound = errors.New("notification channel not found")

// Delivery status.
const (
	NotifyStatePending = "pending" // Pending
	NotifyStateSending = "sending" // Claimed by a dispatcher; the lease has not yet expired
	NotifyStateSent    = "sent"    // Delivered
	NotifyStateFailed  = "failed"  // Retries exhausted or permanently failed; can be resent manually
	NotifyStateSkipped = "skipped" // Channel is disabled and will no longer send
)

// Push mode.
const (
	NotifyModeRealtime = "realtime"
	NotifyModeDigest   = "digest"
)

// ValidNotifyMode whitelist-validates the push mode (same approach as findings.status: no DB CHECK constraint,
// to facilitate future extension).
func ValidNotifyMode(m string) bool {
	return m == NotifyModeRealtime || m == NotifyModeDigest
}

// NotificationChannel is the configuration of a single channel instance. Config and Filter are kept as raw JSON,
// Parsing is delegated to the notify package; the db layer does not understand the meaning of these fields.
type NotificationChannel struct {
	ID     int64           `json:"id"`
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Mode   string          `json:"mode"`
	Config json.RawMessage `json:"config"`
	Filter json.RawMessage `json:"filter"`
	// A pointer is used for Enabled to distinguish between "the field was not provided" and "explicitly set to false" —
	// The frontend toggle control only submits the fields that were changed.
	Enabled    *bool     `json:"enabled,omitempty"`
	RatePerMin int       `json:"rate_per_min"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IsEnabled returns whether the channel is enabled; if Enabled is nil (not loaded), it is treated as enabled.
func (c *NotificationChannel) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// NotificationEvent is a single event fact.
type NotificationEvent struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	FindingID int64           `json:"finding_id"`
	Snapshot  json.RawMessage `json:"snapshot"`
	CreatedAt time.Time       `json:"created_at"`
}

const notificationChannelCols = `id, name, kind, enabled, config, mode, filter, rate_per_min, created_at, updated_at`

func scanNotificationChannel(sc interface{ Scan(...any) error }) (*NotificationChannel, error) {
	var c NotificationChannel
	var enabled bool
	if err := sc.Scan(&c.ID, &c.Name, &c.Kind, &enabled, &c.Config, &c.Mode, &c.Filter, &c.RatePerMin, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.Enabled = &enabled
	return &c, nil
}

// ListNotificationChannels returns all channel instances, with enabled ones first, then ordered by id within each group.
// Sorting is done in SQL so that the UI and the dispatcher see the same stable order.
func (d *DB) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels
ORDER BY enabled DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationChannel{}
	for rows.Next() {
		c, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NotificationChannelByID fetches a single channel.
func (d *DB) NotificationChannelByID(ctx context.Context, id int64) (*NotificationChannel, error) {
	row := d.QueryRowContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels WHERE id=$1`, id)
	c, err := scanNotificationChannel(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotificationChannelNotFound
	}
	return c, err
}

// SaveNotificationChannel creates or updates a channel.
//
// On update, only overwrite the fields that the caller explicitly provides (non-nil / non-empty), so that the frontend can submit partial
// edits from a drawer form without having to echo back the config fields it doesn't display. Echoing them back would risk
// an incident where a masked value overwrites the real secret key.
func (d *DB) SaveNotificationChannel(ctx context.Context, c *NotificationChannel) (int64, error) {
	if c.Mode == "" {
		c.Mode = NotifyModeRealtime
	}
	// Deliberately, **no** processing is applied to 0: 0 is a valid configuration and means "no rate limit".
	//
	// Previously written as `if c.RatePerMin <= 0 { c.RatePerMin = defaultValue }`, intending to "use a safe default when unspecified",
	// give a safe default", but this also swallowed an explicit 0. The docs, the UI hints, and
	// takeTokens all interpret 0 as unlimited, but only here it is quietly changed to 20 (Telegram)
	// The operator believed rate limiting was lifted, but it was actually capped at 20/min with no indication at all.
	//
	// Only the caller knows the difference between "unspecified" and "explicit 0" (the field is absent from the request body vs. explicitly sent as 0),
	// So the default value is filled in by the server layer when the field is omitted; see notifyCreateChannel.
	if c.RatePerMin < 0 {
		return 0, errors.New("rate limit cannot be negative")
	}
	if c.Config == nil {
		c.Config = json.RawMessage(`{}`)
	}
	if c.Filter == nil {
		c.Filter = json.RawMessage(`{}`)
	}
	enabled := c.IsEnabled()

	if c.ID == 0 {
		var id int64
		err := d.QueryRowContext(ctx, `INSERT INTO notification_channels(name,kind,enabled,config,mode,filter,rate_per_min)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			c.Name, c.Kind, enabled, string(c.Config), c.Mode, string(c.Filter), c.RatePerMin).Scan(&id)
		return id, err
	}
	res, err := d.ExecContext(ctx, `UPDATE notification_channels
SET name=$2, kind=$3, enabled=$4, config=$5, mode=$6, filter=$7, rate_per_min=$8
WHERE id=$1`,
		c.ID, c.Name, c.Kind, enabled, string(c.Config), c.Mode, string(c.Filter), c.RatePerMin)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotificationChannelNotFound
	}
	return c.ID, nil
}

// SetNotificationChannelEnabled toggles enabling and disabling.
//
// When disabling a channel, also mark its not-yet-sent deliveries as skipped; otherwise, after re-enabling,
// A batch of old vulnerabilities that piled up during the suspension may suddenly arrive. They are already out of date and easily mistaken for newly added ones.
func (d *DB) SetNotificationChannelEnabled(ctx context.Context, id int64, enabled bool) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE notification_channels SET enabled=$2 WHERE id=$1`, id, enabled)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotificationChannelNotFound
		}
		if !enabled {
			if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET state=$2, last_error=$3
WHERE channel_id=$1 AND state IN ($4,$5)`,
				id, NotifyStateSkipped, "channel has been disabled", NotifyStatePending, NotifyStateSending); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteNotificationChannel deletes a channel. Its delivery history is removed by cascading deletion through the foreign key
// (once the channel configuration is gone, the history can no longer be interpreted).
func (d *DB) DeleteNotificationChannel(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotificationChannelNotFound
	}
	return nil
}

// RecordNotificationEventTx **best-effort** writes one push event within the caller's transaction.
//
// This is the only notification-related change on the vulnerability write path: a single INSERT that reads no tables, is unaware of channels,
// and runs no filtering. Committing the transaction guarantees that "the vulnerability is persisted" and "the push task exists" are atomically consistent,
// leaving no window where the commit succeeds but the message is never enqueued and is lost permanently.
//
// Two key design decisions, neither of which was written on a whim:
//
//  1. **Why SAVEPOINT**: In PostgreSQL, if any statement inside a transaction fails, the whole transaction enters an
//     aborted state, and every subsequent statement (including COMMIT) fails. So "ignore the error from this INSERT
//     and let the caller keep committing" cannot be done in PG, unless a savepoint isolates the error to
//     this one statement. Without a savepoint, the only option left is to roll back the whole transaction.
//
//  2. **Why rolling back everything is wrong**: Push notification is a convenience feature, while the vulnerability record is the product itself. A problem
//     in the notification table (an unmigrated old database, a transient disk failure) should not prevent a high-severity vulnerability from being stored. So here the failure is isolated
//     log the error, and return false so the vulnerability write still commits, at the cost of dropping this one push.
//     Returning bool rather than error is deliberate: callers should not treat it as an error that affects whether the write succeeds.
func RecordNotificationEventTx(ctx context.Context, tx *sql.Tx, kind string, findingID int64, snap notify.Snapshot) bool {
	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[notify] failed to serialize push event finding=%d: %v", findingID, err)
		return false
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT notify_event`); err != nil {
		log.Printf("[notify] failed to create savepoint finding=%d: %v", findingID, err)
		return false
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,$2,$3)`,
		kind, findingID, string(raw)); err != nil {
		log.Printf("[notify] failed to write push event finding=%d (finding record unaffected): %v", findingID, err)
		// Roll back to the savepoint, recovering the transaction from the aborted state.
		if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT notify_event`); rbErr != nil {
			log.Printf("[notify] rollback to savepoint failed finding=%d: %v", findingID, rbErr)
		}
		return false
	}
	// Release the savepoint so that useless savepoints do not accumulate in long transactions.
	_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT notify_event`)
	return true
}

// AddNotificationEvent is the standalone-transaction version of InsertNotificationEventTx, for call sites that are not inside an
// existing transaction (such as the channel's "send test message" feature, which has no real finding).
func (d *DB) AddNotificationEvent(ctx context.Context, kind string, findingID int64, snap notify.Snapshot) (int64, error) {
	raw, err := json.Marshal(snap)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize notification event snapshot: %w", err)
	}
	var id int64
	err = d.QueryRowContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,$2,$3) RETURNING id`,
		kind, findingID, string(raw)).Scan(&id)
	return id, err
}

// FanOutPendingEvents expands vulnerability events that have not yet been dispatched into delivery tasks, according to the currently enabled channels,
// and returns the number of events processed in this round and the number of newly created deliveries.
//
// The entire round runs in one transaction: events are claimed with FOR UPDATE SKIP LOCKED, so multiple processes running at the same time
// also each claim different rows (the archive queue in this project uses the same technique, see
// db/task_archives.go's completeNextArchiveJob).
//
// Filter matching is deliberately done on the Go side rather than in SQL: a channel's filter conditions are a JSONB of several optional fields,
// Expressing the matching of six combinations in SQL would make the query hard to maintain, while the number of channels is "a handful configured by hand",
// Loading everything and comparing each one in memory is faster and easier to test.
//
// Events that match no channel are also marked fanned_out — otherwise they would stay in the pending-dispatch set forever,
// Rescanned on every tick.
func (d *DB) FanOutPendingEvents(ctx context.Context, limit int) (eventCount, deliveryCount int, err error) {
	if limit <= 0 {
		limit = 200
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	channels, err := listEnabledNotificationChannelsTx(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, kind, finding_id, snapshot FROM notification_events
WHERE NOT fanned_out ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return 0, 0, err
	}
	var (
		events      []NotificationEvent
		parsedSnaps []notify.Snapshot
	)
	for rows.Next() {
		var ev NotificationEvent
		if err := rows.Scan(&ev.ID, &ev.Kind, &ev.FindingID, &ev.Snapshot); err != nil {
			rows.Close()
			return 0, 0, err
		}
		var snap notify.Snapshot
		// The snapshot is written by us, so in theory it always parses; a parse failure does not block the delivery flow,
		// But this event will be skipped by every channel that has filter conditions, because its fields are all empty — better to push one fewer than to risk it.
		// than to let one bad row stall the entire queue.
		_ = json.Unmarshal(ev.Snapshot, &snap)
		// kind takes the value from the row itself: the copy in the snapshot is the rendering copy and may have been written by an older version.
		snap.Kind = ev.Kind
		events = append(events, ev)
		parsedSnaps = append(parsedSnaps, snap)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(events) == 0 {
		return 0, 0, tx.Commit()
	}

	type pending struct {
		eventID   int64
		channelID int64
	}
	var toInsert []pending
	for i, snap := range parsedSnaps {
		for _, ch := range channels {
			if !notify.Match(notify.ParseFilter(ch.Filter), snap) {
				continue
			}
			toInsert = append(toInsert, pending{eventID: events[i].ID, channelID: ch.ID})
		}
	}
	if len(toInsert) > 0 {
		var (
			vals []string
			args []any
		)
		for _, p := range toInsert {
			vals = append(vals, fmt.Sprintf("($%d,$%d)", len(args)+1, len(args)+2))
			args = append(args, p.eventID, p.channelID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id) VALUES `+strings.Join(vals, ","), args...); err != nil {
			return 0, 0, err
		}
	}

	// Mark the events of this round as dispatched. Events that matched no channel are also marked (see the function comment).
	ids := make([]string, 0, len(events))
	markArgs := make([]any, 0, len(events))
	for _, ev := range events {
		markArgs = append(markArgs, ev.ID)
		ids = append(ids, fmt.Sprintf("$%d", len(markArgs)))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notification_events SET fanned_out=true WHERE id IN (`+strings.Join(ids, ",")+`)`, markArgs...); err != nil {
		return 0, 0, err
	}
	return len(events), len(toInsert), tx.Commit()
}

// listEnabledNotificationChannelsTx fetches the enabled channels inside the transaction. There are very few of them,
// so there is no pagination and no caching — a cache would introduce the extra timing question of "when do config changes take effect".
func listEnabledNotificationChannelsTx(ctx context.Context, tx *sql.Tx) ([]*NotificationChannel, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name, kind, config, mode, filter, rate_per_min
FROM notification_channels WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationChannel{}
	for rows.Next() {
		var c NotificationChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.Mode, &c.Filter, &c.RatePerMin); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// NotificationAssetNames resolves asset ids into short display names for use in push messages.
//
// The return order matches the input order, and the length may be less than the input's (nonexistent ids are skipped). Preserving the input order is
// To keep the asset order stable across multiple deliveries of the same vulnerability message, so that after a retry the message does not
// show a changed asset order, which would be misread as "the assets changed."
func (d *DB) NotificationAssetNames(ctx context.Context, ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ph, args := placeholders(1, ids)
	rows, err := d.QueryContext(ctx, `SELECT id, type, domain, ip, url, app_name, bundle_id FROM assets WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	labels := map[int64]string{}
	for rows.Next() {
		var (
			id                int64
			typ               string
			domain, ip, url   sql.NullString
			appName, bundleID sql.NullString
		)
		if err := rows.Scan(&id, &typ, &domain, &ip, &url, &appName, &bundleID); err != nil {
			return nil, err
		}
		labels[id] = assetDisplayName(typ, domain.String, ip.String, url.String, appName.String, bundleID.String)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if label, ok := labels[id]; ok && label != "" {
			out = append(out, label)
		}
	}
	return out, nil
}

// assetDisplayName picks the most recognizable identifier for each asset type.
// It returns an empty string as the fallback and leaves it to the caller to decide how to present an asset whose name cannot be obtained. This function does not invent a placeholder,
// because otherwise noise such as "asset#42" would creep into the push message, and readers would take it for a real domain name.
func assetDisplayName(typ, domain, ip, url, appName, bundleID string) string {
	pick := func(vals ...string) string {
		for _, v := range vals {
			if strings.TrimSpace(v) != "" {
				return v
			}
		}
		return ""
	}
	switch typ {
	case "root_domain", "subdomain":
		return domain
	case "ip":
		return ip
	case "app":
		return pick(appName, bundleID)
	case "service", "endpoint":
		return pick(url, domain, ip)
	default:
		return pick(domain, ip, url, appName)
	}
}

// SetFindingStatusWithNotify updates the handling status of a vulnerability and, within the same transaction, records a status-change
// push event.
//
// Returns from = the status before the change; found = whether the vulnerability exists; notified = whether the event was recorded successfully.
//
// Three deliberate behaviors:
//   - No event is registered when the state has not actually changed. Repeated submissions of the same value from the frontend drawer, or automation scripts
//     should not produce push-notification noise.
//   - When the finding does not exist, return found=false and perform no writes; the caller translates this into a 404.
//   - A failure to register the event does not affect the status update (see the savepoint note in RecordNotificationEventTx),
//     so when notified=false the status has already been updated successfully, and the caller should not report an error because of it.
func (d *DB) SetFindingStatusWithNotify(ctx context.Context, id int64, status string) (from string, found bool, notified bool, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var txErr error
		from, found, _, notified, txErr = SetFindingStatusTx(ctx, tx, id, status)
		return txErr
	})
	return from, found, notified, err
}

// SetFindingStatusTx updates the finding status and registers a status-change push event **within the caller's transaction**.
//
// It is factored out as a transaction-level function so that all paths that change status share the same semantics; previously only
// patchFinding takes the notifying version, and **when the retest conclusion is "fixed"** (finding_retests
// the `UPDATE findings SET status=...` in finding_retests writes directly to the database, so channels configured with
// Channels configured with `on_status_change` received no notifications at all for these status transitions: the status silently changed in the UI,
// and operations only discover it when they open the platform.
//
// Returns from = the status before the change, found = whether the vulnerability still exists, changed = whether the status actually changed,
// notified = whether the event was registered successfully (a failed registration does not affect the status update; see RecordNotificationEventTx).
func SetFindingStatusTx(ctx context.Context, tx *sql.Tx, id int64, status string) (from string, found bool, changed bool, notified bool, err error) {
	var (
		vulnclass, name, severity, summary string
		taskID                             sql.NullInt64
		assetIDs                           []byte
	)
	scanErr := tx.QueryRowContext(ctx, `SELECT vulnclass, name, severity, summary, task_id, asset_ids, status
FROM findings WHERE id=$1 FOR UPDATE`, id).
		Scan(&vulnclass, &name, &severity, &summary, &taskID, &assetIDs, &from)
	if scanErr == sql.ErrNoRows {
		return "", false, false, false, nil
	}
	if scanErr != nil {
		return "", false, false, false, scanErr
	}
	found = true
	if from == status {
		// No event is registered when the status has not actually changed: resubmitting the same value and idempotent replays should not
		// generate notification noise.
		return from, true, false, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status=$2 WHERE id=$1`, id, status); err != nil {
		return from, true, false, false, err
	}
	var assets []int64
	_ = json.Unmarshal(assetIDs, &assets)
	notified = RecordNotificationEventTx(ctx, tx, notify.EventFindingStatusChanged, id, notify.Snapshot{
		Kind:       notify.EventFindingStatusChanged,
		FindingID:  id,
		TaskID:     taskID.Int64,
		VulnClass:  vulnclass,
		Name:       name,
		Severity:   severity,
		Summary:    summary,
		AssetIDs:   assets,
		FromStatus: from,
		ToStatus:   status,
	})
	return from, true, true, notified, nil
}

// NotificationStats is the overview count shown at the top of the notifications page.
type NotificationStats struct {
	Channels     int   `json:"channels"`
	ChannelsOn   int   `json:"channels_on"`
	Pending      int   `json:"pending"`
	Failed       int   `json:"failed"`
	SentToday    int   `json:"sent_today"`
	BacklogAgeMS int64 `json:"backlog_age_ms"` // Milliseconds since the oldest pending delivery was due
}

// NotificationStatsSnapshot summarizes the health of the notification system.
// BacklogAgeMS is the most direct metric for "is delivery stuck?" — far more useful than the pending count,
// because a backlog of 3 items can mean anywhere from 3 seconds to 3 hours.
func (d *DB) NotificationStatsSnapshot(ctx context.Context) (*NotificationStats, error) {
	var s NotificationStats
	if err := d.QueryRowContext(ctx, `SELECT
    (SELECT count(*) FROM notification_channels),
    (SELECT count(*) FROM notification_channels WHERE enabled),
    (SELECT count(*) FROM notification_deliveries WHERE state IN ($1,$2)),
    (SELECT count(*) FROM notification_deliveries WHERE state=$3),
    (SELECT count(*) FROM notification_deliveries WHERE state=$4 AND sent_at >= date_trunc('day', now())),
    COALESCE((SELECT EXTRACT(EPOCH FROM (now() - min(created_at))) * 1000 FROM notification_deliveries WHERE state=$1), 0)::bigint`,
		NotifyStatePending, NotifyStateSending, NotifyStateFailed, NotifyStateSent).
		Scan(&s.Channels, &s.ChannelsOn, &s.Pending, &s.Failed, &s.SentToday, &s.BacklogAgeMS); err != nil {
		return nil, err
	}
	return &s, nil
}

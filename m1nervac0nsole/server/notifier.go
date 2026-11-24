package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/notify"
)

// Global setting keys (stored in the settings key-value table, so no table creation is needed).
const (
	// settingNotifyEnabled is the master switch for push notifications. It defaults to on. It serves as a one-click kill switch during maintenance windows,
	// and is not the condition for the feature being enabled. The actual enabling condition is whether a channel has been configured.
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the externally reachable address used to generate back-links to vulnerability details
	// (e.g. https://m1nervac0nsole.example.com). If left empty, messages include no backlink button.
	// The project has no reusable external address configuration, so a new entry is added here.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes is the period of digest mode, in minutes.
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick is the polling interval of the delivery engine. 3 seconds is the upper bound on this engine's real-time responsiveness,
	// and it is also the main source of latency between a vulnerability being written to the database and the message arriving in IM.
	notifyTick = 3 * time.Second
	// When the notifyBackgroundDisabledEnv environment variable is set, the server does not start the background delivery loop
	// (newNotifier(s).Run). The integration tests call stepRealtime and stepDigest directly to verify distribution results deterministically,
	// but if the background loop running every 3 seconds processes the same channels concurrently, the aggregation results fluctuate with timing.
	// Processing the same channel concurrently makes the aggregation fluctuate depending on timing. To prevent this,
	// A test-only switch; if the variable is absent, the service starts as usual (production behavior unchanged).
	notifyBackgroundDisabledEnv = "M1NERVAC0NSOLE_NOTIFY_BACKGROUND_DISABLED"
	// notifyLease is the lease duration taken when claiming a delivery. It must be significantly greater than the worst-case duration of a single delivery
	// (the notify package's HTTP client timeout of 15 seconds); otherwise the same row may be dispatched by two
	// Dispatch concurrently.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick limits the number of events fanned out per tick, so that enabling a channel for the first time
	// does not expand the entire historical backlog into delivery tasks all at once.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is the default value for the digest period.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick is the per-tick delivery cap used when a channel has no rate limit configured.
	// Its purpose is to prevent a single channel configured as unlimited, combined with one scan that surfaces thousands of vulnerabilities, from
	// A single-round loop that drags on lets blocking run for a long time.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick is the maximum number of messages delivered per channel in each tick.
	//
	// This cap is derived backward from the **lease duration**: when rows are claimed, they are given a lease (notifyLease = 3 minutes),
	// and if the number of sends delivered serially in one tick is so large that the worst-case time exceeds the lease, the later sends will not finish before the lease expires.
	// Within a single process this does not matter (Run is one goroutine running serially, so tick is never re-entered), but when **two processes
	// share the same database**, the other side will reclaim the rows whose lease has expired and send them again as duplicates, and it will also
	// increment attempts twice and mark the rows as failed while the original process is still delivering them.
	//
	// Value: a 3-minute lease / 30-second per-send timeout = 6 means the lease is **exactly used up with zero margin**,
	// Cannot take; take 5 so the worst-case time of 150 seconds leaves a 30-second margin. This relationship is governed by
	// TestNotifyTickBudgetFitsWithinLease pins this down: changing notifyLease,
	// notifySendTimeout, or this value will make that assertion fail.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout is the timeout for a single delivery attempt. It also determines the value of the previous constant,
	// The product of the two must not exceed notifyLease; see TestNotifyTickBudgetFitsWithinLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff is the backoff sequence for failed retries, indexed by the number of attempts already made.
// The 3 attempts (including the first) correspond to db.MaxNotifyAttempts, and the two must be changed together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// Reasons for delivery failure or delay, stored in notification_deliveries.last_error
// and shown in the delivery history.
const (
	errDeliveryChannelKindUnregistered = "Unregistered channel type: %q"
	errDeliverySnapshotUnrenderable    = "Could not parse the event snapshot, so this finding could not be turned into a message"
	errDeliveryChannelLengthCapped     = "The message reached the channel length limit; sent the first %d items and deferred the rest to the next batch"
	errDeliveryNoDeliveredCount        = "The channel did not report the number of delivered items (delivered=%d)"
	errDeliveryRetryExhausted          = "Failed after %d attempts: %s"
	errDeliverySnapshotEmpty           = "Event snapshot is empty for delivery #%d"
	errDeliverySnapshotParse           = "Could not parse the event snapshot for delivery #%d: %w"
	errDeliveryBatchAllUnparseable     = "Could not parse any of the %d deliveries in the digest batch"
)

// Notifier is the delivery engine for vulnerability push notifications.
//
// It runs as an independent goroutine alongside the Scheduler (see server.New). Deliberately does not reuse
// the Scheduler's tick: push real-time requirements (3 seconds) differ from the business rhythm of triggers,
// and their failures are isolated from each other. A stalled push should not affect agent triggering.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu protects buckets. There are few channels and contention is low, so a single mutex is sufficient,
	// not worth introducing a finer-grained structure for it.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is a token bucket for a single channel.
//
// A token bucket is used instead of a "count per minute, then reset to zero" sliding window because the latter has poor boundary effects:
// sending 20 messages at the very end of one window and another 20 the next instant amounts to 40 messages within one second for the platform,
// which triggers rate limiting; a token bucket refills at a constant rate and naturally avoids this kind of burst.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx ends. Started once by server.New.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step runs one round: it first dispatches new events, then delivers due tasks.
//
// If any step fails, it only logs the error and does not interrupt the loop; a failure in the notification system must never escalate into a process-level problem.
// Each tick is independent, and the next round will naturally retry.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] Failed to dispatch events: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] Failed to read channels: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// The unit of measurement for the token bucket is **number of messages** (equivalent to HTTP requests), not number of vulnerability entries.
		// In real-time mode the two are the same (one vulnerability, one message); in digest mode an entire batch of vulnerabilities is merged into
		// a single message, so only one token is consumed.
		//
		// Both modes consult the token bucket first and only then claim quota -- the order must not be reversed, otherwise a delivery blocked by rate limiting would already have consumed its retry count.
		// Delivery has already consumed retry attempts.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns the token cost and the upper bound on batch size for the digest channel in this tick.
//
// The two return values are **two different units of measure**, which is the reason this logic is split into its own function:
//
//   - tokens is the number of messages. A batch of vulnerabilities is merged into one message and sent in one HTTP request, so it is always 1.
//     rate_per_min still applies to the digest, so no more than this many summary messages per minute.
//   - claimLimit is the maximum number of vulnerabilities loaded into this batch. It is bounded only by the memory cap and is unrelated to the request budget.
//
// Once, to make rate_per_min take effect for digest, the per-round request budget was
// (notifyMaxSendsPerChannelPerTick, derived from the lease) directly down as the batch size,
// so in order to make rate_per_min apply to the digest. The result was that a channel with rate_per_min=20 refilled only 1 token per 3-second tick, so each summary
// message carried only 1 vulnerability. The digest degenerated into a "real-time push with summary wording", and readers received a stream of
// "1 new vulnerability in the last 30 minutes" messages, while db.MaxDigestBatchSize was never reached.
//
// This symptom is hard to catch in end-to-end tests, because the existing cases all manually pass a sufficiently large limit to
// stepDigest bypasses the quota calculation inside step, so the decision is kept here so that
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget pins this directly.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims and delivers the real-time tasks of a given channel, one vulnerability per message.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] Failed to claim realtime deliveries channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(errDeliveryChannelKindUnregistered, ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// A rendering failure is a problem with the local data, so retrying will not make it better.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest, when the batch expires, aggregates the pending deliveries of a given channel into a single message and sends it.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] Failed to determine whether the digest batch is due channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] Failed to claim digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(errDeliveryChannelKindUnregistered, ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// Deliveries whose snapshot is broken and that could not be included in the message must be explicitly marked as failed. Otherwise they would remain
	// outside of included, neither in the message nor in the failure list. When the send succeeds, their status would be
	// missed by the later bulk mark, leaving them stuck at sending until the lease expires and they are claimed again and again.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := errDeliverySnapshotUnrenderable
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] Failed to mark deliveries with unparseable snapshots as failed channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] Skipped %d deliveries with unparseable snapshots channel=%d", len(skipped), ch.ID)
	}
	// Only pass the items that were included in the message to send: included[i] corresponds strictly to msg.Items[i].
	// send relies on this correspondence to map "the channel reports that the first K items fit" onto the correct delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and transitions state according to the result.
//
// All deliveries in the same batch (in digest mode there may be dozens) share one send result: either they are all delivered, or the whole batch is retried.
// No per-item retries: a digest is a single message, and resending only part of it would corrupt the batch semantics.
//
// The only exception is **segmentation caused by the channel's length limit**: the channel reports that it actually fit only the first K items,
// so items K+1 onward must be held over to the next batch rather than being marked as successful along with the rest. Otherwise the
// truncated items would be neither in the message nor in the failure list, and would vanish entirely.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// Cap each single delivery so that one stuck channel cannot hold up all the remaining channels in this round.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// A channel can never report more deliveries than were sent; if that happens, the rendering layer must have miscounted,
			// so treat it as all delivered and log the problem, which is better than writing corrupted records.
			log.Printf("[notify] Channel reported %d delivered items, more than the %d submitted; treating all as delivered channel=%s",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] Failed to mark deliveries as sent channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// This message has hit the channel's length limit: requeue the remainder right away and let the next tick send it.
			// Use DeferDeliveries rather than RescheduleDeliveries, since this is not a failure,
			// and it should not consume the retry budget (the optimistic +1 applied at claim time gets subtracted back there).
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf(errDeliveryChannelLengthCapped, delivered)); err != nil {
				log.Printf("[notify] Failed to queue continuation deliveries channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// The channel reported neither an error nor how many messages were delivered. Treat it as a failure (apply backoff),
		// so this delivery does not keep being claimed over and over without ever being marked done.
		err = fmt.Errorf(errDeliveryNoDeliveredCount, delivered)
	}

	// Decide the failure handling for each delivery individually, rather than judging by the maximum attempt count across the whole batch.
	//
	// Previously it was `if maxAttempts(deliveries) >= MaxNotifyAttempts`, which failed the whole batch, but
	// the attempt counts of the entries in a batch are not all the same: an old delivery that has already been retried twice (attempts=2) would drag the other entries in the same batch
	// Brand-new deliveries (attempts=1) get dragged into failed together with the rest, so a new bug means none of the retries are used and the message is lost permanently.
	// This is exactly the opposite of the original intent of "not letting old rows drag new rows down with them."
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] Error while marking deliveries as failed channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf(errDeliveryRetryExhausted, db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] Error while marking deliveries as failed channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// Reschedule in groups by delay: there are only 3 backoff tiers, so there are naturally few groups; no need to issue a separate
	// UPDATE (that would make a batch of 500 rows produce 500 round trips).
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] Failed to reschedule deliveries channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] Delivery failed channel=%d kind=%s permanently_failed=%d retries_exhausted=%d pending_retry=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns those in all that are not in keep (compared by pointer identity).
// Used to find deliveries that failed to enter the message queue. They must be explicitly handled and must not be left in a gray area.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt obtains the channel implementation and parses its configuration.
// Returning ok=false means the type is not registered; the delivery should be marked as failed immediately rather than retried indefinitely.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// If configuration parsing fails, use an empty map: the channel's own Validate will report which field is missing,
		// and that error is more useful for guiding the user to fix the problem than a JSON parsing error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders a single vulnerability message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch renders the summary message. It parses each snapshot individually: if one entry is broken, only that entry is skipped,
// so it does not cause the entire batch summary to be lost.
//
// The returned included slice corresponds to msg.Items **strictly one-to-one** (the i-th delivery ↔ the i-th item).
// This correspondence is a hard requirement: the caller decides the first K deliveries based on "the channel reported that the first K entries fit"
// marked as delivered. If a bad snapshot is skipped here but the skipped delivery is not removed from included,
// the indices will be misaligned — the bad entry that should have failed gets marked as delivered, and good entries are wrongly judged as not delivered.
// Entries that are broken are explicitly marked as failed by the caller; see stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// A bad snapshot does not go into the message, nor into included — its disposition is the caller's responsibility
			// (explicitly marked as failed, rather than slipping through hidden among "delivered").
			log.Printf("[notify] Skipped unparseable snapshot in digest batch delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf(errDeliveryBatchAllUnparseable, len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor renders an event snapshot into a pending push item, while also resolving the asset name and the detail back-link.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// Failing to parse the asset name must not block the push: not being able to read the name is far less costly than failing to receive the notification,
		// it only means one asset line is missing from the message.
		log.Printf("[notify] Failed to parse asset name finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// The detail page route is at web/src/app/(main)/function/findings/detail/page.tsx,
		// which reads the finding id from the query parameter id.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens takes **at most want** tokens from the channel's token bucket and returns the number actually obtained.
//
// One token = one message (one HTTP request). In real-time mode, the caller passes as many as it needs;
// in summary mode, an entire batch of findings is sent as only one message, so pass 1.
//
// The bucket capacity is the channel's per-minute limit, refilled at a constant rate. ratePerMin<=0 means no rate limiting,
// Returns a finite but sufficiently large value, to keep a single loop round from being stalled by unbounded backlog.
//
// want: this cap is required. Without it, the only option is to drain the whole bucket, and the caller already has its own per-round limit,
// tokens taken beyond need are both unused and vanish before the next refill, so the accumulated burst capacity can never be reached,
// and even a round with no pending deliveries at all would still be charged one.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// Refill based on real elapsed time; the rate is ratePerMin/60 tokens per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// Add a tiny epsilon before truncating to an integer: token counts are accumulated floating-point values, so when a bucket is refilled in two steps,
	// 0.5 + 0.5 may yield 0.9999999999, and a direct int() would truncate that to 0,
	// so a mathematically full bucket could fail to yield a token. 1e-9 is far smaller than one token, so it will not mask a real deficit.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the master switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL returns the external address used for back-links, with any trailing slash removed.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval returns the digest period, falling back to the default value if it is invalid or not configured.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot parses the snapshot of the event that the delivery corresponds to.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf(errDeliverySnapshotEmpty, dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf(errDeliverySnapshotParse, dl.ID, err)
	}
	if snap.Kind == "" {
		// The event type is determined by the event row; the copy in the snapshot may have been written by an older version.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

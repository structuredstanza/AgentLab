package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/notify"
)

// This file covers the end-to-end behavior of the push feature: vulnerability persisted → event → dispatch → real HTTP send.
//
// One security note: these test cases **do not call the global Notifier.step()**; they only call stepRealtime/stepDigest on the channels they create themselves.
// Channel calls stepRealtime/stepDigest. The reason is that step() iterates over all enabled channels in the library——
// Running the tests on a development database that has real bots configured, the global step would push vulnerabilities produced during testing
// to those real groups. Calling each channel individually strictly limits the impact to fake receivers that the tests create themselves.
//
// Cleanup: when a test case finishes, delete the events it produced (cascading to delete deliveries) and the channels, so no backlog is left on real channels.
//
// Assertion approach: stepRealtime/stepDigest return no value and log internally, so what these tests assert is
// **observable external behavior** (what the fake receiver received, and what state the delivery rows ended up in), not the function's
// return value. This is closer to the real call path than stubbing the return value.

// notifyFixture is the shared fixture for the test cases in this file.
type notifyFixture struct {
	s       *Server
	pg      *db.DB
	request func(method, path, body string) *httptest.ResponseRecorder
	n       *Notifier
	// Self-created task/exploration: the test cases record vulnerabilities here, isolating their data from other test cases.
	taskID int64
	expID  int64
	// Events produced after cleanupMark are also deleted during cleanup.
	cleanupMark int64
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	// All fake receivers in this file run on 127.0.0.1, but delivery denies loopback addresses by default
	// (to prevent SSRF into same-machine services and cloud metadata). Tests explicitly enable this switch;
	// the "deny by default" behavior is covered by ssrf_test.go in the notify package.
	t.Setenv(notify.AllowLocalTargetsEnv, "1")
	// Disables the background delivery loop (3-second tick). The cases in this file call stepRealtime and
	// stepDigest directly to verify the result of a single distribution pass (first K delivered, rest held),
	// and if the background loop processes the same channel concurrently, the tallies fluctuate with timing (intermittent failures on slow CI
	// runners), which breaks determinism. This variable is set before trafficEvidenceServer starts the server
	// It has to be set up before it takes effect.
	t.Setenv(notifyBackgroundDisabledEnv, "1")
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg

	// Build a task of its own: the task created by the shared fixture trafficEvidenceServer cannot obtain an exploration id,
	// yet recording a vulnerability requires one.
	task, err := s.m.CreateTask("notification push test", "push behaviour verification", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID) })

	var mark int64
	if err := pg.QueryRow(`SELECT COALESCE(max(id),0) FROM notification_events`).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	// Make the fixture self-contained: mark all events that already exist before the fixture is built as dispatched, in one pass.
	//
	// Why this is necessary: FanOutPendingEvents is **global** and fans out every undispatched event in the database
	// onto all matching channels. The shared fixture trafficEvidenceServer itself records a vulnerability
	// (the initial finding it returns), and other test cases may also leave residual events behind. Without isolation,
	// these stray events would be dispatched onto this test case's channels, causing assertions such as "should have N deliveries" to fail.
	// Right or wrong at random: the failure depends on the order in which test cases run, which makes it harder to debug than a plain failure.
	if _, err := pg.Exec(`UPDATE notification_events SET fanned_out = true WHERE id <= $1 AND NOT fanned_out`, mark); err != nil {
		t.Fatal(err)
	}

	f := &notifyFixture{s: s, pg: pg, request: request, n: newNotifier(s), taskID: taskID, expID: task.ExpID, cleanupMark: mark}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM notification_events WHERE id > $1`, f.cleanupMark); err != nil {
			t.Logf("failed to clean up notification events: %v", err)
		}
	})
	// The master switch must be on (other test cases may have turned it off).
	if err := pg.SetBool(settingNotifyEnabled, true); err != nil {
		t.Fatal(err)
	}
	return f
}

// record writes a finding through the real evidence-write path and returns the finding id.
// This path registers the push event within the **same transaction**, which is exactly the hook point for this feature.
func (f *notifyFixture) record(t *testing.T, vulnclass, severity string) int64 {
	t.Helper()
	out, err := f.s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID:        f.taskID,
		ExplorationID: f.expID,
		Worker:        "test",
		VulnClass:     vulnclass,
		Name:          vulnclass,
		Severity:      severity,
		Summary:       vulnclass + " summary",
		Evidence:      "poc",
	}, nil)
	if err != nil {
		t.Fatalf("failed to record the finding: %v", err)
	}
	return out.FindingID
}

// channel reads back the channel configuration (used by stepX when invoked per channel).
func (f *notifyFixture) channel(t *testing.T, id int64) *db.NotificationChannel {
	t.Helper()
	ch, err := f.pg.NotificationChannelByID(context.Background(), id)
	if err != nil {
		t.Fatalf("failed to read the channel: %v", err)
	}
	return ch
}

// deliver dispatches the event and runs one delivery round for the specified channel only.
func (f *notifyFixture) deliver(t *testing.T, chID int64, baseURL string) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	f.n.stepRealtime(ctx, f.channel(t, chID), 50, baseURL)
}

// createChannel creates a channel through the HTTP API, which also covers the API's own validation path.
func (f *notifyFixture) createChannel(t *testing.T, payload map[string]any) int64 {
	t.Helper()
	raw, _ := json.Marshal(payload)
	r := f.request("POST", "/api/notify/channels", string(raw))
	if r.Code != 200 {
		t.Fatalf("failed to create channel %d: %s", r.Code, r.Body)
	}
	var res struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &res); err != nil || res.ID == 0 {
		t.Fatalf("channel creation returned an error: %s (%v)", r.Body, err)
	}
	t.Cleanup(func() { f.pg.Exec(`DELETE FROM notification_channels WHERE id=$1`, res.ID) })
	return res.ID
}

// fakeWebhook is a fake receiver that records the request bodies it receives.
type fakeWebhook struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []map[string]any
}

func newFakeWebhook(t *testing.T) *fakeWebhook {
	t.Helper()
	f := &fakeWebhook{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok","ok":true}`)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeWebhook) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeWebhook) body(t *testing.T, i int) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.bodies) {
		t.Fatalf("fake receiver got only %d requests, cannot fetch item %d", len(f.bodies), i)
	}
	return f.bodies[i]
}

func (f *fakeWebhook) last(t *testing.T) map[string]any {
	t.Helper()
	if f.count() == 0 {
		t.Fatal("fake receiver got no requests")
	}
	return f.body(t, f.count()-1)
}

// messageText extracts the human-readable part of the request payload:
// the generic webhook's default template carries a top-level `title`, Telegram carries `text`.
func messageText(t *testing.T, body map[string]any) string {
	t.Helper()
	var parts []string
	if s, ok := body["title"].(string); ok {
		parts = append(parts, s)
	}
	if s, ok := body["text"].(string); ok {
		parts = append(parts, s)
	}
	if items, ok := body["items"].([]any); ok {
		for _, raw := range items {
			if item, ok := raw.(map[string]any); ok {
				if name, ok := item["name"].(string); ok {
					parts = append(parts, name)
				}
			}
		}
	}
	if len(parts) == 0 {
		t.Fatalf("no recognizable body in the request: %v", body)
	}
	return strings.Join(parts, "\n")
}

// agePendingBatch backdates the channel's pending deliveries to test digest batch expiry.
func (f *notifyFixture) agePendingBatch(t *testing.T, chID int64) {
	t.Helper()
	if _, err := f.pg.Exec(`UPDATE notification_deliveries SET created_at = now() - interval '2 hours'
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyEndToEndRealtimeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "realtime push",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
	})
	f.record(t, "SQL injection", "high")
	f.deliver(t, chID, "")

	if hook.count() != 1 {
		t.Fatalf("should send 1 message, actually sent %d", hook.count())
	}
	text := messageText(t, hook.last(t))
	// The vulnerability title is echoed verbatim from input, so it is the stable check.
	// Severity and summary labels are rendering details and are not pinned.
	if !strings.Contains(text, "SQL injection") {
		t.Fatalf("message body is missing the finding title:\n%s", text)
	}
	// Delivery must transition to sent.
	var pending int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state <> $2`,
		chID, db.NotifyStateSent).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("%d entries still not marked sent after delivery", pending)
	}
}

func TestNotifyChannelAPIMasksSecretsAndPreservesOnUpdate(t *testing.T) {
	f := newNotifyFixture(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "masking case",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": "https://example.com/hook?token=abc123456", "headers": map[string]any{"Authorization": "Bearer SECabcdef123456"}},
	})

	r := f.request("GET", "/api/notify/channels", "")
	if r.Code != 200 {
		t.Fatalf("listing channels failed %d: %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), "abc123456") || strings.Contains(r.Body.String(), "SECabcdef123456") {
		t.Fatalf("API response leaked credentials: %s", r.Body)
	}
	var listed struct {
		Channels []struct {
			ID         int64          `json:"id"`
			Config     map[string]any `json:"config"`
			SecretKeys []string       `json:"secret_keys"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	var mine *struct {
		ID         int64          `json:"id"`
		Config     map[string]any `json:"config"`
		SecretKeys []string       `json:"secret_keys"`
	}
	for i := range listed.Channels {
		if listed.Channels[i].ID == chID {
			mine = &listed.Channels[i]
		}
	}
	if mine == nil {
		t.Fatal("the newly created channel does not appear in the list")
	}
	if !notify.IsMasked(fmt.Sprint(mine.Config["url"])) || !notify.IsMasked(fmt.Sprint(mine.Config["headers"])) {
		t.Fatalf("credential fields should be masked values: %v", mine.Config)
	}
	if len(mine.SecretKeys) == 0 {
		t.Fatal("the API should tell the frontend which fields are credentials")
	}

	// PATCH only renames and echoes back masked credentials: real credentials must be preserved as-is.
	body, _ := json.Marshal(map[string]any{
		"name":   "after rename",
		"config": map[string]any{"url": fmt.Sprint(mine.Config["url"]), "headers": mine.Config["headers"]},
	})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("update failed %d: %s", r.Code, r.Body)
	}
	cfg := f.channelConfig(t, chID)
	if cfg["url"] != "https://example.com/hook?token=abc123456" {
		t.Fatalf("masked echo overwrote the real credential: %v", cfg["url"])
	}
	if hdr, _ := cfg["headers"].(map[string]any); hdr["Authorization"] != "Bearer SECabcdef123456" {
		t.Fatalf("masked echo overwrote the header credential: %v", cfg["headers"])
	}
	if f.channel(t, chID).Name != "after rename" {
		t.Fatal("name was not updated")
	}

	// An explicitly cleared secret should take effect (as distinct from "echoing back the mask = keep unchanged").
	body, _ = json.Marshal(map[string]any{"config": map[string]any{"secret": ""}})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("clearing secret failed %d: %s", r.Code, r.Body)
	}
	if _, still := f.channelConfig(t, chID)["secret"]; still {
		t.Fatal("an empty string should clear the secret")
	}
}

func (f *notifyFixture) channelConfig(t *testing.T, id int64) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(f.channel(t, id).Config, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestNotifyChannelAPICreateValidation(t *testing.T) {
	f := newNotifyFixture(t)
	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"invalid kind", map[string]any{"name": "x", "kind": "nope", "config": map[string]any{}}},
		{"missing name", map[string]any{"kind": notify.KindWebhook, "config": map[string]any{"url": "https://e.com/h"}}},
		{"missing webhook", map[string]any{"name": "x", "kind": notify.KindWebhook, "config": map[string]any{}}},
		{"invalid webhook scheme", map[string]any{"name": "x", "kind": notify.KindWebhook, "config": map[string]any{"url": "file:///etc/passwd"}}},
		{"invalid mode", map[string]any{"name": "x", "kind": notify.KindWebhook, "mode": "sometimes", "config": map[string]any{"url": "https://e.com/h"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			r := f.request("POST", "/api/notify/channels", string(raw))
			if r.Code != 400 {
				t.Fatalf("should return 400, got %d: %s", r.Code, r.Body)
			}
			// Rejection status is the contract; the message text is not pinned.
		})
	}
	if r := f.request("DELETE", "/api/notify/channels/99999999", ""); r.Code != 404 {
		t.Fatalf("deleting a nonexistent channel should return 404, got %d", r.Code)
	}
}

func TestNotifyFilterBlocksBelowThreshold(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "critical only",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
		"filter": map[string]any{"min_severity": "critical"},
	})
	f.record(t, "low-severity issue", "low")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("findings below the threshold should not produce deliveries, got %d", n)
	}
	f.n.stepRealtime(context.Background(), f.channel(t, chID), 50, "")
	if hook.count() != 0 {
		t.Fatal("filtered findings should not emit messages")
	}
}

func TestNotifyDigestBatchesMultipleFindingsIntoOneMessage(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "digest push",
		"kind":   notify.KindWebhook,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"url": hook.URL},
	})
	for i := 0; i < 3; i++ {
		f.record(t, fmt.Sprintf("digest finding %d", i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)

	// Not yet expired: do not send.
	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 0 {
		t.Fatal("the digest batch was sent before it was due")
	}

	// After aging the batch: the three items are merged into one message.
	f.agePendingBatch(t, chID)
	f.n.stepDigest(ctx, ch, 50, "")
	if got := hook.count(); got != 1 {
		t.Fatalf("three items should be summarized into one message, actually sent %d", got)
	}
	text := messageText(t, hook.last(t))
	for i := 1; i <= 3; i++ {
		if !strings.Contains(text, fmt.Sprintf("digest finding %d", i)) {
			t.Fatalf("digest message is missing item %d:\n%s", i, text)
		}
	}
	// Items in the same batch should share a batch_id.
	var distinct, total int
	if err := f.pg.QueryRow(`SELECT count(DISTINCT batch_id), count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&distinct, &total); err != nil {
		t.Fatal(err)
	}
	if total != 3 || distinct != 1 {
		t.Fatalf("three deliveries should share one batch_id, got distinct=%d total=%d", distinct, total)
	}
}

func TestNotifyDisabledChannelDoesNotSend(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":    "disabled channel",
		"kind":    notify.KindWebhook,
		"enabled": false,
		"config":  map[string]any{"url": hook.URL},
	})
	f.record(t, "finding during the disabled period", "critical")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a disabled channel should not produce deliveries, got %d", n)
	}
}

func TestNotifyStatusChangeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "status-change subscription",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
		"filter": map[string]any{"on_status_change": true},
	})
	finding := f.record(t, "status-change case", "high")
	r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"fixed"}`)
	if r.Code != 200 {
		t.Fatalf("status change failed %d: %s", r.Code, r.Body)
	}
	f.deliver(t, chID, "")

	// Both the finding_created and the status-change events must deliver. Each message
	// must carry this finding's title, so no other event can account for the count.
	if n := hook.count(); n < 2 {
		t.Fatalf("expected at least 2 messages (creation and status change), got %d", n)
	}
	for i := 0; i < hook.count(); i++ {
		if !strings.Contains(messageText(t, hook.body(t, i)), "status-change case") {
			t.Fatalf("message %d does not carry the finding title", i)
		}
	}
}

func TestNotifyStatusChangeSuppressedByDefault(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "no status-change subscription",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
	})
	finding := f.record(t, "no change subscription", "high")
	if r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"false_positive"}`); r.Code != 200 {
		t.Fatalf("status change failed %d: %s", r.Code, r.Body)
	}
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id
WHERE d.channel_id=$1 AND e.kind=$2`, chID, notify.EventFindingStatusChanged).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a channel not subscribed to status changes should not receive status-change deliveries, got %d", n)
	}
}

func TestNotifyTestMessageEndpoint(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "test send",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", chID), ""); r.Code != 200 {
		t.Fatalf("test send failed %d: %s", r.Code, r.Body)
	}
	if hook.count() != 1 {
		t.Fatalf("the fake receiver should receive 1 test message, got %d", hook.count())
	}
	// When the configuration is broken, the channel's original error should be returned to the user as-is.
	badID := f.createChannel(t, map[string]any{
		"name":   "bad address",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": "http://127.0.0.1:1/hook"},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", badID), ""); r.Code != 502 {
		t.Fatalf("a delivery failure should return 502, got %d: %s", r.Code, r.Body)
	}
}

func TestNotifyDeliveriesHistoryAndRetry(t *testing.T) {
	f := newNotifyFixture(t)
	// Point at an address that is guaranteed to fail, to produce a failed delivery.
	chID := f.createChannel(t, map[string]any{
		"name":   "failing retry",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": "http://127.0.0.1:1/hook"},
	})
	f.record(t, "will-fail push", "high")
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)
	// Send continuously until the retry budget is exhausted.
	for i := 0; i < db.MaxNotifyAttempts; i++ {
		f.n.stepRealtime(ctx, ch, 50, "")
		if _, err := f.pg.Exec(`UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 minute' WHERE channel_id=$1`, chID); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	if err := f.pg.QueryRow(`SELECT state FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStateFailed {
		t.Fatalf("after retries are exhausted it should be failed, got %s", state)
	}

	r := f.request("GET", fmt.Sprintf("/api/notify/deliveries?channel_id=%d&state=failed", chID), "")
	if r.Code != 200 {
		t.Fatalf("history query failed %d: %s", r.Code, r.Body)
	}
	var hist struct {
		Deliveries []struct {
			ID        int64  `json:"id"`
			State     string `json:"state"`
			LastError string `json:"last_error"`
			Attempts  int    `json:"attempts"`
			Title     string `json:"title"`
		} `json:"deliveries"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Total != 1 || len(hist.Deliveries) != 1 {
		t.Fatalf("should find 1 failed delivery, got total=%d len=%d", hist.Total, len(hist.Deliveries))
	}
	if hist.Deliveries[0].LastError == "" {
		t.Fatal("history should include the failure reason, otherwise users cannot troubleshoot")
	}
	if hist.Deliveries[0].Attempts < db.MaxNotifyAttempts {
		t.Fatalf("the attempt count should be recorded, got %d", hist.Deliveries[0].Attempts)
	}
	if hist.Deliveries[0].Title != "will-fail push" {
		t.Fatalf("history should include the finding title, got %q", hist.Deliveries[0].Title)
	}

	// Manual resend: should return to pending and reset the counter to zero.
	if r := f.request("POST", fmt.Sprintf("/api/notify/deliveries/%d/retry", hist.Deliveries[0].ID), ""); r.Code != 200 {
		t.Fatalf("retry failed %d: %s", r.Code, r.Body)
	}
	var attempts int
	if err := f.pg.QueryRow(`SELECT state, attempts FROM notification_deliveries WHERE id=$1`, hist.Deliveries[0].ID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStatePending || attempts != 0 {
		t.Fatalf("after retry it should be pending with attempts=0, got %s/%d", state, attempts)
	}
}

func TestNotifyMetaAndSettingsRoundTrip(t *testing.T) {
	f := newNotifyFixture(t)
	r := f.request("GET", "/api/notify/meta", "")
	if r.Code != 200 {
		t.Fatalf("meta failed: %s", r.Body)
	}
	var meta struct {
		Kinds []struct {
			Kind       string   `json:"kind"`
			SecretKeys []string `json:"secret_keys"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Kinds) != len(notify.Kinds()) {
		t.Fatalf("meta should list all %d channels, got %d", len(notify.Kinds()), len(meta.Kinds))
	}
	for _, k := range meta.Kinds {
		if len(k.SecretKeys) == 0 {
			t.Errorf("channel %s did not report credential fields", k.Kind)
		}
	}

	// Round-trip all three global settings. The trailing slash should be normalized away, otherwise the callback link would be built as "//function/...".
	if r := f.request("PUT", "/api/settings", `{"notify_public_base_url":"https://m1nervac0nsole.example.com/","notify_digest_interval_min":15,"notify_enabled":true}`); r.Code != 200 {
		t.Fatalf("writing settings failed %d: %s", r.Code, r.Body)
	}
	t.Cleanup(func() {
		f.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, settingNotifyPublicBaseURL, settingNotifyDigestMinutes)
	})
	payload := f.s.settingsPayload()
	if payload["notify_public_base_url"] != "https://m1nervac0nsole.example.com" {
		t.Fatalf("callback URL was not normalized: %v", payload["notify_public_base_url"])
	}
	if payload["notify_digest_interval_min"] != 15 {
		t.Fatalf("digest interval did not take effect: %v", payload["notify_digest_interval_min"])
	}

	// Illegal values should be rejected.
	for _, body := range []string{
		`{"notify_public_base_url":"ftp://x"}`,
		`{"notify_digest_interval_min":0}`,
		`{"notify_digest_interval_min":99999}`,
	} {
		if r := f.request("PUT", "/api/settings", body); r.Code != 400 {
			t.Errorf("%s should return 400, got %d", body, r.Code)
		}
	}
}

// TestNotifyDeepLinkUsesPublicBaseURL covers deep-link construction: when public_base_url is configured,
// A single message must use an ActionCard with buttons, and the link must point to the vulnerability detail page.
func TestNotifyDeepLinkUsesPublicBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "backlink",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
	})
	finding := f.record(t, "finding with a backlink", "high")
	f.deliver(t, chID, "https://m1nervac0nsole.example.com")

	body := hook.last(t)
	items, _ := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("the default template should carry one item, got %v", body["items"])
	}
	item, _ := items[0].(map[string]any)
	want := fmt.Sprintf("https://m1nervac0nsole.example.com/function/findings/detail?id=%d", finding)
	if item["detail_url"] != want {
		t.Fatalf("callback URL is wrong\nexpected %s\ngot %v", want, item["detail_url"])
	}
}

// TestNotifyNoDeepLinkWithoutBaseURL: reverse coverage. When no external base URL is configured, a broken link should not be produced
// (e.g., pointing to localhost or a relative path), it should fall back to plain markdown.
func TestNotifyNoDeepLinkWithoutBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "no backlink",
		"kind":   notify.KindWebhook,
		"config": map[string]any{"url": hook.URL},
	})
	f.record(t, "finding without a backlink", "high")
	f.deliver(t, chID, "")

	body := hook.last(t)
	if body["title"] == nil {
		t.Fatal("the default template should carry a title")
	}
	// Without a public base URL there must be no detail deep link at all.
	if text := messageText(t, body); strings.Contains(text, "/function/findings/detail") {
		t.Fatalf("detail link should not appear without a public base URL:\n%s", text)
	}
}

// TestNotifyDigestSegmentsAndDefersRemainder is the end-to-end evidence for the "silent loss" fix.
//
// A digest message is bounded by the channel's length limit (Telegram, 4096 characters). When a batch does not fit, it **must be split by whole entries**:
// the markers for the entries that fit in this message are marked as delivered, and the rest return to the queue for the next message. The earlier implementation marked the whole batch
// as successful. The entries that were cut off were neither in the message nor in the failure list, while the delivery history still showed success;
// the gap went unnoticed.
//
// Assert four things: (1) only the number of entries that actually fit is marked (2) the rest remain pending (3) the deferred entries
// **Does not consume the retry budget** ④ Run another round to send the remaining ones (it won't get stuck).
func TestNotifyDigestSegmentsAndDefersRemainder(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	// Using Telegram: its 4096-character limit forces the split.
	chID := f.createChannel(t, map[string]any{
		"name":   "segmented digest",
		"kind":   notify.KindTelegram,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"bot_token": "123:abc", "chat_id": "1", "base_url": hook.URL},
	})
	const total = 60
	// Make the title longer to ensure the 60 entries far exceed the limit, so splitting is inevitable.
	longName := strings.Repeat("overlong finding name", 6)
	for i := 0; i < total; i++ {
		f.record(t, longName+strconv.Itoa(i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	f.agePendingBatch(t, chID)
	ch := f.channel(t, chID)

	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 1 {
		t.Fatalf("should emit only one message, got %d", hook.count())
	}

	var sent, pending int
	if err := f.pg.QueryRow(`SELECT
    count(*) FILTER (WHERE state=$2),
    count(*) FILTER (WHERE state=$3)
  FROM notification_deliveries WHERE channel_id=$1`, chID, db.NotifyStateSent, db.NotifyStatePending).
		Scan(&sent, &pending); err != nil {
		t.Fatal(err)
	}
	if sent == 0 {
		t.Fatal("some entries should be marked as delivered")
	}
	if pending == 0 {
		t.Fatalf("a batch of %d entries cannot all fit in 4096 bytes; some should remain pending; sent=%d", total, sent)
	}
	if sent+pending != total {
		t.Fatalf("entry count mismatch: sent=%d pending=%d total=%d (neither delivered nor pending = lost)", sent, pending, total)
	}

	// Deferred entries must not consume the retry budget: attempts is optimistically incremented +1 when claimed, so it must be decremented back when deferred.
	var maxAttempts int
	if err := f.pg.QueryRow(`SELECT COALESCE(max(attempts),0) FROM notification_deliveries
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending).Scan(&maxAttempts); err != nil {
		t.Fatal(err)
	}
	if maxAttempts > 0 {
		t.Fatalf("deferred entries must not consume the retry budget (otherwise they fail after a few), got attempts=%d", maxAttempts)
	}

	// Keep running until it converges. The assertion is that **everything is ultimately delivered** and that multiple rounds were actually needed along the way—
	// This is stronger than "the second round finishes sending": it proves that splitting won't get stuck and won't drop the remaining entries.
	rounds := 0
	for {
		var undelivered int
		if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries
WHERE channel_id=$1 AND state <> $2 AND state <> $3`, chID, db.NotifyStateSent, db.NotifyStateFailed).
			Scan(&undelivered); err != nil {
			t.Fatal(err)
		}
		if undelivered == 0 {
			break
		}
		rounds++
		if rounds > total+5 {
			t.Fatalf("digest delivery does not converge: ran %d rounds with %d items still undecided", rounds, undelivered)
		}
		before := hook.count()
		f.n.stepDigest(ctx, ch, 50, "")
		if hook.count() == before {
			t.Fatalf("round %d made no progress, the remaining %d items would be stuck forever", rounds, undelivered)
		}
	}
	if rounds < 2 {
		t.Fatalf("a 4096-byte message cannot fit %d long-title findings; they should be sent across multiple rounds, but only %d rounds were used", total, rounds)
	}
	// Every round after the first should be **pure continuation sends**, with no entries rejected by the channel.
	var failed int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state=$2`,
		chID, db.NotifyStateFailed).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Fatalf("the fake receiver always returns success, so there should be no failed entries, got %d", failed)
	}
}

// TestNotifyBackoffTableMatchesAttemptBudget is a drift-prevention assertion.
//
// The retry budget (db.MaxNotifyAttempts) and the backoff schedule table (notifyBackoff) live in two separate packages:
// the former is the state machine's policy, the latter is the engine's execution cadence. If only one of them is changed, such as raising the budget to 5
// attempts without adding backoff tiers—the code will not report an error; retries 4 and 5 will simply reuse the last tier's interval,
// which shows up as "retries mysteriously slowing down". This is hard to trace back to this spot during troubleshooting.
// Assert that the two lengths match, so that this kind of drift is exposed in CI.
func TestNotifyBackoffTableMatchesAttemptBudget(t *testing.T) {
	if len(notifyBackoff) != db.MaxNotifyAttempts {
		t.Fatalf("notifyBackoff length (%d) differs from max attempts (%d) — changing one must change the other",
			len(notifyBackoff), db.MaxNotifyAttempts)
	}
	// Backoff intervals must be non-decreasing; otherwise retries would fire ever more rapidly and aggravate rate limiting.
	for i := 1; i < len(notifyBackoff); i++ {
		if notifyBackoff[i] < notifyBackoff[i-1] {
			t.Fatalf("backoff intervals must be non-decreasing: tier %d %v < tier %d %v",
				i, notifyBackoff[i], i-1, notifyBackoff[i-1])
		}
	}
}

// TestNotifyRateLimitDoesNotConsumeRetryBudget locks in the ordering of "acquire the token first, then claim".
// If the order were reversed (claim first, then give up), a delivery blocked by the rate limiter would already have had attempts incremented once,
// The budget gets entirely consumed by pure waiting, and eventually it falls into failed.
func TestNotifyRateLimitDoesNotConsumeRetryBudget(t *testing.T) {
	// Only tests the token bucket itself; no Server is needed (and one should not be built for it).
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// 1 per minute: when the bucket is full, at most 1 is allowed.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now); got != 1 {
		t.Fatalf("with a full bucket, 1 per minute should take 1 token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("after tokens are exhausted it should immediately return 0, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(30*time.Second)); got != 0 {
		t.Fatalf("half a period should not refill a full token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Minute)); got != 1 {
		t.Fatalf("a full period should refill 1 token, got %d", got)
	}
	// Channels without a rate limit use a finite upper bound, to avoid a single round being held up by an unbounded backlog.
	if got := n.takeTokens(2, 0, notifyUnlimitedBurstPerTick+10, now); got != notifyUnlimitedBurstPerTick {
		t.Fatalf("an unlimited channel should return the per-tick cap %d, got %d", notifyUnlimitedBurstPerTick, got)
	}
	// Token buckets across channels are independent of each other.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("channel 1's bucket should still be empty, got %d", got)
	}
}

// TestNotifyTakeTokensKeepsUnusedTokens locks in the semantics of "take only want tokens."
//
// The earlier implementation drained the entire bucket and only then had the caller truncate, so a channel with rate=100/min that had filled its bucket
// but used only 5 notifications in a round would discard the remaining 95 tokens; the same happened when the channel had no pending deliveries in that round.
// The result is that the comment's claim, that a backlog can be flushed at up to rate_per_min items at once, is not achievable under any circumstances.
func TestNotifyTakeTokensKeepsUnusedTokens(t *testing.T) {
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// The bucket starts full (100), and this round only needs 5.
	if got := n.takeTokens(1, 100, 5, now); got != 5 {
		t.Fatalf("with want=5 it should take exactly 5 tokens, got %d", got)
	}
	// Key assertion: the remaining 95 must still be in the bucket, rather than being drained and discarded.
	// Do not advance time, so that whatever is taken can only come from the existing stock rather than from refill.
	if got := n.takeTokens(1, 100, 95, now); got != 95 {
		t.Fatalf("remaining tokens should still be available (expected 95), got %d — the bucket was drained for the whole round", got)
	}
	if got := n.takeTokens(1, 100, 1, now); got != 0 {
		t.Fatalf("the bucket is exhausted, should return 0, got %d", got)
	}
	// want<=0 must not deduct any tokens (empty rounds are not charged).
	n2 := &Notifier{buckets: map[int64]*notifyBucket{}}
	if got := n2.takeTokens(1, 20, 0, now); got != 0 {
		t.Fatalf("want=0 should return 0, got %d", got)
	}
	if got := n2.takeTokens(1, 20, 20, now); got != 20 {
		t.Fatalf("the want=0 call should not consume tokens; should still be able to take all 20, got %d", got)
	}
}

// TestDigestTickPlanDecouplesBatchSizeFromSendBudget pins down the two dimensions of digest mode.
//
// Once the digest batch size is tied to the per-round send budget, a channel with rate_per_min=20 can only refill 1 token
// in each 3-second tick, so every digest message carries only 1 vulnerability, which is functionally the same as having no digest at all.
// The summary, while the message header still says "1 new vulnerability in the last 30 minutes". This regression does not raise any error,
// The existing end-to-end cases cannot reveal it either (they pass an oversized limit into stepDigest by hand,
// bypassing the quota calculation inside step), so the decision itself is asserted directly here.
func TestDigestTickPlanDecouplesBatchSizeFromSendBudget(t *testing.T) {
	tokens, claimLimit := digestTickPlan()
	// One batch = one message = one request = one token. The token's unit is the message, not the vulnerability.
	if tokens != 1 {
		t.Fatalf("a digest batch sends only one message, so it should consume exactly 1 token, got %d", tokens)
	}
	if claimLimit != db.MaxDigestBatchSize {
		t.Fatalf("digest batch size should equal the in-memory upper bound db.MaxDigestBatchSize=%d, got %d",
			db.MaxDigestBatchSize, claimLimit)
	}
	// Key relationship: the batch size must be far larger than the per-tick request budget. Once the two are of the same order of magnitude,
	// it means the "how many messages to send" and the "how many vulnerabilities to pack per batch" have been conflated into one number again.
	if claimLimit <= notifyMaxSendsPerChannelPerTick {
		t.Fatalf("digest batch size %d must not be constrained by the per-round request budget %d — the request budget is the number of requests derived from the lease, a different dimension from how many findings fit in one batch",
			claimLimit, notifyMaxSendsPerChannelPerTick)
	}
}

// TestNotifyTickBudgetFitsWithinLease is yet another anti-drift assertion.
//
// The per-channel send cap per tick (notifyMaxSendsPerChannelPerTick) is derived backward from the lease duration:
// The worst-case serial delivery time within one round must be < the lease; otherwise the last few items will have their leases expire before they have all been sent,
// In a multi-instance deployment, the peer will re-claim them and send them again as duplicates. These three constants live in different places,
// Changing any one of them may break the relationship without any error being reported—so it is pinned down here.
func TestNotifyTickBudgetFitsWithinLease(t *testing.T) {
	worst := time.Duration(notifyMaxSendsPerChannelPerTick) * notifySendTimeout
	if worst >= notifyLease {
		t.Fatalf("worst-case per-channel round time %v must not reach or exceed the lease %v"+
			" (notifyMaxSendsPerChannelPerTick=%d × notifySendTimeout=%v) — if you change any of these three constants, check the other two too",
			worst, notifyLease, notifyMaxSendsPerChannelPerTick, notifySendTimeout)
	}
}

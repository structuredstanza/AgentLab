package server

import (
	"net/http/httptest"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestNotifyChannelLookupErrStatus checks that a missing channel maps to HTTP 404.
// notifyChannelLookupErr takes only w and err, so no DB or Server is needed.
func TestNotifyChannelLookupErrStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	notifyChannelLookupErr(rec, db.ErrNotificationChannelNotFound)
	if rec.Code != 404 {
		t.Fatalf("status code = %d, want 404 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestNotifyTestMessageLinks checks that the channel test message keeps the home and detail links.
// It is built as a pure function, so no DB or network is needed.
func TestNotifyTestMessageLinks(t *testing.T) {
	const base = "https://m1nervac0nsole.example.test"
	msg := notifyTestMessage(base)
	if len(msg.Items) != 1 {
		t.Fatalf("test message item count = %d, want 1", len(msg.Items))
	}
	item := msg.Items[0]
	if msg.HomeURL != base || item.DetailURL != base {
		t.Fatalf("link preservation failed: HomeURL=%q DetailURL=%q (want %q)", msg.HomeURL, item.DetailURL, base)
	}
}

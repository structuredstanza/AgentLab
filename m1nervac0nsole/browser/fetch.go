package browser

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// fetchReplyTimeout bounds the answer to a paused request. The page waits on
// it, so a wedged pipe must not leak the event goroutine forever.
const fetchReplyTimeout = 5 * time.Second

// enableFetch turns on request-level interception when the caller supplied a
// scope. Without a callback the browser is left alone, so a driver with no
// scope pays no round trip per request.
func (d *Driver) enableFetch(ctx context.Context, c conn) error {
	d.mu.Lock()
	allow := d.allowRequest
	d.mu.Unlock()
	if allow == nil {
		return nil
	}
	_, err := c.Send(ctx, "Fetch.enable", map[string]any{
		"patterns": []any{map[string]any{"urlPattern": "*", "requestStage": "Request"}},
	})
	return err
}

// requestPaused judges one request before it leaves the browser. It fails
// closed: a callback error blocks the request and records its host for the
// next tool result.
func (d *Driver) requestPaused(params json.RawMessage) {
	var ev struct {
		RequestID string `json:"requestId"`
		Request   struct {
			URL string `json:"url"`
		} `json:"request"`
	}
	if json.Unmarshal(params, &ev) != nil || ev.RequestID == "" {
		return
	}

	d.mu.Lock()
	allow := d.allowRequest
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), fetchReplyTimeout)
	defer cancel()
	if allow != nil {
		if err := allow(ev.Request.URL); err != nil {
			d.recordBlocked(ev.Request.URL)
			_, _ = d.Send(ctx, "Fetch.failRequest", map[string]any{
				"requestId":   ev.RequestID,
				"errorReason": "BlockedByClient",
			})
			return
		}
	}
	_, _ = d.Send(ctx, "Fetch.continueRequest", map[string]any{"requestId": ev.RequestID})
}

// recordBlocked notes the host once per drain window, so a page that hammers
// one blocked host reports it a single time.
func (d *Driver) recordBlocked(rawURL string) {
	host := rawURL
	if parsed, err := url.Parse(rawURL); err == nil {
		switch {
		case parsed.Hostname() != "":
			host = parsed.Hostname()
		case parsed.Scheme != "":
			host = parsed.Scheme
		}
	}
	d.mu.Lock()
	if d.blockedSeen == nil {
		d.blockedSeen = map[string]bool{}
	}
	if !d.blockedSeen[host] {
		d.blockedSeen[host] = true
		d.blocked = append(d.blocked, host)
	}
	d.mu.Unlock()
}

// BlockedRequests returns the hosts refused since the previous call and clears
// the list, so one tool result reports each host once.
func (d *Driver) BlockedRequests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.blocked
	d.blocked = nil
	d.blockedSeen = nil
	return out
}

package browser

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// fetchReplyTimeout bounds the answer to a paused request. The page waits on
// it, so a wedged pipe must not leak the event goroutine forever.
const fetchReplyTimeout = 5 * time.Second

// enableFetch turns on request-level interception when the caller supplied a
// scope, and authentication handling when the launch carries a proxy
// credential. Without either the browser is left alone, so a driver that needs
// neither pays no round trip per request.
func (d *Driver) enableFetch(ctx context.Context, c conn) error {
	d.mu.Lock()
	allow := d.allowRequest
	auth := d.proxyUser != "" || d.proxyPass != ""
	d.mu.Unlock()
	if allow == nil && !auth {
		return nil
	}
	params := map[string]any{
		"patterns": []any{map[string]any{"urlPattern": "*", "requestStage": "Request"}},
	}
	if auth {
		// Every paused request is still continued by requestPaused; this only
		// adds the challenge event the proxy credential answers.
		params["handleAuthRequests"] = true
	}
	_, err := c.Send(ctx, "Fetch.enable", params)
	return err
}

// requestPaused judges one request before it leaves the browser. It fails
// closed: a callback error blocks the request and records its host for the
// next tool result. The session is the target that paused it: a popup's
// request can only be answered on the popup's session.
func (d *Driver) requestPaused(session string, params json.RawMessage) {
	var ev struct {
		RequestID    string `json:"requestId"`
		ResourceType string `json:"resourceType"`
		Request      struct {
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
			_, _ = d.sendIn(ctx, session, "Fetch.failRequest", map[string]any{
				"requestId":   ev.RequestID,
				"errorReason": "BlockedByClient",
			})
			return
		}
	}
	if session != "" && ev.ResourceType == "Document" {
		// A popup's destination is only known once it asks for its document: an
		// image or a script it loads is not where it is going.
		d.namePopup(session, ev.Request.URL)
	}
	_, _ = d.sendIn(ctx, session, "Fetch.continueRequest", map[string]any{"requestId": ev.RequestID})
}

// authRequired answers an HTTP authentication challenge. Chromium ignores
// credentials embedded in --proxy-server, so a proxy challenge is the only way
// the testing browser authenticates to the gateway: the launch credential is
// supplied here, never on the command line. A challenge from an origin is
// cancelled, which is what a headless browser with no credentials does.
func (d *Driver) authRequired(session string, params json.RawMessage) {
	var ev struct {
		RequestID     string `json:"requestId"`
		AuthChallenge struct {
			Source string `json:"source"`
		} `json:"authChallenge"`
	}
	if json.Unmarshal(params, &ev) != nil || ev.RequestID == "" {
		return
	}

	d.mu.Lock()
	user, pass := d.proxyUser, d.proxyPass
	d.mu.Unlock()

	answer := map[string]any{"response": "CancelAuth"}
	if strings.EqualFold(ev.AuthChallenge.Source, "Proxy") && (user != "" || pass != "") {
		answer = map[string]any{"response": "ProvideCredentials", "username": user, "password": pass}
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchReplyTimeout)
	defer cancel()
	_, _ = d.sendIn(ctx, session, "Fetch.continueWithAuth", map[string]any{
		"requestId":             ev.RequestID,
		"authChallengeResponse": answer,
	})
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

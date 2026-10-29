package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements the DingTalk custom robot.
//
// Platform characteristics (these determine the implementation trade-offs here):
//   - Single-robot rate limit of 20 messages/minute; messages sent beyond this are silently dropped (HTTP may still return 200),
//     So rate limiting must be done on the client side, see DefaultRatePerMin.
//   - Choose one of three security settings: signing secret / custom keyword / IP allowlist. Signing is the only option that does not depend
//     on message content, so only signing is supported (a bare webhook with none of the three enabled is also supported).
//   - Both success and failure return HTTP 200; the errcode in the body distinguishes them. Not checking errcode
//     would record delivery failures as successes.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// The DingTalk webhook URL contains an access_token, which is itself a credential, so the whole URL is masked.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// The target is the DingTalk Webhook address itself; changing the address requires re-declaring the signing secret for the new address as well.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook address is missing")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook address is invalid: %w", err)
	}
	return nil
}

// Send delivers a message once. When there is a back-link and it is a single item, ActionCard is used (with buttons); otherwise markdown is used.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// DingTalk markdown bodies have no explicit byte limit, but we still apply an upper bound to keep evidence fields from growing abnormally large.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "View details",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk reports business errors inside HTTP 200 responses.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse DingTalk response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 means signature verification failed and 310000 means keyword mismatch. Both are configuration errors,
		// and retrying will not fix them.
		return 0, Permanent(fmt.Errorf("DingTalk returned an error (%d): %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends the timestamp and sign parameters to the webhook according to DingTalk's official signing rules.
//
// Rule: the string to sign is timestamp + "\n" + secret, and the **HMAC-SHA256 key is also secret**,
// Base64-encode the result, then URL-encode it. timestamp is in milliseconds. If secret is empty, return as-is,
// to support robots without signing enabled.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// Do not pass through err: the error text from url.Parse contains the full address (including access_token).
		return "", fmt.Errorf("failed to parse webhook address: %s", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks that the address is usable and uses a supported protocol, and for literal IP targets it determines whether they are on an internal network.
//
// Two points deserve care:
//
//  1. **Error messages must be redacted.** url.Parse itself returns a *url.Error, whose Error() includes
//     **the complete original address**, but for this feature, the addresses of these services embed credentials (DingTalk access_token,
//     WeCom key, Telegram bot token, Feishu hook id). Previously this place did `return err` directly,
//     so the error "invalid address format" carried the credentials out: into the 400 response of the test endpoint,
//     the last_error persisted on each delivery attempt, server logs, and the delivery history API.
//
//  2. **Literal IP addresses are judged as internal directly**; domain names are left for the dial stage to judge (blockInternalDial is the real
//     enforcement point, and it also covers DNS rebinding). Doing this check here is so that a warning can be given when the configuration is saved,
//     rather than waiting until the first delivery fails.
//
// Restricting protocols is defensive: schemes such as file:/// and gopher:// could cause http.Client to behave unexpectedly
// (although they are already blocked by the scheme check, there is no reason to open up this surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("cannot parse address (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http or https is supported; received: %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("host name is missing")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("refusing to send to local or link-local address %s (to send to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

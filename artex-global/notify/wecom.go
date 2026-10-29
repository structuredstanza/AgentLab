package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit is the hard limit on the markdown content of WeCom group robot messages (in bytes, not characters).
// This is the tightest limit among all six channels, and the main reason TruncateBytes exists.
const weComMarkdownLimit = 4096

// weComChannel implements the WeCom (Enterprise WeChat) group robot.
//
// Platform characteristics:
//   - It is the only channel that authenticates through the key in the URL and does not support signing, so the webhook address itself is the entire credential.
//   - The markdown content limit is 4096 **bytes**, and an over-length message is rejected outright (not truncated). Chinese characters take 3 bytes each,
//     so the body can hold only a little over a thousand Chinese characters, and the client must truncate.
//   - The rate limit is 20 messages per minute, also enforced by client-side rate limiting.
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// WeCom has only one credential, the webhook (the key in the URL), and it does not support signing;
// the whole address is the entire credential, so there are no other fields that need masking.
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// WeCom has only one field, the webhook, which serves as both the destination and the credential, so there is no such thing as a leftover credential after the address is changed.
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook address is missing")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook address is invalid: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// A digest batch can be quite long (50 entries × one line each + prefix), and 4096 bytes is easy to exceed.
	// Truncation is done here rather than left to the platform to report an error: a rejection means the entire batch is lost, whereas truncation at least delivers the first few entries.
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse WeCom response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 means the API call limit has been exceeded. The platform's rate-limit window is a rolling one, so retrying after a backoff is effective,
		// which is why it is explicitly classified as retryable. Reaching this point means the client's rate_per_min is configured too aggressively,
		// and retrying is only a fallback; the real fix is to lower the rate-limit value for that channel.
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom request was rate-limited (%d): %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 means the webhook key is invalid. This is a permanent failure, and retrying will not recover from it.
		return 0, Permanent(fmt.Errorf("WeCom returned an error (%d): %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

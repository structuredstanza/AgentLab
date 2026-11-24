package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// telegramTextLimit is the upper limit of the text field of Telegram sendMessage (in characters).
const telegramTextLimit = 4096

// telegramChannel implements the Telegram Bot API.
//
// Platform characteristics:
//   - Authentication is entirely in the URL path (/bot<token>/sendMessage), so no request signing is needed.
//   - Use HTML parse mode instead of MarkdownV2: MarkdownV2 requires escaping `_*[]()~`>#+-=|{}.!`
//     which is 18 characters; miss one and the whole message is rejected. HTML only requires escaping & < > (three characters).
//   - Business errors are also hidden inside HTTP 200 responses; check the ok field to detect them.
type telegramChannel struct{}

func (telegramChannel) Kind() string { return KindTelegram }

// Telegram allows roughly 1 message/second in one-to-one chats and 20 messages/minute in groups. Use the conservative values.
func (telegramChannel) DefaultRatePerMin() int { return 20 }

// The Bot Token is a full credential; chat_id is only the recipient and is not a secret (having it without the Token still cannot send messages).
func (telegramChannel) SecretKeys() []string { return []string{"bot_token"} }

// base_url determines the API endpoint the Token is sent to (e.g., a self-hosted reverse proxy). Changing it requires re-issuing the Token.
func (telegramChannel) DestinationKeys() []string { return []string{"base_url"} }

func (telegramChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "bot_token") == "" {
		return errors.New("Bot Token is missing")
	}
	if cfgString(cfg, "chat_id") == "" {
		return errors.New("Chat ID is missing")
	}
	if base := cfgString(cfg, "base_url"); base != "" {
		if err := validateHTTPURL(base); err != nil {
			return fmt.Errorf("API address is invalid: %w", err)
		}
	}
	return nil
}

func (c telegramChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := telegramEndpoint(cfg)
	if err != nil {
		return 0, Permanent(err)
	}
	text, kept := telegramHTML(m)
	payload := map[string]any{
		"chat_id":                  cfgString(cfg, "chat_id"),
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": false,
	}
	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse Telegram response: %w (%s)", err, snippet(raw))
	}
	if res.OK {
		return kept, nil
	}
	// 429 means rate limiting; retrying after a backoff is effective. The others (400 bad parameters, 401 invalid token, 403 blocked by user,
	// 404 chat not found) are configuration problems; retrying will not fix them on its own.
	if res.ErrorCode == 429 {
		return 0, fmt.Errorf("hit Telegram request rate limit: %s", res.Description)
	}
	return 0, Permanent(fmt.Errorf("Telegram response error %d: %s", res.ErrorCode, res.Description))
}

// telegramEndpoint builds the sendMessage URL. When base_url is empty, the official API is used,
// when non-empty, it is used for a self-hosted Bot API reverse proxy.
func telegramEndpoint(cfg map[string]any) (string, error) {
	base := cfgString(cfg, "base_url")
	if base == "" {
		base = "https://api.telegram.org"
	}
	base = strings.TrimSuffix(base, "/")
	token := cfgString(cfg, "bot_token")
	raw := base + "/bot" + token + "/sendMessage"
	u, err := url.Parse(raw)
	if err != nil {
		// Do not pass through err: the URL contains the Bot Token, and addr should not be echoed back here either.
		return "", fmt.Errorf("failed to build API address (API address: %s)", redactRequestTarget(base))
	}
	return u.String(), nil
}

// telegramHTML renders the HTML body, returning the body and the number of entries actually written (see Channel.Send).
func telegramHTML(m Message) (string, int) {
	var b strings.Builder
	b.WriteString("<b>" + telegramEscape(markdownTitle(m)) + "</b>\n")
	if m.Batch {
		// Telegram's limit is in **characters**, so packing is also measured in characters (runeSize).
		footer := ""
		if m.HomeURL != "" {
			footer = fmt.Sprintf("\n\n<a href=\"%s\">View full on platform</a>", telegramEscapeAttr(m.HomeURL))
		}
		kept := packItemCount(m.Items, telegramTextLimit, telegramReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return telegramBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		b.Reset()
		b.WriteString("<b>" + telegramEscape(telegramBatchTitle(m, items, len(m.Items))) + "</b>")
		for i, it := range items {
			b.WriteString("\n" + telegramEscape(telegramBatchLine(it, i+1)))
		}
		b.WriteString(footer)
		return TruncateHTML(b.String(), telegramTextLimit), kept
	}
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		b.WriteString(fmt.Sprintf("\n<b>Status change</b>: %s → %s",
			telegramEscape(StatusLabel(it.FromStatus)), telegramEscape(StatusLabel(it.ToStatus))))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n<b>Type</b>: " + telegramEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		b.WriteString("\n<b>Asset</b>: " + telegramEscape(a))
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		b.WriteString("\n<b>Summary</b>: " + telegramEscape(s))
	}
	if it.DetailURL != "" {
		b.WriteString(fmt.Sprintf("\n\n<a href=\"%s\">View details</a>", telegramEscapeAttr(it.DetailURL)))
	}
	return TruncateHTML(b.String(), telegramTextLimit), 1
}

// telegramReservedRunes reserves space for the message title and a possible truncation notice (measured in characters).
const telegramReservedRunes = 160

// telegramBatchLine renders one entry in the summary (unescaped; the caller escapes everything uniformly).
func telegramBatchLine(it Item, idx int) string {
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		return fmt.Sprintf("%d. %s · %s — %s", idx, SeverityLabel(it.Severity), it.Title(), a)
	}
	return fmt.Sprintf("%d. %s · %s", idx, SeverityLabel(it.Severity), it.Title())
}

// telegramBatchTitle renders the title line of the summary message. The entry count is the number of entries **actually included** in this message,
// rather than the total for this batch, since readers would otherwise assume the number in the message header is the full count.
func telegramBatchTitle(m Message, items []Item, total int) string {
	title := fmt.Sprintf("Vulnerability summary · %d total", total)
	if extra := total - len(items); extra > 0 {
		title += fmt.Sprintf(" (only the first %d shown; the remaining %d will follow in the next message)", len(items), extra)
	}
	if m.WindowMinutes > 0 {
		title = fmt.Sprintf("last %d min · %s", m.WindowMinutes, title)
	}
	return title
}

// telegramEscape escapes HTML text content for Telegram.
// Telegram only recognizes these three entities, so entities that already exist, like &amp;, would be escaped a second time after conversion. This is the
// Expected behavior: we want to display the raw characters, not let the user inject HTML.
func telegramEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// telegramEscapeAttr escapes HTML attribute values. Beyond text escaping, it must also handle quotes.
// A quote inside a URL would close the href attribute early and turn the rest of the content into an injection point.
func telegramEscapeAttr(s string) string {
	s = telegramEscape(s)
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

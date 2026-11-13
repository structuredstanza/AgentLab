package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel is an adapter for a notification channel. Implementations must be **stateless**: the same instance is shared and reused concurrently by multiple channels
// configurations, so credentials are always passed in via the cfg parameter.
type Channel interface {
	// Kind returns the channel type identifier, which must match the key in the registry.
	Kind() string
	// Validate is called when the configuration is saved, checking required fields and formats. The returned error is shown directly to
	// the person configuring, so the message should state "which field is missing" rather than a generic "invalid configuration".
	Validate(cfg map[string]any) error
	// Send delivers one message and returns the **number of entries actually delivered** along with an error.
	//
	// Why return the count: every platform has a message length limit, and when a summary message cannot fit the whole batch, it gets truncated.
	// If the caller unconditionally marks the entire batch as delivered, the entries that were cut off simply disappear——they are not visible in the message,
	// and the delivery history still shows success, so nothing can reveal that the entries were never sent. Once kept is returned,
	// the caller marks only the first kept entries, and the rest are left for the next batch.
	//
	// Returning an error indicates delivery failed; a *PermanentError means it should not be retried.
	// When failing, kept is meaningless, and the caller should ignore it.
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin returns the officially recommended per-minute delivery limit for this channel, used as the default
	// rate-limit value when creating a new channel instance. Returning 0 means no known limit.
	DefaultRatePerMin() int
	// SecretKeys returns the key names in this channel's configuration that hold credentials. When the API echoes configuration back, the values of these keys are masked,
	// and on update, if a masked value is received, the original value in the database is kept. Only the implementation knows clearly which fields count as credentials
	// (for a webhook the entire URL can be the credential, whereas for Telegram only the bot token within it is),
	// so this knowledge must be provided by the channel and must not be guessed by the upper layers.
	SecretKeys() []string
	// DestinationKeys returns the key names in this channel's configuration that determine where messages are sent.
	//
	// Like SecretKeys, this is security-relevant: the destination address and the credentials are two separate fields,
	// and if it were allowed to "change only the address while keeping the credentials as they are," anyone able to modify the channel configuration could send the real credentials stored in the database
	// to a server they control, and the masking of the channel configuration would lose all meaning.
	// See PrepareConfigUpdate for details.
	DestinationKeys() []string
}

// registry is the channel registry. Channels are deliberately registered through explicit literals rather than self-registration in init(): this keeps the full set of channels visible in one place, and a newly added channel that is missed surfaces at compile time instead of relying on runtime side effects.
// can all be seen in one place, and adding a channel exposes omissions at compile time rather than relying on runtime side effects.
var registry = map[string]Channel{
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get returns the channel implementation for the given kind.
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind reports whether kind is a supported channel type.
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds returns all supported channel types, sorted lexicographically (so the UI dropdown displays them in a stable order).
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError marks a delivery failure that should not be retried: credential errors, target rejections, invalid request bodies, and the like.
// Retries only make sense for transient failures (network jitter, rate limiting, upstream 5xx); repeatedly backing off and retrying a permanent failure
// It will neither succeed, nor will it cause the real error to be buried in the retry logs.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent marks err as a permanent failure. When err is nil, it returns nil,
// so that it can be written as `return Permanent(someCheck())`.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether the err chain carries a permanent-failure marker.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ---- config-reading helper ----
//
// Channel configs come from a JSONB column in the database. After encoding/json deserializes them, they become map[string]any,
// Numeric values are always float64, and arrays are []any. The helpers below normalize this conversion layer and tolerate user
// caused by users leaving fields blank in the UI (for example, entering a port as a string).

// cfgString gets a string configuration item and trims leading and trailing whitespace, since values copied and pasted from web forms often carry it.
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt gets an integer configuration item, accepting both float64 (the JSON default) and string sources.
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool gets a boolean configuration item, accepting the strings "true" and "1".
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings gets a string array configuration item, automatically trimming whitespace and discarding empty strings.
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// It also accepts a single string, to support form submissions where only one value is provided.
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap gets a string map configuration item (such as custom HTTP headers), trimming whitespace from both keys and values and discarding empty keys.
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}

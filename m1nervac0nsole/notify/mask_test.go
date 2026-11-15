package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestMaskedValueHidesBodyButKeepsTailHint(t *testing.T) {
	const secret = "https://oapi.dingtalk.com/robot/send?access_token=abcdef123456"
	got := MaskedValue(secret)
	if strings.Contains(got, "abcdef123456") {
		t.Fatalf("masked value leaked the full credential: %q", got)
	}
	if strings.Contains(got, "oapi.dingtalk.com") {
		t.Fatalf("masked value must not expose the address body: %q", got)
	}
	// The last 6 characters must be preserved so the user can recognize which bot it is.
	if !strings.HasSuffix(got, "123456") {
		t.Fatalf("the last 6 characters must be kept as an identifying hint: %q", got)
	}
	if !IsMasked(got) {
		t.Fatalf("masked value must be recognized by IsMasked: %q", got)
	}
}

func TestMaskedValueShortSecretGivesNoHint(t *testing.T) {
	// If a short credential also exposes its last 6 characters, that effectively exposes the entire credential.
	for _, s := range []string{"abc", "abcdef", ""} {
		got := MaskedValue(s)
		if got != MaskedPrefix {
			t.Fatalf("a credential of length %d must not get a trailing hint, got %q", len(s), got)
		}
		if s != "" && strings.Contains(got, s) {
			t.Fatalf("masked value contains the original value: %q", got)
		}
	}
}

func TestMaskConfigMasksOnlySecrets(t *testing.T) {
	cfg := map[string]any{
		"url":     "https://example.com/hook?token=SECRETVALUE",
		"headers": map[string]any{"X-Api-Key": "SECtest123456"},
		"port":    float64(587),
		"host":    "smtp.example.com",
	}
	masked := MaskConfig(KindWebhook, cfg)
	for _, k := range []string{"url", "headers"} {
		s, _ := masked[k].(string)
		if !IsMasked(s) {
			t.Errorf("%s must be masked, got %q", k, s)
		}
	}
	// Non-credential fields must be preserved as-is, otherwise the UI cannot display them.
	if masked["port"] != float64(587) {
		t.Errorf("non-credential field port must not change: %v", masked["port"])
	}
}

func TestMaskConfigUnknownKindReturnsEmpty(t *testing.T) {
	// When the channel type cannot be recognized, it is better to let the UI show an empty configuration than to echo back raw content that may contain credentials.
	got := MaskConfig("nope", map[string]any{"webhook": "https://x/y?token=LEAK"})
	if len(got) != 0 {
		t.Fatalf("unknown channel type must return an empty config, got %v", got)
	}
}

func TestMaskConfigDoesNotMutateInput(t *testing.T) {
	// Masking is a display-layer behavior and must not reversely alter the true value stored in the database.
	cfg := map[string]any{"url": "https://example.com/hook", "headers": map[string]any{"X": "SECtest123456"}}
	_ = MaskConfig(KindWebhook, cfg)
	if IsMasked(cfg["url"].(string)) {
		t.Fatal("MaskConfig modified its input, which would overwrite real credentials with mask values")
	}
}

func TestMergeConfigKeepsStoredOnMaskedIncoming(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET", "method": "POST"}
	// The user only changed the method, so the browser submits the masked value plus the new method.
	incoming := map[string]any{
		"webhook": MaskedValue("https://real/hook"),
		"secret":  MaskedValue("REALSECRET"),
		"method":  "PUT",
	}
	got := MergeConfig(stored, incoming)
	if got["webhook"] != "https://real/hook" || got["secret"] != "REALSECRET" {
		t.Fatalf("masked fields must keep the original values from the store, got %v", got)
	}
	if got["method"] != "PUT" {
		t.Fatalf("the modified field must take effect, got %v", got["method"])
	}
}

func TestMergeConfigEmptyStringClears(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET"}
	got := MergeConfig(stored, map[string]any{"secret": ""})
	if _, ok := got["secret"]; ok {
		t.Fatalf("an empty string must clear the field, got %v", got)
	}
	// Fields not mentioned are preserved (partial update semantics).
	if got["webhook"] != "https://real/hook" {
		t.Fatalf("fields not mentioned must be kept, got %v", got)
	}
}

func TestMergeConfigKeepsUnmentionedStoredKeys(t *testing.T) {
	stored := map[string]any{"host": "smtp.example.com", "port": float64(587), "password": "pw"}
	got := MergeConfig(stored, map[string]any{"port": float64(465)})
	if got["host"] != "smtp.example.com" || got["password"] != "pw" {
		t.Fatalf("fields not mentioned must be kept, got %v", got)
	}
	if got["port"] != float64(465) {
		t.Fatalf("mentioned fields must be updated, got %v", got["port"])
	}
}

// TestPrepareConfigUpdateBlocksDestinationSwap is the most important security invariant in this package:
// **Changing the destination address must not carry over the old credentials.**
//
// These test cases use exactly the attack-shaped input (only the address is changed, with credentials left unmentioned),
// rather than "correct input for the defense logic". If we only tested the latter, the defense could be non-functional and the tests would still all pass.
func TestPrepareConfigUpdateBlocksDestinationSwap(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
		// wantMissing is the set of credential keys expected to be named.
		wantMissing string
	}{
		{
			name: "generic webhook changes address and wants to keep the Authorization header",
			kind: KindWebhook,
			stored: map[string]any{
				"url":     "https://legit.example.com/hook",
				"headers": map[string]any{"Authorization": "Bearer REAL-TOKEN"},
			},
			incoming:    map[string]any{"url": "https://attacker.tld/c"},
			wantMissing: "headers",
		},
		{
			name:        "Telegram changes base_url to send the bot token to its own endpoint",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld"},
			wantMissing: "bot_token",
		},
		{
			name:        "mail changes the SMTP host and would hand over the password",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"host": "smtp.attacker.tld"},
			wantMissing: "password",
		},
		{
			name:        "mail turning TLS off must restate the password",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "tls": false, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"tls": true},
			wantMissing: "password",
		},
		{
			// A masked value = "reuse the old credential", which must likewise be rejected in the context of an address change.
			name:        "masked credential returned plus a new address",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld", "bot_token": MaskedValue("123456:REAL")},
			wantMissing: "bot_token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err == nil {
				t.Fatalf("address changed without re-supplying credentials, so it should be rejected; got config %v", merged)
			}
			var target *ErrDestinationChangedWithoutCredentials
			if !errors.As(err, &target) {
				t.Fatalf("must return a dedicated error type so the API can give an actionable hint, got %T: %v", err, err)
			}
			found := false
			for _, m := range target.Missing {
				if m == tc.wantMissing {
					found = true
				}
			}
			if !found {
				t.Fatalf("must name the missing credential key %q, got %v", tc.wantMissing, target.Missing)
			}
			// Error messages must give the operator guidance on how to fix the problem.
			if !strings.Contains(err.Error(), tc.wantMissing) {
				t.Errorf("error message should mention %q: %v", tc.wantMissing, err)
			}
		})
	}
}

// TestPrepareConfigUpdateAllowsLegitimateEdits is the negative test case: ordinary edits must not be wrongly blocked,
// otherwise this guard will be bypassed or removed because it is "too annoying."
func TestPrepareConfigUpdateAllowsLegitimateEdits(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
	}{
		{
			name:     "name only (config returned unchanged)",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "headers": map[string]any{"Authorization": "Bearer REAL"}},
			incoming: map[string]any{"url": MaskedValue("https://legit.example.com/hook")},
		},
		{
			name:     "method only, address and credential untouched",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "method": "POST"},
			incoming: map[string]any{"method": "PUT"},
		},
		{
			name:     "change address and **also** supply a new credential",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": map[string]any{"Authorization": "Bearer NEW"}},
		},
		{
			name:     "change address and state explicitly that no credential is needed",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": ""},
		},
		{
			name:     "Telegram changes chat_id (not the destination)",
			kind:     KindTelegram,
			stored:   map[string]any{"bot_token": "t", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming: map[string]any{"chat_id": "-100200"},
		},
		{
			name:     "mail changes the recipient (not the destination)",
			kind:     KindEmail,
			stored:   map[string]any{"host": "smtp.corp.com", "port": 587, "password": "PW", "from": "a@b.c", "to": []any{"x@y.z"}},
			incoming: map[string]any{"to": []any{"new@y.z"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err != nil {
				t.Fatalf("valid edit was wrongly blocked: %v", err)
			}
			if merged == nil {
				t.Fatal("should return the merged result")
			}
		})
	}
}

// TestPrepareConfigUpdatePortTypeTolerance covers an easily misjudged detail:
// the frontend submits the port as a JSON number (float64), and the value read back from the database is also float64,
// but the two values may have different types (e.g., int vs. float64). Comparing them with == would judge "unchanged" as "changed,"
// and users who only changed their name would be prompted to "re-enter the password" — false alarms would make people stop trusting this guard.
func TestPrepareConfigUpdatePortTypeTolerance(t *testing.T) {
	stored := map[string]any{"host": "smtp.corp.com", "port": float64(587), "password": "PW"}
	// The same port, submitted in int form.
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 587}); err != nil {
		t.Fatalf("same port value (differing only in type) must not be judged as an address change: %v", err)
	}
	// A genuinely changed port must still be blocked.
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 25}); err == nil {
		t.Fatal("a port change must be blocked")
	}
}

// TestPrepareConfigUpdateSurvivesRepeatedSaveWithBlankDestination covers the path where a destination field may be left blank: Telegram's base_url left empty means the official API address is used.
// Telegram's base_url left empty means the official API address is used.
//
// This used to cause the channel to fail to save permanently starting from the second save:
//
//	When created, the database stores base_url:"" (the create path saves the config submitted by the frontend directly and does not go through MergeConfig)
//	→ First save: MergeConfig treats the empty string as an explicit clear and delete()s that key
//	→ On the second save, incoming is still "", but the key is no longer in stored, so it is judged as "the address changed"
//	→ bot_token is the masked echo value → 400 "destination address has changed, please re-enter the credential fields as well"
//
// The user changed nothing, yet from then on saving always failed, unless the Bot Token was pasted again.
func TestPrepareConfigUpdateSurvivesRepeatedSaveWithBlankDestination(t *testing.T) {
	stored := map[string]any{"bot_token": "123:ABC", "chat_id": "-100", "base_url": ""}

	// The frontend buildConfig() submits a value for every field definition of this channel: credential back-fill masks,
	// and empty text boxes submit empty strings. Here we fully reproduce its output, rather than submitting only the "changed keys".
	submit := func() map[string]any {
		return map[string]any{
			"bot_token": MaskedValue("123:ABC"),
			"chat_id":   "-100",
			"base_url":  "",
		}
	}

	// First save: only the channel name was changed, and config is echoed back unchanged.
	merged, err := PrepareConfigUpdate(KindTelegram, stored, submit())
	if err != nil {
		t.Fatalf("first save was wrongly blocked: %v", err)
	}
	if _, ok := merged["base_url"]; ok {
		t.Fatal("precondition changed: an empty string should be removed by MergeConfig; this case must cover the step after the key disappears")
	}

	// Second save: the submitted content is exactly the same as last time, and the user changed nothing.
	merged2, err := PrepareConfigUpdate(KindTelegram, merged, submit())
	if err != nil {
		t.Fatalf("second save was wrongly blocked (user changed nothing): %v", err)
	}
	// Third time, to confirm that it is not a "one-off error" but consistently saveable.
	if _, err := PrepareConfigUpdate(KindTelegram, merged2, submit()); err != nil {
		t.Fatalf("third save was wrongly blocked: %v", err)
	}
	// Credentials must be preserved all the way through, without being cleared along with the empty-string logic.
	if got := merged2["bot_token"]; got != "123:ABC" {
		t.Fatalf("Bot Token should keep its original value, got %v", got)
	}
}

// TestPrepareConfigUpdateStillGuardsBlankDestinationChanges is the counterpart of the previous test case.
// Assertion: treat an empty string and a "missing key" as equivalent, and **must not** let through genuine destination address changes.
// Both of these directions are real credential exfiltration paths: Telegram's Bot Token travels in the URL path,
// so changing base_url is equivalent to sending the Token to the new address.
func TestPrepareConfigUpdateStillGuardsBlankDestinationChanges(t *testing.T) {
	// Direction 1: changing from "empty" (the official address) to a self-hosted address.
	official := map[string]any{"bot_token": "123:ABC", "chat_id": "-100"}
	if _, err := PrepareConfigUpdate(KindTelegram, official, map[string]any{
		"bot_token": MaskedValue("123:ABC"),
		"base_url":  "https://tg-proxy.attacker.tld",
	}); err == nil {
		t.Fatal("switching from the official address to a self-hosted address must require re-entering the token")
	}

	// Direction 2: clearing the self-hosted address (= switching back to the official API) is likewise an address change.
	proxied := map[string]any{"bot_token": "123:ABC", "base_url": "https://proxy.internal/bot"}
	if _, err := PrepareConfigUpdate(KindTelegram, proxied, map[string]any{
		"bot_token": MaskedValue("123:ABC"),
		"base_url":  "",
	}); err == nil {
		t.Fatal("clearing the self-hosted address (switching back to the official API) is also an address change and must require re-entering the token")
	}
}

func TestDestinationKeysDeclaredForEveryKind(t *testing.T) {
	// Same reasoning as SecretKeys: if a channel forgets to declare its destination key, PrepareConfigUpdate cannot protect it.
	for kind, ch := range registry {
		if len(ch.DestinationKeys()) == 0 {
			t.Errorf("channel %s declares no destination keys, so the credential-carrying protection on address change is ineffective for it", kind)
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("channel %s declares no credential keys", kind)
		}
	}
}

func TestSecretKeysDeclaredForEveryKind(t *testing.T) {
	// The compiler already forces every channel to implement SecretKeys; this checks again that "no channel hands back a blank slate on masking"
	// — a channel that returns an empty slice means its credentials are echoed back to the browser in plaintext.
	expect := map[string]bool{
		KindWebhook: true, KindTelegram: true, KindEmail: true,
	}
	for kind, ch := range registry {
		if !expect[kind] {
			t.Errorf("channel %s has no expected mask registered in the test", kind)
			continue
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("channel %s declares no credential fields, so its config would be echoed in plaintext", kind)
		}
	}
}

// TestPrepareConfigUpdateRejectsMaskedInContainer covers a gap identified in the audit:
// When a masking sentinel is placed into a **non-string** structure (for example, when webhook.headers is an object),
// MergeConfig only recognizes a value as masked if it is a string with the prefix, so the literal "__masked__" would be treated as
// stored into the database as the real header value. Subsequent authentication then silently fails, with no error reported.
func TestPrepareConfigUpdateRejectsMaskedInContainer(t *testing.T) {
	stored := map[string]any{
		"url":     "https://legit.example.com/hook",
		"headers": map[string]any{"Authorization": "Bearer REAL"},
	}
	// a masking sentinel embedded inside an object.
	incoming := map[string]any{
		"headers": map[string]any{"Authorization": MaskedPrefix},
	}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, incoming); err == nil {
		t.Fatal("a sentinel mask embedded inside the struct must be rejected (otherwise the literal would be stored in the database)")
	}
	// Submitting the whole object (with real new values) is still accepted as usual.
	ok := map[string]any{"headers": map[string]any{"Authorization": "Bearer NEW"}}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, ok); err != nil {
		t.Fatalf("a normal submission of new headers must not be blocked: %v", err)
	}
}

// TestPrepareConfigUpdateReplacesEditedWebhookURL covers the edit the UI could not
// make: the webhook URL is both the destination and a credential, so it is masked in
// the API echo and the headers are masked too. Changing the URL therefore submitted a
// real new URL next to a masked header, which the guard rejected, leaving the address
// permanently uneditable. The new address must win, and the header that belonged to
// the old address must be dropped rather than carried over.
func TestPrepareConfigUpdateReplacesEditedWebhookURL(t *testing.T) {
	stored := map[string]any{
		"url":     "https://old.example.com/hook?token=OLD",
		"headers": map[string]any{"Authorization": "Bearer REAL"},
		"method":  "POST",
	}
	// Exactly what the form submits: the edited URL, the untouched header as the mask
	// it was shown as, and the other fields echoed back.
	incoming := map[string]any{
		"url":           "https://new.example.com/hook?token=NEW",
		"headers":       MaskedValue(`{"Authorization":"Bearer REAL"}`),
		"method":        "POST",
		"body_template": "",
	}
	merged, err := PrepareConfigUpdate(KindWebhook, stored, incoming)
	if err != nil {
		t.Fatalf("an edited webhook URL must be accepted, got %v", err)
	}
	if got := merged["url"]; got != "https://new.example.com/hook?token=NEW" {
		t.Fatalf("the edited URL must replace the stored one, got %v", got)
	}
	if _, ok := merged["headers"]; ok {
		t.Fatalf("the header belonged to the old address and must not travel to the new one, got %v", merged["headers"])
	}
}

// TestPrepareConfigUpdateKeepsUntouchedMaskedWebhookURL is the other half: a save that
// does not touch the URL keeps the stored address and the stored header.
func TestPrepareConfigUpdateKeepsUntouchedMaskedWebhookURL(t *testing.T) {
	stored := map[string]any{
		"url":     "https://old.example.com/hook?token=OLD",
		"headers": map[string]any{"Authorization": "Bearer REAL"},
		"method":  "POST",
	}
	incoming := map[string]any{
		"url":     MaskedValue("https://old.example.com/hook?token=OLD"),
		"headers": MaskedValue(`{"Authorization":"Bearer REAL"}`),
		"method":  "PUT",
	}
	merged, err := PrepareConfigUpdate(KindWebhook, stored, incoming)
	if err != nil {
		t.Fatalf("an untouched masked URL must keep the stored one, got %v", err)
	}
	if got := merged["url"]; got != "https://old.example.com/hook?token=OLD" {
		t.Fatalf("the masked URL must keep the stored address, got %v", got)
	}
	if _, ok := merged["headers"]; !ok {
		t.Fatal("an untouched masked header must keep the stored value")
	}
	if got := merged["method"]; got != "PUT" {
		t.Fatalf("the edited method must be applied, got %v", got)
	}
}

package infer

import (
	"encoding/json"
	"strings"
)

const redacted = "[redacted]"

// redactJSON masks secret-named keys and token-shaped values in a copy of raw.
// Opaque signed or encrypted state is never masked.
func redactJSON(raw []byte) ([]byte, error) {
	doc, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	for k, v := range doc {
		doc[k] = scrub(k, v)
	}
	return json.Marshal(doc)
}

func scrub(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			t[k] = scrub(k, c)
		}
		return t
	case []any:
		for i, c := range t {
			t[i] = scrub(key, c)
		}
		return t
	case string:
		if secretKey(key) || (!opaqueKeys[key] && secretValue(t)) {
			return redacted
		}
	}
	return v
}

var secretKeyParts = []string{
	"authorization", "cookie", "secret", "password", "api_key", "apikey", "api-key",
	"credential", "access_token", "refresh_token", "id_token", "bearer",
}

func secretKey(k string) bool {
	l := strings.ToLower(k)
	if l == "token" || strings.HasSuffix(l, "_token") || strings.HasSuffix(l, "-token") {
		return true
	}
	for _, p := range secretKeyParts {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func secretValue(s string) bool {
	l := strings.ToLower(s)
	if strings.HasPrefix(l, "bearer ") || strings.HasPrefix(l, "basic ") {
		return true
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return strings.HasPrefix(s, "sk-") || strings.HasPrefix(s, "ya29.")
}

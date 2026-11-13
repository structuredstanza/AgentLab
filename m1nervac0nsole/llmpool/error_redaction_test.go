package llmpool

import (
	"errors"
	"strings"
	"testing"
)

// The provider transport copies the upstream body into the error, and llmpool
// persists that string to llm_health and serves it to the UI as last_error, so
// anything the provider echoes back would be stored and displayed.
// The values below are synthetic: they match the scrub patterns, not a real key.
func TestTrimErrRedactsCredentialShapes(t *testing.T) {
	cases := []struct {
		name, in, secret string
	}{
		{
			"openai bad key",
			`openai: status 401: {"error":{"message":"Incorrect API key provided: sk-TESTKEY12345"}}`,
			"sk-TESTKEY12345",
		},
		{
			"bearer echo",
			`anthropic: status 401: invalid bearer sk-TESTBEARER123`,
			"sk-TESTBEARER123",
		},
		{
			"key query param",
			`gemini: status 400: bad request for https://x/v1?key=TESTQUERYPARAM12345`,
			"TESTQUERYPARAM12345",
		},
		{
			"api key field",
			`{"x-api-key":"TESTHEADERVALUE123"}`,
			"TESTHEADERVALUE123",
		},
	}
	for _, c := range cases {
		got := trimErr(errors.New(c.in))
		if strings.Contains(got, c.secret) {
			t.Errorf("%s: secret survived redaction: %q", c.name, got)
		}
		if !strings.Contains(got, "REDACTED") {
			t.Errorf("%s: no redaction marker in %q", c.name, got)
		}
	}

	// ordinary diagnostics must stay readable
	for _, keep := range []string{
		"openai: status 429: rate limit exceeded",
		"dial tcp 127.0.0.1:443: connect: connection refused",
		"anthropic: overloaded_error",
	} {
		if got := trimErr(errors.New(keep)); got != keep {
			t.Errorf("benign message altered: %q -> %q", keep, got)
		}
	}
}

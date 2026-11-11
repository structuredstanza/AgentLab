package db

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestScrubSecretsClasses covers every secret class the knowledge base and
// reflection pool must never store: credentials in headers, key=value pairs,
// tokens, keys, URL userinfo, cookies and opaque blobs. Every case asserts the
// exact output string: a scrubber that also mangles surrounding text (or drops
// the character before a key) must fail here, not just "the secret is gone".
//
// Fixtures are assembled from parts on purpose: no literal credential lives in
// this file.
func TestScrubSecretsClasses(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	privateKey := "-----BEGIN " + "RSA " + "PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA\n" +
		"-----END " + "RSA " + "PRIVATE KEY-----"
	hexBlob := strings.Repeat("ab12", 12)                                         // 48 hex chars
	b64Blob := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 24))) // 32 chars
	cases := []struct {
		name      string
		in        string
		want      string
		wantCount int
	}{
		{"authorization header", "Authorization: Bearer abcdef123456",
			"Authorization: <redacted>", 1},
		{"authorization equals", "authorization=token-value-here",
			"authorization=<redacted>", 1},
		{"bearer in prose", "send it with bearer abcdefgh12345678 please",
			"send it with bearer <redacted> please", 1},
		{"password pair keeps the preceding word", "login with password=hunter2 works",
			"login with password=<redacted> works", 1},
		{"passwd colon", "passwd: s3cr3t-value",
			"passwd: <redacted>", 1},
		{"secret pair", "client_secret: abc123xyz",
			"client_secret: <redacted>", 1},
		{"token pair", "token=xyzzy-1234",
			"token=<redacted>", 1},
		{"api key", "api_key=sk-live-abc123",
			"api_key=<redacted>", 1},
		{"apikey", "apikey=sk-live-def456",
			"apikey=<redacted>", 1},
		{"jwt", "cookie-less auth " + jwt,
			"cookie-less auth <redacted>", 1},
		{"aws access key", "key " + aws,
			"key <redacted>", 1},
		{"private key block", privateKey, "<redacted>", 1},
		{"url userinfo", "postgres://artex:s3cr3t@db.internal:5432/artex",
			"postgres://artex:<redacted>@db.internal:5432/artex", 1},
		{"cookie header", "Cookie: sid=abc123; theme=dark",
			"Cookie: <redacted>", 1},
		{"set-cookie header", "Set-Cookie: session=deadbeef",
			"Set-Cookie: <redacted>", 1},
		{"hex blob", "sha " + hexBlob,
			"sha <redacted>", 1},
		{"base64 blob", "payload " + b64Blob,
			"payload <redacted>", 1},
		// JSON-shaped input must stay JSON-shaped: the quotes are kept.
		{"json quoted key", `{"token":"abc123"}`,
			`{"token":"<redacted>"}`, 1},
		{"json spaced key", `{"password": "hunter2"}`,
			`{"password": "<redacted>"}`, 1},
		{"json authorization", `{"Authorization":"Bearer abc.def.ghi"}`,
			`{"Authorization":"<redacted>"}`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, n := ScrubSecrets(c.in)
			if n != c.wantCount {
				t.Fatalf("redactions = %d, want %d (%q -> %q)", n, c.wantCount, c.in, out)
			}
			if out != c.want {
				t.Fatalf("ScrubSecrets(%q) = %q, want %q", c.in, out, c.want)
			}
			// A second pass must find nothing: the placeholder is inert.
			if again, n := ScrubSecrets(out); n != 0 || again != out {
				t.Fatalf("second pass changed output (%d redactions): %q", n, again)
			}
		})
	}
}

// TestScrubSecretsBenignTextUnchanged guards against over-redaction of ordinary
// operational notes.
func TestScrubSecretsBenignTextUnchanged(t *testing.T) {
	for _, in := range []string{
		"",
		"GET /admin returned 403 after the WAF rule was enabled",
		"the login form reflects the next parameter into the error banner",
		"jwt is used for the session cookie",
	} {
		out, n := ScrubSecrets(in)
		if n != 0 || out != in {
			t.Fatalf("benign text rewritten (%d redactions): %q -> %q", n, in, out)
		}
	}
}

// TestScrubTargetIdentifiersGeneralises checks the promotion path: origin
// identifiers (including a host suffix), IP literals and emails are replaced,
// and unrelated text survives.
func TestScrubTargetIdentifiersGeneralises(t *testing.T) {
	in := "XSS on api.example.com and acme corp; host 10.1.2.3, v6 ::1, mail ops@other.org"
	out, n := ScrubTargetIdentifiers(in, []string{"example.com", "Acme Corp"})
	if n != 5 {
		t.Fatalf("redactions = %d, want 5: %q", n, out)
	}
	for _, leak := range []string{"example.com", "acme corp", "Acme Corp", "10.1.2.3", "::1", "ops@other.org"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(leak)) {
			t.Fatalf("%q leaked into %q", leak, out)
		}
	}
	for _, want := range []string{scrubTarget, scrubIP, scrubEmail} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s placeholder: %q", want, out)
		}
	}
}

// TestScrubTargetIdentifiersKeepsUnrelatedTargets makes sure a promotion only
// strips the origin task's identifiers, not every host it mentions.
func TestScrubTargetIdentifiersKeepsUnrelatedTargets(t *testing.T) {
	out, n := ScrubTargetIdentifiers("compare other.org with 10.1.2.3 at 12:30:45", []string{"example.com"})
	if n != 1 || !strings.Contains(out, "other.org") {
		t.Fatalf("unrelated host removed (%d redactions): %q", n, out)
	}
	if !strings.Contains(out, "12:30:45") {
		t.Fatalf("clock time was treated as an IPv6 literal: %q", out)
	}
	if !strings.Contains(out, scrubIP) {
		t.Fatalf("IPv4 literal survived: %q", out)
	}
}

// TestScrubTargetIdentifiersNoIdentifiers covers the operator generalisation
// path: with no origin task, only IP literals and emails are replaced.
func TestScrubTargetIdentifiersNoIdentifiers(t *testing.T) {
	out, n := ScrubTargetIdentifiers("203.0.113.9 reported by ops@corp.tld", nil)
	if n != 2 {
		t.Fatalf("redactions = %d, want 2: %q", n, out)
	}
	if out != "<ip> reported by <email>" {
		t.Fatalf("unexpected output: %q", out)
	}
}

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
		// A scheme name in a sentence is not a credential, but anything else
		// after "basic"/"bearer" is, including an all-lowercase token.
		{"basic scheme noun", "the endpoint accepts basic authentication",
			"the endpoint accepts basic authentication", 0},
		{"bearer scheme noun", "send bearer authorization",
			"send bearer authorization", 0},
		{"lowercase bearer token", "send bearer supersecrettoken",
			"send bearer <redacted>", 1},
		{"basic base64 credential", "basic dXNlcjpwYXNz",
			"basic <redacted>", 1},
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
		{"url userinfo", "postgres://m1nervac0nsole:s3cr3t@db.internal:5432/m1nervac0nsole",
			"postgres://m1nervac0nsole:<redacted>@db.internal:5432/m1nervac0nsole", 1},
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
	in := "XSS on api.example.com and acme corp; host 10.1.2.3, v6 2001:db8::5, mail ops@other.org"
	out, n := ScrubTargetIdentifiers(in, []string{"example.com", "Acme Corp"})
	if n != 5 {
		t.Fatalf("redactions = %d, want 5: %q", n, out)
	}
	for _, leak := range []string{"example.com", "acme corp", "Acme Corp", "10.1.2.3", "2001:db8::5", "ops@other.org"} {
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

// TestScrubKeepsTechniqueText is the live-data regression corpus: every line
// here was rewritten by an earlier scrubber, which turned scope operators into
// <ip>, cookie attributes into <redacted> and paths into opaque blobs. The
// knowledge base stores technique text, so losing these makes an entry
// unusable. Each case runs through both scrubbers and must come back intact.
func TestScrubKeepsTechniqueText(t *testing.T) {
	cases := []string{
		// PowerShell/C++ scope operators, and a Windows stream name.
		`[Convert]::ToBase64String($bytes)`,
		`[IO.File]::AppendAllText("a.txt", $x)`,
		`C:\Config.Msi::$INDEX_ALLOCATION`,
		`version()::int`,
		`std::string s;`,
		// A dotted number longer than a quad is an OID, not an address.
		`oid 1.3.6.1.4.1.9.9 in the tree`,
		`java v1.8.0.191 deployed`,
		// Loopback and unspecified addresses identify no target.
		`curl http://127.0.0.1:8080/admin`,
		`curl http://[::1]:8080/admin`,
		`bind 0.0.0.0:80`,
		// Scheme names, cookie attributes and routes are not credentials.
		`the endpoint accepts basic authentication`,
		`The endpoint accepts basic authentication.`,
		`Set-Cookie: lacks HttpOnly`,
		`Set-Cookie: Path=/; HttpOnly; SameSite=Lax`,
		`com/example/service/impl/HandlerFactoryImpl`,
		`com/Example/Service2/HandlerFactoryImpl`,
		`/api/v1/users/list/all/items/detail`,
		`/api/v2/UserManagement/ListAllGroups`,
		`users/admin/roles/permissions/groups/policies`,
		`12:30:45`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			out, n := ScrubSecrets(in)
			if n != 0 || out != in {
				t.Fatalf("ScrubSecrets rewrote technique text (%d redactions): %q -> %q", n, in, out)
			}
			out, n = ScrubTargetIdentifiers(in, nil)
			if n != 0 || out != in {
				t.Fatalf("ScrubTargetIdentifiers rewrote technique text (%d redactions): %q -> %q", n, in, out)
			}
		})
	}
}

// TestScrubStillCatchesSecretsAndTargets is the other half of the corpus: the
// precision rules above must not have opened a hole for the classes they
// neighbour, in the same sentence.
func TestScrubStillCatchesSecretsAndTargets(t *testing.T) {
	in := "std::string -> basic authentication; password=hunter2\n" +
		"bearer abcdefgh12345678\n" +
		"Set-Cookie: sid=abc123\n" +
		"loopback 127.0.0.1 and 0.0.0.0, target 203.0.113.9 and 2001:db8::5, " +
		"ops@corp.tld\n" +
		"the host is 198.51.100.7."
	out, n := ScrubSecrets(in)
	if n != 3 {
		t.Fatalf("secret redactions = %d, want 3: %q", n, out)
	}
	out, n = ScrubTargetIdentifiers(out, nil)
	if n != 4 {
		t.Fatalf("target redactions = %d, want 4: %q", n, out)
	}
	for _, gone := range []string{"hunter2", "abcdefgh12345678", "abc123", "203.0.113.9", "2001:db8::5", "198.51.100.7", "ops@corp.tld"} {
		if strings.Contains(out, gone) {
			t.Fatalf("%q survived: %q", gone, out)
		}
	}
	for _, kept := range []string{"std::string", "basic authentication", "127.0.0.1", "0.0.0.0"} {
		if !strings.Contains(out, kept) {
			t.Fatalf("%q was lost: %q", kept, out)
		}
	}
}

// TestScrubFailsClosed pins the cases where a precision rule has to lose: when
// technique text and a secret or a target look alike, the scrubber redacts.
// Fixtures are assembled from parts so no credential-shaped literal lives here.
func TestScrubFailsClosed(t *testing.T) {
	secrets := []struct{ name, in, want string }{
		// base64 contains slashes too; only word-shaped segments are a path.
		{"slash blob without a digit", "key " + "pvlXvlo/isqUgfZKww" + "AFPHbWfGovkvsd", "key <redacted>"},
		{"slash blob with plus", "key " + "pvlXvlo/isqUgfZKww" + "+FPHbWfGovkvsd", "key <redacted>"},
		{"bare cookie token", "Set-Cookie: " + "session-token-" + "9f8e7d6c", "Set-Cookie: <redacted>"},
		{"attribute before a cookie pair", "Set-Cookie: Path=/; sid=" + "abc123", "Set-Cookie: <redacted>"},
		{"lowercase bearer token with a full stop", "send bearer " + "supersecrettoken" + ".", "send bearer <redacted>"},
	}
	for _, c := range secrets {
		t.Run(c.name, func(t *testing.T) {
			if out, _ := ScrubSecrets(c.in); out != c.want {
				t.Fatalf("ScrubSecrets(%q) = %q, want %q", c.in, out, c.want)
			}
		})
	}
	targets := []struct{ name, in, want string }{
		// A flag or a keyword in front of an address must not shield it.
		{"verbose flag", "curl -v 203.0.113.9", "curl -v <ip>"},
		{"version keyword", "release 203.0.113.9 was vulnerable", "release <ip> was vulnerable"},
		// A bare four-part version cannot be told from an address.
		{"bare version quad", "build 1.8.0.191 deployed", "build <ip> deployed"},
	}
	for _, c := range targets {
		t.Run(c.name, func(t *testing.T) {
			if out, _ := ScrubTargetIdentifiers(c.in, nil); out != c.want {
				t.Fatalf("ScrubTargetIdentifiers(%q) = %q, want %q", c.in, out, c.want)
			}
		})
	}
}

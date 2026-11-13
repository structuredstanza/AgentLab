package notify

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// This file covers two related hardening measures:
//   ① Delivery addresses must not let the server be used as a springboard to attack the internal network / cloud metadata (SSRF)
//   ② Error messages from address validation must not leak credentials contained in the address
//
// About the test environment: many cases in this package use httptest fake receivers on 127.0.0.1, which the guard blocks by default.
// So TestMain turns on AllowLocalTargetsEnv globally, while every SSRF case below
// explicitly clears it, in order to assert the **default-deny** behavior.

func TestMain(m *testing.M) {
	// Regular cases can connect to the local fake receivers; SSRF cases clear it temporarily themselves.
	_ = os.Setenv(AllowLocalTargetsEnv, "1")
	os.Exit(m.Run())
}

// TestDialGuardRejectsLoopbackByDefault is the core assertion of the SSRF protection:
// Under the default configuration, delivery to a loopback address must be rejected at the **connection layer**.
func TestDialGuardRejectsLoopbackByDefault(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "") // Turning off the escape hatch = default behavior
	_, err := (webhookChannel{}).Send(context.Background(),
		map[string]any{"url": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("loopback addresses must not be allowed for delivery by default")
	}
	if hit {
		t.Fatal("request already reached the local service; the guard did not take effect")
	}
	// The error message should guide users on how to relax this (a local SMTP relay is a legitimate configuration).
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("rejection message should explain how to explicitly allow it: %v", err)
	}
}

// TestDialGuardAllowsLoopbackWhenOptedIn is the inverse case: once explicitly enabled, it must work,
// otherwise legitimate deployments such as a local postfix or an internal relay would be blanket-blocked.
func TestDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (webhookChannel{}).Send(context.Background(),
		map[string]any{"url": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("delivery should succeed after explicitly allowing it: %v", err)
	}
}

func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"169.254.169.254", // Cloud metadata endpoints — the main reason this function exists
		"169.254.1.1", "fe80::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", // IPv4-mapped forms must be unwrapped before checking, otherwise they are a bypass
		"",
	}
	for _, s := range blocked {
		if !isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be rejected", s)
		}
	}
	// RFC1918 private networks are deliberately allowed: self-hosted Mattermost on the internal network and SMTP relays are common, legitimate uses.
	// This assertion locks in that trade-off. If someone later adds a private-address check in passing, this will fail,
	// forcing a deliberate decision rather than silently breaking a batch of deployments.
	allowed := []string{"10.0.0.5", "172.16.3.4", "192.168.1.10", "8.8.8.8", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed (private networks are a common legitimate delivery target)", s)
		}
	}
}

// TestValidateHTTPURLRejectsLiteralPrivateTargets covers the upfront hint at config time:
// a literal IP should be rejected at save time, rather than waiting for the first delivery to fail.
func TestValidateHTTPURLRejectsLiteralPrivateTargets(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/hook",
	} {
		if err := validateHTTPURL(raw); err == nil {
			t.Errorf("%s should be rejected at config time", raw)
		}
	}
	// Public and private addresses both pass as usual (private ones are left to the dial stage, which does not block them).
	for _, raw := range []string{"https://oapi.dingtalk.com/robot/send", "http://10.0.0.9/hook"} {
		if err := validateHTTPURL(raw); err != nil {
			t.Errorf("%s should pass validation: %v", raw, err)
		}
	}
}

// TestValidateHTTPURLErrorNeverLeaksCredentials covers the branch that my previous round missed, as the audit pointed out.
//
// When url.Parse **fails**, it returns a *url.Error whose Error() includes the full raw URL. In the previous round, I only
// Desensitized the error returned by http.Client.Do; this spot was missed. Meanwhile, the "permanent failure path" test case added at that time
// (file://, gopher://, ftp://) all actually parse successfully with url.Parse and go down the scheme branch,
// so all-green doesn't prove this path is safe either — it's a false guarantee.
func TestValidateHTTPURLErrorNeverLeaksCredentials(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/%zz?access_token=" + leakProbeToken,         // Invalid percent-encoding
		"https://a.example.com:port/x?access_token=" + leakProbeToken, // Non-numeric port
		"http://[::1?access_token=" + leakProbeToken,                  // Unmatched brackets
	}
	for _, raw := range cases {
		// First confirm that this input **actually** makes url.Parse fail. Without this step, the test case may
		// silently take a different branch (the previous round's false guarantee came from exactly this).
		if _, err := url.Parse(raw); err == nil {
			t.Errorf("%q should have failed to parse, otherwise this case does not cover the target branch", raw)
			continue
		}
		err := validateHTTPURL(raw)
		if err == nil {
			t.Errorf("%q should fail validation", raw)
			continue
		}
		assertNoSecret(t, err.Error(), leakProbeToken)
	}
	// Confirm that the channel-layer wrapper does not leak the address either.
	t.Setenv(AllowLocalTargetsEnv, "")
	err := (webhookChannel{}).Validate(map[string]any{"url": cases[0]})
	if err == nil {
		t.Fatal("invalid address should fail validation")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestEmailDialGuardRejectsLoopbackByDefault covers the dial guard of the SMTP channel.
//
// The email channel used to rely on a bare net.Dialer, which was the only gap in the entire SSRF protection: the host could be set to
// 169.254.169.254 or 127.0.0.1 and connect directly, and when the smtp.NewClient handshake failed, the peer's returned line was wrapped into the error
// and echoed back through the delivery history API via last_error, which is the same half-blind read primitive that other channels had already closed off; the timing difference between "connection refused" and "timeout" could also be used to probe ports.
// A semi-blind read primitive that has already been turned off; the timing difference between "connection refused" and "timeout" can still be used to probe ports.
//
// This package's TestMain globally enables AllowLocalTargetsEnv (many test cases use a fake receiver on 127.0.0.1),
// so this test case must clear it itself; otherwise the guard would pass whether or not it is present,
// This is also exactly why the gap was never caught by any test.
func TestEmailDialGuardRejectsLoopbackByDefault(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "") // Turning off the escape hatch = default behavior
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil {
		t.Fatal("by default, delivering email to loopback addresses must not be allowed")
	}
	// The connection should never have been established at all: the guard intercepts it in the Control hook, so EHLO is never sent.
	if f.sawCommand("EHLO") || f.sawCommand("HELO") {
		t.Fatal("SMTP session was established; the guard did not take effect")
	}
	// The error message should tell the user how to lift the restriction (a local postfix relay is a legitimate configuration).
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("rejection message should explain how to explicitly allow it: %v", err)
	}
}

// TestEmailDialGuardAllowsLoopbackWhenOptedIn is the paired inverse case: once explicitly enabled,
// delivery must succeed normally. Self-hosted SMTP on an internal network or a local relay is a very common deployment, so the guard must not be a blanket block.
func TestEmailDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("local SMTP should be deliverable after explicitly allowing it: %v", err)
	}
	if !f.sawCommand("EHLO") {
		t.Fatal("EHLO was not seen; the session was not actually established")
	}
}

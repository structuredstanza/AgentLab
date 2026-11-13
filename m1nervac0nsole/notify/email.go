package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// emailDialTimeout / emailSessionTimeout bound the connection setup and the entire SMTP session, respectively.
// net/smtp itself has no timeout mechanism at all. Without these two limits, a stuck peer would leave the
// delivery goroutine hanging there forever, and since the dispatcher processes work serially on a single goroutine,
// ...which would bring down the entire notification system.
const (
	emailDialTimeout    = 10 * time.Second
	emailSessionTimeout = 45 * time.Second
)

// emailChannel implements SMTP email delivery.
type emailChannel struct{}

func (emailChannel) Kind() string { return KindEmail }

// Email has no platform-imposed rate limit, but it should not be used to spam; set a lenient default.
func (emailChannel) DefaultRatePerMin() int { return 60 }

// Only the password is masked. The SMTP host, account, and recipients are not secrets, and masking them would only make editing harder.
func (emailChannel) SecretKeys() []string { return []string{"password"} }

// host/port determine which server the password is handed to; tls determines whether transport is encrypted. Changing any one of the three
// Requires re-entering the password. This also ensures that the step "disable TLS" must explicitly carry the credentials, rather than being changed casually as a side effect.
func (emailChannel) DestinationKeys() []string { return []string{"host", "port", "tls"} }

func (emailChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "host") == "" {
		return errors.New("SMTP server address is missing")
	}
	port := cfgInt(cfg, "port")
	if port <= 0 || port > 65535 {
		return errors.New("SMTP port is invalid (must be in the range 1-65535)")
	}
	if cfgString(cfg, "from") == "" {
		return errors.New("sender address is missing")
	}
	if len(cfgStrings(cfg, "to")) == 0 {
		return errors.New("at least one recipient address is required")
	}
	return nil
}

func (c emailChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	host := cfgString(cfg, "host")
	port := cfgInt(cfg, "port")
	from := cfgString(cfg, "from")
	to := cfgStrings(cfg, "to")
	username := cfgString(cfg, "username")
	password := cfgString(cfg, "password")
	implicitTLS := cfgBool(cfg, "tls")

	msg, err := buildEmailMessage(from, to, m)
	if err != nil {
		return 0, Permanent(err)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := emailDial(ctx, addr, host, implicitTLS)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// STARTTLS: upgrade if the peer supports it. Credentials must not be sent over a plaintext session (see the auth note below).
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return 0, fmt.Errorf("STARTTLS failed: %w", err)
			}
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			// smtp.PlainAuth refuses to send credentials over an unencrypted connection (unless the target is localhost).
			// This is the correct security behavior and must not be bypassed, but the reason needs to be explained clearly——
			// Otherwise, users would only see "unencrypted connection" and have no idea what to do.
			if strings.Contains(err.Error(), "unencrypted connection") {
				return 0, Permanent(fmt.Errorf("refusing to send credentials: the connection is not encrypted. Enable TLS, use port 465 (implicit TLS), or check 'Use TLS' (%w)", err))
			}
			return 0, Permanent(fmt.Errorf("SMTP authentication failed: %w", err))
		}
	}
	if err := client.Mail(from); err != nil {
		return 0, smtpStageError(fmt.Sprintf("sender address %s was rejected", from), err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return 0, smtpStageError(fmt.Sprintf("recipient address %s was rejected", rcpt), err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return 0, fmt.Errorf("failed to write message body: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("message submission failed: %w", err)
	}
	// A failure in Quit does not change the fact that "the mail was accepted by the server," so its error is ignored.
	_ = client.Quit()
	// There is no length truncation for the mail (the entire HTML body is sent), so the whole batch counts as delivered.
	return len(m.Items), nil
}

// emailDial establishes the SMTP connection.
//
// implicitTLS=true uses the "TLS on connect" approach, as with port 465; false connects in plaintext on 25/587 and then
// STARTTLS. The two cannot be mixed: sending a plaintext greeting to port 465 will get the connection dropped immediately.
//
// The session deadline is set at the point of connection (rather than being patched in afterward), because net/smtp's Client holds the underlying
// The connection is hidden in an unexported field, so external callers cannot access it. Once the connection is handed out, the only safeguard is the deadline set beforehand.
// as a fallback. This also incidentally covers blocking during the handshake phase.
// Control installs blockInternalDial, sharing the same guard as HTTP-based channels. Without it, SMTP
// would be a gap in the entire SSRF protection: setting host to 169.254.169.254 or 127.0.0.1 would connect directly,
// when smtp.NewClient handshake fails, it wraps the single line returned by the peer into the error, which then goes out via last_error
// through last_error by the delivery history API, forming a semi-blind read primitive. The timing difference between "connection refused" and "timeout" could also be
// used to probe ports. The dial stage is the final point of enforcement, and it also covers DNS rebinding.
func emailDial(ctx context.Context, addr, host string, implicitTLS bool) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: emailDialTimeout, Control: blockInternalDial}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP handshake failed: %w", err)
	}
	return client, nil
}

// smtpStageError classifies a failure in a given stage as either "retryable" or "permanent failure" based on the SMTP reply code.
//
// Why we must distinguish: SMTP 4xx and 5xx responses mean completely different things——
//   - 4xx (450 greylisting, 451 local error, 452 insufficient storage) is a **temporary** rejection;
//     the correct handling is to retry later. Greylisting in particular is hit on almost every first delivery attempt.
//   - 5xx (550 user unknown, 553 invalid address) is a permanent rejection; retrying is pointless.
//
// If every such response were treated as a permanent failure, a mail server with greylisting enabled would send **every** push into failed after its first attempt——
// Failing after a try lands in failed, yet this kind of failure is exactly where automatic retry should earn its keep.
// The reply code is taken from the first three digits of the error text; if no code can be parsed, treat the failure as retryable (better to try one more time
// than to mark a possibly transient fault as dead just because parsing failed).
func smtpStageError(what string, err error) error {
	code := smtpReplyCode(err.Error())
	if code >= 500 && code < 600 {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	return fmt.Errorf("%s: %w", what, err)
}

// smtpReplyCode extracts the leading three-digit reply code from an SMTP error text, and returns 0 if none can be found.
// net/smtp does not export an error code field, so it can only be extracted from the text; the format is "450 4.7.1 ...".
func smtpReplyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	n, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return n
}

// buildEmailMessage assembles a complete RFC 5322 email.
//
// The body is encoded in base64 for two reasons: first, SMTP requires each line to be no longer than 1000 bytes, and HTML
// bodies (especially summary emails) very easily contain overly long lines; second, base64 never produces lines starting with ".",
// which avoids the hassle of SMTP dot-stuffing.
func buildEmailMessage(from string, to []string, m Message) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	// Chinese subjects must be RFC 2047-encoded, otherwise they will be displayed as garbled text by mail clients.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", htmlTitle(m)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	// The email has no hard length limit, so the body is not truncated.
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody(m, 0)))
	// base64 is line-wrapped at 76 characters, per RFC 2045.
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String(), nil
}

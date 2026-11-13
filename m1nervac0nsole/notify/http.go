package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets determines whether delivering messages to loopback / link-local addresses is allowed.
//
// It is denied by default. These address ranges are not where IM bots or public email servers would ever live, and what they can reach
// is sensitive: the management ports of other services on the same machine, as well as the cloud metadata endpoint
// (169.254.169.254, which can expose instance credentials). The delivery address is configured by the administrator, but if an XSS/CSRF
// hijacked via XSS/CSRF, or a second person sharing the same JWT, could change the configuration to read response content back
// — doJSON writes the first 200 bytes of 4xx/5xx response bodies into last_error, and the delivery history endpoint
// It echoes it back, which makes this a semi-blind read primitive.
//
// However, a "local SMTP relay" (postfix on 127.0.0.1:25) is a common setup for self-hosted mail,
// so a blanket ban would block people. Instead of hardcoding an allow, we provide an explicit escape hatch:
// setting M1NERVAC0NSOLE_NOTIFY_ALLOW_LOCAL=1 enables it.
//
// It is exported as AllowLocalTargetsEnv so that tests can turn it on explicitly. Test cases in this package and the server package
// make heavy use of httptest fake receivers on 127.0.0.1; without enabling it, all of them would be blocked by the guard.
const AllowLocalTargetsEnv = "M1NERVAC0NSOLE_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP reports whether the target IP falls into an address range that is blocked for delivery by default.
//
// It only rejects loopback, link-local (including the cloud metadata address 169.254.169.254), unspecified, and multicast addresses.
// **Does not reject** RFC1918 private networks: self-hosted Mattermost / SMTP relays on an internal network are a very common and legitimate setup,
// Blocking them as well would make the feature outright unusable in real environments. This trade-off is deliberate——
// The guard must block truly sensitive targets without breaking normal deployments along with them.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) must be unwrapped to IPv4 before checking, otherwise the check is bypassed.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the Control hook of the http.Transport dialer, and checks the target address **at connection establishment**
// Check the target address.
//
// Why it is set at the dial stage rather than only validating when the config is saved: this is the point where it actually takes effect.
// It also covers two cases that bypass config validation: DNS rebinding (resolving to a public IP at validation time,
// when actually connecting it resolves to the internal network) and redirects (although we already reject cross-host redirects, a same-host redirect
// may still point the path somewhere else).
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot resolve target address: %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("refusing to send to local or link-local address %s (to send to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport builds on the default Transport and adds only one dial guard.
// Clone preserves all of the defaults' tuning (connection pool, HTTP/2, timeouts, proxy, etc.),
// so that behavior is not changed just to add one check.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is the client shared by all channel deliveries.
//
// Deliberately does **not** reuse the project's global egress proxy (the GlobalProxy on the server side): that proxy is meant for penetration
// target traffic and is often an unstable tunnel, and the availability of notifications should not be held hostage by fluctuations in the target network.
// Connect directly for IM push. Timeout is set to 15 seconds; a peer slower than that is effectively in a faulty state.
//
// Reject cross-host redirects. Delivery addresses for this feature are always a single fixed endpoint, so normally a redirect
// to a different host should never occur. The credentials (a webhook query token, a Telegram bot token) **are contained in the URL**,
// so following a cross-host redirect would hand the credentials to the redirect target. Same-host
// redirects (such as adding a trailing slash) are still allowed.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("redirects to other hosts are not allowed (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit caps how much of the response body is read. A misbehaving peer may return oversized content, while we only need
// the error code and a short error description to display in the delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns the response body (size-limited).
//
// When payload is nil, send an empty body (for GET or for platforms that do not require a body).
// Header keys and values in headers are appended as-is, for custom headers on the generic webhook.
//
// Error classification is the core responsibility of this function: network-level failures and 5xx/408/429 are classified as "retryable,"
// All other 4xx responses are classified as "permanent failure" — retrying a 403 only repeats the same error and writes it to the log 3 times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// A serialization failure is a local bug (a configuration field has the wrong type), and retrying will not make it succeed.
			return nil, Permanent(fmt.Errorf("failed to create request body: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// An invalid URL most likely means the user entered the address incorrectly, so it is a permanent failure.
		// Here too, err must not be passed through: the error text from url.Parse contains the full address.
		return nil, Permanent(fmt.Errorf("request address is invalid: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	useragent.SetIfAbsent(req.Header.Set, req.Header.Get("User-Agent"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refused, DNS failure, and timeouts are mostly transient faults, so they are left to backoff retry.
		//
		// Error text must be sanitized before it is passed outward. Reason: http.Client.Do returns a *url.Error,
		// Its Error() is `Op "full URL": underlying error`, and these providers' credentials are **in the URL itself**
		// (a webhook query token, Telegram /bot<token>/).
		// Without sanitization, the credentials would leak through this error string to four places: notification_deliveries
		// last_error (stored in plaintext in the database), the response of the delivery history API (**bypassing the channel configuration mask**),
		// server logs, and the 502 text returned to the frontend by the test-send API.
		return nil, fmt.Errorf("request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429 (rate limiting) and 408 (timeout) are worth retrying; other 4xx errors are configuration or permission issues, so retrying is pointless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("remote server is rate-limiting or responding slowly (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("remote server error (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("remote server rejected the request (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// validateHTTPURL checks that the address is usable and uses a supported protocol, and for literal IP targets it determines whether they are on an internal network.
//
// Two points deserve care:
//
//  1. **Error messages must be redacted.** url.Parse itself returns a *url.Error, whose Error() includes
//     **the complete original address**, but addresses here embed credentials (a webhook query token, a Telegram bot token).
//     Previously this place did `return err` directly,
//     so the error "invalid address format" carried the credentials out: into the 400 response of the test endpoint,
//     the last_error persisted on each delivery attempt, server logs, and the delivery history API.
//
//  2. **Literal IP addresses are judged as internal directly**; domain names are left for the dial stage to judge (blockInternalDial is the real
//     enforcement point, and it also covers DNS rebinding). Doing this check here is so that a warning can be given when the configuration is saved,
//     rather than waiting until the first delivery fails.
//
// Restricting protocols is defensive: schemes such as file:/// and gopher:// could cause http.Client to behave unexpectedly
// (although they are already blocked by the scheme check, there is no reason to open up this surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("cannot parse address (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http or https is supported; received: %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("host name is missing")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("refusing to send to local or link-local address %s (to send to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// snippet compresses the response body into a single line of short text, used for error messages. The response may contain newlines and a lot of whitespace,
// Stuffing this directly into last_error would break the layout of the delivery history page.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget reduces the delivery address to "scheme://host/…" for use in error messages.
//
// This is the only address-redaction policy in this package, and it is deliberately **very blunt**: apart from the scheme and host,
// everything else is discarded. The reason is that there is no "general and safe" way to tell which part of a URL holds the credential:
//
//	a webhook  credential is commonly in the query  /hook?token=xxx
//	Telegram   credential is in the **middle of the path** /bot<token>/sendMessage
//
// Trying to "keep only the useful part" would mean writing a patch for each channel, and missing even one of them is a credential leak.
// Keeping the host is enough for troubleshooting (DNS resolution failures, connection failures, and certificate mismatches can all be located),
// Which bot it is can be identified by the masked tail-digit hint in the channel configuration.
//
// On parse failure, return a fixed placeholder — never echo the original string back out.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(address cannot be resolved)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips the address from transport-layer errors, keeping only the underlying cause.
//
// The structure of *url.Error is {Op, URL, Err}, and Error() prints the URL along with everything else.
// Here the Err field is accessed explicitly, bypassing its Error() method — this is more reliable than doing string replacement afterward,
// Replacement has to handle the many variants that appear after URL encoding/escaping, so it's easy to miss cases.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: unknown error", uerr.Op, host)
	}
	// A non-*url.Error (such as an error returned by a redirect policy) may also carry an address, so it is also routed through redaction.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces http(s) addresses appearing in a piece of text with their redacted form.
//
// Used as a fallback for errors that do not expose structured fields (redirect policy errors, custom errors from third-party libraries).
// Only the http/https prefixes are recognized, and text is split on whitespace and quotes, since addresses never contain either kind of character.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

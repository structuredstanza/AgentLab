// Package nativeproxy is the console-side HTTP client for the host native proxy.
// Provider credentials never enter this process: the host holds the private
// per-profile stores and this client only carries bearer-authenticated
// control and inference requests to it.
package nativeproxy

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
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	envURL       = "M1NERVAC0NSOLE_NATIVE_PROXY_URL"
	envTokenFile = "M1NERVAC0NSOLE_NATIVE_PROXY_TOKEN_FILE"

	maxJSONBody           = 1 << 20
	maxErrorBody          = 64 << 10
	MaxInferenceBodyBytes = 8 << 20
)

var (
	safeToken = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	safeID    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Client talks to one native proxy. The zero value is not usable; build it with New or NewFromEnv.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// Error is a non-2xx native proxy response. Code is a safe machine code, never provider prose.
type Error struct {
	Op     string
	Status int
	Code   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("native proxy %s failed: status %d: %s", e.Op, e.Status, e.Code)
}

// LoginSession is the native proxy view of an interactive login.
type LoginSession struct {
	SessionID        string       `json:"session_id"`
	Status           string       `json:"status"`
	AuthorizationURL string       `json:"authorization_url,omitempty"`
	Instructions     string       `json:"instructions,omitempty"`
	Progress         string       `json:"progress,omitempty"`
	Prompt           *LoginPrompt `json:"prompt,omitempty"`
	Email            string       `json:"email,omitempty"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty"`
	Error            string       `json:"error,omitempty"`
}

// LoginPrompt asks the human user for input at the login prompt.
type LoginPrompt struct {
	Message     string `json:"message"`
	Placeholder string `json:"placeholder,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	AllowEmpty  bool   `json:"allow_empty,omitempty"`
}

// ProfileStatus is local grant metadata only.
type ProfileStatus struct {
	Connected bool       `json:"connected"`
	Email     string     `json:"email,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Model is one entry of the native proxy's local catalog. SupportedEfforts is always sent by the proxy:
// an empty list means the model takes no reasoning effort.
type Model struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ContextWindow    *int     `json:"context_window"`
	SupportedEfforts []string `json:"supported_efforts"`
}

// New builds a client for the native proxy at rawURL authenticated with token.
// The proxy is never consulted, so proxy traffic cannot be redirected by environment proxies.
func New(rawURL, token string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("native proxy URL is invalid")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("native proxy URL must be an http(s) origin without credentials, query or fragment")
	}
	if token == "" {
		return nil, errors.New("native proxy token is empty")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	tr := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		// A hosted provider returns response headers almost immediately. A local model
		// does not: it prefills the whole prompt before the first frame, which on a long
		// conversation takes minutes. Aborting at 60s failed turns that were progressing.
		ResponseHeaderTimeout: headerTimeout(),
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{base: u, token: token, http: &http.Client{Transport: tr}}, nil
}

// NewFromEnv returns nil and no error when M1NERVAC0NSOLE_NATIVE_PROXY_URL is unset: the proxy is unavailable.
// It reads only M1NERVAC0NSOLE_NATIVE_PROXY_URL and the token file named by M1NERVAC0NSOLE_NATIVE_PROXY_TOKEN_FILE.
// headerTimeout bounds how long the proxy may take to start a stream. A local model
// prefills before its first token, so this has to accommodate the whole prompt, not
// just the connection; M1NERVAC0NSOLE_NATIVE_PROXY_HEADER_TIMEOUT_SECONDS overrides it.
func headerTimeout() time.Duration {
	const fallback = 300 * time.Second
	raw := strings.TrimSpace(os.Getenv("M1NERVAC0NSOLE_NATIVE_PROXY_HEADER_TIMEOUT_SECONDS"))
	if raw == "" {
		return fallback
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

func NewFromEnv() (*Client, error) {
	rawURL := os.Getenv(envURL)
	if rawURL == "" {
		return nil, nil
	}
	path := os.Getenv(envTokenFile)
	if path == "" {
		return nil, fmt.Errorf("%s is required when %s is set", envTokenFile, envURL)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("native proxy token file is unreadable")
	}
	return New(rawURL, strings.TrimSpace(string(raw)))
}

// Start begins an interactive login for profileID with provider.
func (c *Client) Start(ctx context.Context, profileID, provider string) (LoginSession, error) {
	var out LoginSession
	err := c.doJSON(ctx, "login_start", http.MethodPost, profilePath(profileID)+"/login/start", map[string]string{"provider": provider}, &out)
	if err != nil {
		return LoginSession{}, err
	}
	if err := validID(out.SessionID); err != nil {
		return LoginSession{}, err
	}
	return out, nil
}

// Poll returns the current state of a login session.
func (c *Client) Poll(ctx context.Context, profileID, sessionID string) (LoginSession, error) {
	if err := validID(sessionID); err != nil {
		return LoginSession{}, err
	}
	var out LoginSession
	err := c.doJSON(ctx, "login_poll", http.MethodGet, profilePath(profileID)+"/login/"+url.PathEscape(sessionID), nil, &out)
	if err != nil {
		return LoginSession{}, err
	}
	switch out.Status {
	case "pending", "complete", "error", "cancelled":
	default:
		return LoginSession{}, errors.New("native proxy returned an unknown login status")
	}
	return out, nil
}

// Input answers a login prompt.
func (c *Client) Input(ctx context.Context, profileID, sessionID, value string) error {
	if err := validID(sessionID); err != nil {
		return err
	}
	return c.doJSON(ctx, "login_input", http.MethodPost, profilePath(profileID)+"/login/"+url.PathEscape(sessionID)+"/input", map[string]string{"value": value}, nil)
}

// Cancel cancels a login session.
func (c *Client) Cancel(ctx context.Context, profileID, sessionID string) error {
	if err := validID(sessionID); err != nil {
		return err
	}
	return c.doJSON(ctx, "login_cancel", http.MethodDelete, profilePath(profileID)+"/login/"+url.PathEscape(sessionID), nil, nil)
}

// Status reports local grant metadata for provider.
func (c *Client) Status(ctx context.Context, profileID, provider string) (ProfileStatus, error) {
	var out ProfileStatus
	err := c.doJSON(ctx, "status", http.MethodGet, profilePath(profileID)+"/status?provider="+url.QueryEscape(provider), nil, &out)
	return out, err
}

// Disconnect removes the profile grant after the proxy drains in-flight work.
func (c *Client) Disconnect(ctx context.Context, profileID string) error {
	return c.doJSON(ctx, "disconnect", http.MethodDelete, profilePath(profileID)+"/grant", nil, nil)
}

// Models returns the native proxy's root-local catalog for provider. It needs no profile,
// so model discovery works before login.
func (c *Client) Models(ctx context.Context, provider string) ([]Model, error) {
	var out struct {
		Models []Model `json:"models"`
	}
	err := c.doJSON(ctx, "models", http.MethodGet, "/v1/models?provider="+url.QueryEscape(provider), nil, &out)
	return out.Models, err
}

// Infer posts a native inference request body and returns the NDJSON stream.
// The caller owns the response and must close its body. Non-2xx responses return *Error.
func (c *Client) Infer(ctx context.Context, profileID string, body json.RawMessage) (*http.Response, error) {
	if len(body) > MaxInferenceBodyBytes {
		return nil, errors.New("native proxy inference body exceeds 8 MiB")
	}
	req, err := c.newRequest(ctx, http.MethodPost, profilePath(profileID)+"/infer", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("native proxy request failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, proxyError("infer", resp)
	}
	return resp, nil
}

// VerifyReplay checks signed native state locally without inference or refresh.
func (c *Client) VerifyReplay(ctx context.Context, profileID string, body json.RawMessage) error {
	if len(body) > MaxInferenceBodyBytes {
		return errors.New("native replay verification request is too large")
	}
	return c.doJSON(ctx, "replay_verify", http.MethodPost, profilePath(profileID)+"/replay/verify", body, nil)
}

func (c *Client) doJSON(ctx context.Context, op, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("native proxy request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return proxyError(op, resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxJSONBody))
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody))
	if err := dec.Decode(out); err != nil {
		return errors.New("native proxy returned malformed JSON")
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := *c.base
	rel, err := url.Parse(path)
	if err != nil {
		return nil, errors.New("native proxy path is invalid")
	}
	u.Path = c.base.Path + rel.Path
	u.RawPath = c.base.Path + rel.EscapedPath()
	u.RawQuery = rel.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errors.New("native proxy request is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	useragent.SetIfAbsent(req.Header.Set, req.Header.Get("User-Agent"))
	return req, nil
}

func proxyError(op string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	code := "proxy_error"
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil && safeToken.MatchString(env.Error.Code) {
		code = env.Error.Code
	}
	return &Error{Op: op, Status: resp.StatusCode, Code: code}
}

// profilePath escapes profileID as a single path segment; an unsafe ID never reaches the URL.
func profilePath(profileID string) string {
	return "/v1/profiles/" + url.PathEscape(profileID)
}

func validID(id string) error {
	if !safeID.MatchString(id) {
		return errors.New("native proxy identifier is invalid")
	}
	return nil
}

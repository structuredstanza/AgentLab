// Package sdkbridge is the ARTEX-side HTTP client for the host SDK bridge.
// Provider credentials never enter this process: the bridge holds the private
// per-profile SDK stores and this client only carries bearer-authenticated
// control and inference requests to it.
package sdkbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	envURL       = "ARTEX_SDK_BRIDGE_URL"
	envTokenFile = "ARTEX_SDK_BRIDGE_TOKEN_FILE"

	maxJSONBody  = 1 << 20
	maxErrorBody = 64 << 10
)

var (
	safeToken = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	safeID    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Client talks to one SDK bridge. The zero value is not usable; build it with New or NewFromEnv.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// Error is a non-2xx bridge response. Code is a safe machine code, never provider prose.
type Error struct {
	Op     string
	Status int
	Code   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("sdk bridge %s failed: status %d: %s", e.Op, e.Status, e.Code)
}

// LoginSession is the bridge view of an interactive login.
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

// Model is one entry of the bridge's local catalog. SupportedEfforts is always sent by the bridge:
// an empty list means the model takes no reasoning effort.
type Model struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ContextWindow    *int     `json:"context_window"`
	SupportedEfforts []string `json:"supported_efforts"`
}

// New builds a client for the bridge at rawURL authenticated with token.
// The proxy is never consulted, so bridge traffic cannot be redirected by environment proxies.
func New(rawURL, token string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("sdk bridge URL is invalid")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("sdk bridge URL must be an http(s) origin without credentials, query or fragment")
	}
	if token == "" {
		return nil, errors.New("sdk bridge token is empty")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{base: u, token: token, http: &http.Client{Transport: tr}}, nil
}

// NewFromEnv returns nil and no error when ARTEX_SDK_BRIDGE_URL is unset: the bridge is unavailable.
// It reads only ARTEX_SDK_BRIDGE_URL and the token file named by ARTEX_SDK_BRIDGE_TOKEN_FILE.
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
		return nil, errors.New("sdk bridge token file is unreadable")
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
		return LoginSession{}, errors.New("sdk bridge returned an unknown login status")
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

// Disconnect removes the profile grant after the bridge drains in-flight work.
func (c *Client) Disconnect(ctx context.Context, profileID string) error {
	return c.doJSON(ctx, "disconnect", http.MethodDelete, profilePath(profileID)+"/grant", nil, nil)
}

// Models returns the bridge's local catalog for provider.
func (c *Client) Models(ctx context.Context, profileID, provider string) ([]Model, error) {
	var out struct {
		Models []Model `json:"models"`
	}
	err := c.doJSON(ctx, "models", http.MethodGet, profilePath(profileID)+"/models?provider="+url.QueryEscape(provider), nil, &out)
	return out.Models, err
}

// Infer posts a native inference request body and returns the NDJSON stream.
// The caller owns the response and must close its body. A non-2xx response is returned as *Error.
func (c *Client) Infer(ctx context.Context, profileID string, body json.RawMessage) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodPost, profilePath(profileID)+"/infer", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("sdk bridge request failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, bridgeError("infer", resp)
	}
	return resp, nil
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
		return errors.New("sdk bridge request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return bridgeError(op, resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxJSONBody))
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody))
	if err := dec.Decode(out); err != nil {
		return errors.New("sdk bridge returned malformed JSON")
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := *c.base
	rel, err := url.Parse(path)
	if err != nil {
		return nil, errors.New("sdk bridge path is invalid")
	}
	u.Path = c.base.Path + rel.Path
	u.RawPath = c.base.Path + rel.EscapedPath()
	u.RawQuery = rel.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errors.New("sdk bridge request is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

func bridgeError(op string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	code := "bridge_error"
	var env struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil && safeToken.MatchString(env.Error) {
		code = env.Error
	}
	return &Error{Op: op, Status: resp.StatusCode, Code: code}
}

// profilePath escapes profileID as a single path segment; an unsafe ID never reaches the URL.
func profilePath(profileID string) string {
	return "/v1/profiles/" + url.PathEscape(profileID)
}

func validID(id string) error {
	if !safeID.MatchString(id) {
		return errors.New("sdk bridge identifier is invalid")
	}
	return nil
}

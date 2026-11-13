package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type loginRunner struct{ cfg *sdkconfig.Config }

func (r loginRunner) Run(ctx context.Context, profile contract.ProfileID, provider contract.Provider, authorizationURL func(string) error, progress func(string), prompt func(string) (string, error)) (*contract.Record, error) {
	if _, err := contract.ParseProfileID(string(profile)); err != nil {
		return nil, err
	}
	var authn sdkauth.Authenticator
	switch provider {
	case contract.ProviderClaude:
		authn = sdkauth.NewClaudeAuthenticator()
	case contract.ProviderCodex:
		authn = sdkauth.NewCodexAuthenticator()
	case contract.ProviderAntigravity:
		authn = sdkauth.NewAntigravityAuthenticator()
	default:
		return nil, errors.New("unsupported provider")
	}
	opts := &sdkauth.LoginOptions{
		NoBrowser: true,
		AuthorizationURL: func(raw string) error {
			if !validAuthorizationOrigin(provider, raw) {
				return errors.New("authorization URL origin rejected")
			}
			return authorizationURL(raw)
		},
		Progress: progress,
		Prompt: func(message string) (string, error) {
			value, err := prompt(message)
			if err != nil || strings.TrimSpace(value) == "" {
				return value, err
			}
			if !validCallbackOrigin(provider, value) {
				return "", errors.New("OAuth callback origin rejected")
			}
			return value, nil
		},
	}
	auth, err := authn.Login(ctx, r.cfg, opts)
	if err != nil {
		return nil, err
	}
	if auth == nil || auth.Provider != string(provider) {
		return nil, errors.New("native authenticator returned an invalid record")
	}
	raw, err := rawAuth(auth)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errors.New("native authenticator returned invalid metadata")
	}
	id, err := newCoreAuthID()
	if err != nil {
		return nil, err
	}
	rec := &contract.Record{CoreAuthID: id, Raw: raw}
	rec.Email, _ = fields["email"].(string)
	if rec.Email == "" {
		rec.Email, _ = fields["account_email"].(string)
	}
	if expiry, ok := fields["expired"].(string); ok {
		rec.ExpiresAt, _ = time.Parse(time.RFC3339, expiry)
	}
	if rec.ExpiresAt.IsZero() {
		if expiry, ok := auth.ExpirationTime(); ok {
			rec.ExpiresAt = expiry
		}
	}
	return rec, nil
}

func rawAuth(auth *coreauth.Auth) ([]byte, error) {
	var value any = auth.Metadata
	if auth.Storage != nil {
		value = auth.Storage
	}
	if value == nil {
		return nil, errors.New("native authenticator returned no credential metadata")
	}
	return json.Marshal(value)
}

func newCoreAuthID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate core auth id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func validAuthorizationOrigin(provider contract.Provider, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Port() != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	wantHost, wantPath := "", ""
	switch provider {
	case contract.ProviderClaude:
		wantHost, wantPath = "claude.ai", "/oauth/authorize"
	case contract.ProviderCodex:
		wantHost, wantPath = "auth.openai.com", "/oauth/authorize"
	case contract.ProviderAntigravity:
		wantHost, wantPath = "accounts.google.com", "/o/oauth2/v2/auth"
	default:
		return false
	}
	return strings.EqualFold(u.Hostname(), wantHost) && u.Path == wantPath
}

func validCallbackOrigin(provider contract.Provider, raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return true
	}
	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		if strings.HasPrefix(candidate, "?") || strings.Contains(candidate, "=") && !strings.ContainsAny(candidate, "/#") {
			candidate = "http://localhost/" + strings.TrimPrefix(candidate, "?")
		} else {
			candidate = "http://" + candidate
		}
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host != "localhost" && host != "127.0.0.1" && host != "[::1]" && host != "::1" {
		return false
	}
	ports := map[contract.Provider]string{
		contract.ProviderClaude:      "54545",
		contract.ProviderCodex:       "1455",
		contract.ProviderAntigravity: "51121",
	}
	port := u.Port()
	return port == "" || port == ports[provider]
}

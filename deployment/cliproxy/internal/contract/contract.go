// Package contract holds the host-internal interfaces shared by slices. Every
// slice codes against these types; changing one is an integration decision.
package contract

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"
)

// Provider is one of the enabled providers. Claude, Codex and Antigravity are
// subscription providers backed by OAuth grants. Local is a model hosted on the
// operator's own machine: it has no grant to refresh, but routing it through the
// host keeps every outbound model request under one policy, one capture and one
// cache decision instead of leaving a second, uncontrolled egress.
type Provider string

const (
	ProviderClaude      Provider = "claude"
	ProviderCodex       Provider = "codex"
	ProviderAntigravity Provider = "antigravity"
	ProviderLocal       Provider = "local"
)

// ParseProvider accepts only the canonical lowercase names.
func ParseProvider(s string) (Provider, bool) {
	switch Provider(s) {
	case ProviderClaude, ProviderCodex, ProviderAntigravity, ProviderLocal:
		return Provider(s), true
	}
	return "", false
}

// RequiresGrant reports whether the provider authenticates with a stored grant.
// A local provider does not: it is configured by the host, not logged in to.
func RequiresGrant(p Provider) bool { return p != ProviderLocal }

// ProfileID is a canonical positive decimal of at most 19 digits, no leading zero.
type ProfileID string

var profileIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// ErrBadProfileID is returned for any non-canonical profile identifier.
var ErrBadProfileID = errors.New("invalid profile id")

// ParseProfileID validates a profile path segment before any lookup.
func ParseProfileID(s string) (ProfileID, error) {
	if !profileIDPattern.MatchString(s) {
		return "", ErrBadProfileID
	}
	return ProfileID(s), nil
}

// Record is one provider grant for one profile. Raw is the native auth JSON
// exactly as the core store expects it; it never leaves the host.
type Record struct {
	CoreAuthID string // opaque core auth identifier, derived from profile and provider
	Email      string
	ExpiresAt  time.Time
	Raw        []byte
}

// Store persists grants privately under the host root. Save is atomic
// (temp file + rename) and rejects a stale generation.
type Store interface {
	Load(ctx context.Context, profile ProfileID, provider Provider) (*Record, error)
	// Save replaces the grant only if expectedGen matches the stored generation
	// (0 means "no grant yet"). Returns the new generation.
	Save(ctx context.Context, profile ProfileID, provider Provider, expectedGen uint64, rec *Record) (uint64, error)
	// DeleteAll removes every provider grant for the profile.
	DeleteAll(ctx context.Context, profile ProfileID) error
	// Generation reports the stored generation of one grant, used to reject a
	// refresh that would overwrite a grant saved by someone else.
	Generation(profile ProfileID, provider Provider) (uint64, error)
}

// Lifecycle serializes per-profile login, cancel, refresh and disconnect.
type Lifecycle interface {
	StartLogin(ctx context.Context, profile ProfileID, provider Provider) (sessionID string, err error)
	LoginView(profile ProfileID, sessionID string) (LoginView, error)
	SubmitInput(profile ProfileID, sessionID string, value string) error
	CancelLogin(profile ProfileID, sessionID string) error
	// Disconnect cancels pending logins, drains inference and refresh, then deletes.
	Disconnect(ctx context.Context, profile ProfileID) error
}

// LoginStatus is the public login state.
type LoginStatus string

const (
	LoginPending   LoginStatus = "pending"
	LoginComplete  LoginStatus = "complete"
	LoginError     LoginStatus = "error"
	LoginCancelled LoginStatus = "cancelled"
)

// LoginPrompt asks the human user for input during login.
type LoginPrompt struct {
	Message     string `json:"message"`
	Placeholder string `json:"placeholder,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	AllowEmpty  bool   `json:"allow_empty,omitempty"`
}

// LoginView is the body of GET /v1/profiles/{id}/login/{sid}.
type LoginView struct {
	Status           LoginStatus  `json:"status"`
	AuthorizationURL string       `json:"authorization_url,omitempty"`
	Instructions     string       `json:"instructions,omitempty"`
	Progress         string       `json:"progress,omitempty"`
	Prompt           *LoginPrompt `json:"prompt,omitempty"`
	Email            string       `json:"email,omitempty"`
	ExpiresAt        string       `json:"expires_at,omitempty"`
	Error            string       `json:"error,omitempty"`
}

// Model is one entry of the embedded local catalog.
type Model struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ContextWindow    int      `json:"context_window"`
	SupportedEfforts []string `json:"supported_efforts"`
}

// Catalog answers pre-login, from the embedded catalog only.
type Catalog interface {
	Models(provider Provider) ([]Model, error)
}

// Window is one usage window of the existing allocation recipes.
type Window struct {
	ID                string  `json:"id"`
	Label             string  `json:"label"`
	UsedFraction      float64 `json:"used_fraction"`
	RemainingFraction float64 `json:"remaining_fraction"`
	ResetsAt          *string `json:"resets_at"`
}

// UsageReport is the body of GET /v1/profiles/{id}/usage.
type UsageReport struct {
	Provider  Provider `json:"provider"`
	Plan      *string  `json:"plan"`
	FetchedAt string   `json:"fetched_at"`
	Windows   []Window `json:"windows"`
}

// Usage runs the guarded host-only allocation recipe for one provider.
type Usage interface {
	Usage(ctx context.Context, profile ProfileID, provider Provider) (UsageReport, error)
}

// Policy is the outbound admission/capture decorator installed once per process.
// It wraps the transport selected by the native executor.
type Policy func(next http.RoundTripper) http.RoundTripper

// Receipts signs and verifies opaque replay receipts with the host private key.
type Receipts interface {
	// Sign binds an admitted native assistant state to provider/model/profile/session/grant.
	Sign(b Binding, state []byte) (string, error)
	// Verify returns nil only when the receipt covers exactly this state and binding.
	Verify(receipt string, b Binding, state []byte) error
}

// Binding is the exact identity a replay receipt is bound to. CredentialID is
// the host-only grant epoch ID, stable across refresh and changed on re-login.
type Binding struct {
	Provider     Provider
	Model        string
	Profile      ProfileID
	SessionID    string
	CredentialID string
}

// ErrDenied is returned by admission for any policy rejection. Its message is fixed
// and never echoes the offending payload.
var ErrDenied = errors.New("outbound request denied by policy")

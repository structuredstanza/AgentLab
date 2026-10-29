package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sdkbridge"
)

// Subscription login is proxied to the host SDK bridge. The bridge holds the
// per-profile grants and login sessions; ARTEX only binds them to the
// authenticated LLM profile and never sees provider credentials.

var errSDKUnavailable = errors.New("SDK login bridge is unavailable")

// sdkStatusTimeout bounds the readiness check run on every profile resolution.
const sdkStatusTimeout = 3 * time.Second

// newSDKBridge returns nil when the bridge is not configured or unreadable;
// API-key operation must keep working in that case.
func newSDKBridge() *sdkbridge.Client {
	c, err := sdkbridge.NewFromEnv()
	if err != nil {
		log.Printf("[sdk] login bridge disabled: %v", err)
		return nil
	}
	return c
}

// sdkProvider maps an ARTEX auth method to the bridge provider ID. It returns
// "" for API-key profiles. Callers never choose the provider ID.
func sdkProvider(authMethod string) string {
	switch authMethod {
	case "claude_code":
		return "anthropic"
	case "codex":
		return "openai-codex"
	case "antigravity":
		return "google-antigravity"
	}
	return ""
}

// sdkProfileStatus reads local grant metadata of an SDK-backed profile.
func (s *Server) sdkProfileStatus(ctx context.Context, p *db.LLMProfile) (sdkbridge.ProfileStatus, error) {
	if s.sdk == nil {
		return sdkbridge.ProfileStatus{}, errSDKUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, sdkStatusTimeout)
	defer cancel()
	return s.sdk.Status(ctx, strconv.FormatInt(p.ID, 10), sdkProvider(p.AuthMethod))
}

// profileUsable reports whether a profile can serve requests right now. SDK
// readiness is the bridge's local Connected flag, never a Postgres grant read.
func (s *Server) profileUsable(p *db.LLMProfile) bool {
	if p == nil || s == nil {
		return false
	}
	if p.AuthMethod == "api_key" {
		return p.APIKey != ""
	}
	st, err := s.sdkProfileStatus(context.Background(), p)
	return err == nil && st.Connected
}

// sdkOAuthProfile loads the path profile and rejects API-key profiles and an
// unavailable bridge. It writes the error response itself when it returns false.
func (s *Server) sdkOAuthProfile(w http.ResponseWriter, r *http.Request) (*db.LLMProfile, bool) {
	pg := s.pg(w)
	if pg == nil {
		return nil, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid LLM profile id")
		return nil, false
	}
	p, err := pg.ProfileByID(id)
	if err != nil {
		writeErr(w, 500, "could not load LLM profile")
		return nil, false
	}
	if p == nil {
		writeErr(w, 404, "LLM profile not found")
		return nil, false
	}
	if sdkProvider(p.AuthMethod) == "" {
		writeErr(w, 400, "subscription login is only available for OAuth profiles")
		return nil, false
	}
	if s.sdk == nil {
		writeErr(w, 503, errSDKUnavailable.Error())
		return nil, false
	}
	return p, true
}

// writeSDKErr maps bridge failures to safe messages. Provider or bridge prose
// never reaches the UI, and SDK errors are not treated as ARTEX logout (401).
func writeSDKErr(w http.ResponseWriter, err error) {
	var be *sdkbridge.Error
	if errors.As(err, &be) && be.Status == http.StatusNotFound {
		writeErr(w, 404, "login session not found")
		return
	}
	writeErr(w, 502, "SDK login bridge request failed")
}

func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sdkOAuthProfile(w, r)
	if !ok {
		return
	}
	sess, err := s.sdk.Start(r.Context(), strconv.FormatInt(p.ID, 10), sdkProvider(p.AuthMethod))
	if err != nil {
		writeSDKErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": sess.SessionID, "status": "pending"})
}

// sdkLoginView is the UI contract for a login session. Bridge Error prose is
// replaced with a fixed message.
type sdkLoginView struct {
	Status           string                 `json:"status"`
	AuthorizationURL string                 `json:"authorization_url,omitempty"`
	Instructions     string                 `json:"instructions,omitempty"`
	Progress         string                 `json:"progress,omitempty"`
	Prompt           *sdkbridge.LoginPrompt `json:"prompt,omitempty"`
	Email            string                 `json:"email,omitempty"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	Error            string                 `json:"error,omitempty"`
}

func (s *Server) oauthPoll(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sdkOAuthProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := decode(r, &body); err != nil || body.SessionID == "" {
		writeErr(w, 400, "session_id is required")
		return
	}
	sess, err := s.sdk.Poll(r.Context(), strconv.FormatInt(p.ID, 10), body.SessionID)
	if err != nil {
		writeSDKErr(w, err)
		return
	}
	view := sdkLoginView{
		Status: sess.Status, AuthorizationURL: sess.AuthorizationURL, Instructions: sess.Instructions,
		Progress: sess.Progress, Prompt: sess.Prompt, Email: sess.Email, ExpiresAt: sess.ExpiresAt,
	}
	if sess.Error != "" {
		view.Error = "login failed"
	}
	writeJSON(w, 200, view)
}

func (s *Server) oauthInput(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sdkOAuthProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
		Value     string `json:"value"`
	}
	if err := decode(r, &body); err != nil || body.SessionID == "" {
		writeErr(w, 400, "session_id is required")
		return
	}
	if err := s.sdk.Input(r.Context(), strconv.FormatInt(p.ID, 10), body.SessionID, body.Value); err != nil {
		writeSDKErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) oauthCancel(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sdkOAuthProfile(w, r)
	if !ok {
		return
	}
	if err := s.sdk.Cancel(r.Context(), strconv.FormatInt(p.ID, 10), r.PathValue("session_id")); err != nil {
		writeSDKErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "cancelled"})
}

func (s *Server) oauthDisconnect(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sdkOAuthProfile(w, r)
	if !ok {
		return
	}
	if err := s.sdk.Disconnect(r.Context(), strconv.FormatInt(p.ID, 10)); err != nil {
		writeSDKErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// disconnectSDKProfile drops the bridge grant of an SDK profile whose binding is
// going away. Callers MUST NOT change the DB row unless this returns nil, so no
// active grant is left unmanaged.
func (s *Server) disconnectSDKProfile(ctx context.Context, id int64) error {
	if s.sdk == nil {
		return errSDKUnavailable
	}
	return s.sdk.Disconnect(ctx, strconv.FormatInt(id, 10))
}

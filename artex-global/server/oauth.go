package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/nativeproxy"
)

// Subscription login is proxied to the host native proxy. The proxy holds the
// per-profile grants and login sessions; ARTEX only binds them to the
// authenticated LLM profile and never sees provider credentials.

var errNativeProxyUnavailable = errors.New("native proxy login is unavailable")

// nativeProxyStatusTimeout bounds the readiness check run on every profile resolution.
const nativeProxyStatusTimeout = 3 * time.Second

// newNativeProxy returns nil when the native proxy is not configured or unreadable;
// API-key operation must keep working in that case.
func newNativeProxy() *nativeproxy.Client {
	c, err := nativeproxy.NewFromEnv()
	if err != nil {
		log.Printf("[nativeproxy] login proxy disabled: %v", err)
		return nil
	}
	return c
}

// nativeProxyProvider maps an ARTEX auth method to the native proxy provider ID. It returns
// "" for API-key profiles. Callers never choose the provider ID.
func nativeProxyProvider(authMethod string) string {
	switch authMethod {
	case "claude_code":
		return "claude"
	case "codex":
		return "codex"
	case "antigravity":
		return "antigravity"
	}
	return ""
}

// nativeProxyProfileStatus reads local grant metadata of a native-proxy-backed profile.
func (s *Server) nativeProxyProfileStatus(ctx context.Context, p *db.LLMProfile) (nativeproxy.ProfileStatus, error) {
	if s.nativeProxy == nil {
		return nativeproxy.ProfileStatus{}, errNativeProxyUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, nativeProxyStatusTimeout)
	defer cancel()
	return s.nativeProxy.Status(ctx, strconv.FormatInt(p.ID, 10), nativeProxyProvider(p.AuthMethod))
}

// profileUsable reports whether a profile can serve requests right now. Native proxy
// readiness is the proxy's local Connected flag, never a Postgres grant read.
func (s *Server) profileUsable(p *db.LLMProfile) bool {
	if p == nil || s == nil {
		return false
	}
	if p.Format == "ollama" {
		return true
	}
	if p.AuthMethod == "api_key" {
		return p.APIKey != ""
	}
	st, err := s.nativeProxyProfileStatus(context.Background(), p)
	return err == nil && st.Connected
}

// nativeProxyOAuthProfile loads the path profile and rejects API-key profiles and an
// unavailable native proxy. It writes the error response itself when it returns false.
func (s *Server) nativeProxyOAuthProfile(w http.ResponseWriter, r *http.Request) (*db.LLMProfile, bool) {
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
	if nativeProxyProvider(p.AuthMethod) == "" {
		writeErr(w, 400, "subscription login is only available for OAuth profiles")
		return nil, false
	}
	if s.nativeProxy == nil {
		writeErr(w, 503, errNativeProxyUnavailable.Error())
		return nil, false
	}
	return p, true
}

// writeNativeProxyErr maps native proxy failures to safe messages. Provider or proxy prose
// never reaches the UI, and native proxy errors are not treated as ARTEX logout (401).
func writeNativeProxyErr(w http.ResponseWriter, err error) {
	var be *nativeproxy.Error
	if errors.As(err, &be) && be.Status == http.StatusNotFound {
		writeErr(w, 404, "login session not found")
		return
	}
	writeErr(w, 502, "native proxy request failed")
}

func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	p, ok := s.nativeProxyOAuthProfile(w, r)
	if !ok {
		return
	}
	sess, err := s.nativeProxy.Start(r.Context(), strconv.FormatInt(p.ID, 10), nativeProxyProvider(p.AuthMethod))
	if err != nil {
		writeNativeProxyErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": sess.SessionID, "status": "pending"})
}

// nativeProxyLoginView is the UI contract for a login session. Native proxy Error prose is
// replaced with a fixed message.
type nativeProxyLoginView struct {
	Status           string                   `json:"status"`
	AuthorizationURL string                   `json:"authorization_url,omitempty"`
	Instructions     string                   `json:"instructions,omitempty"`
	Progress         string                   `json:"progress,omitempty"`
	Prompt           *nativeproxy.LoginPrompt `json:"prompt,omitempty"`
	Email            string                   `json:"email,omitempty"`
	ExpiresAt        *time.Time               `json:"expires_at,omitempty"`
	Error            string                   `json:"error,omitempty"`
}

func (s *Server) oauthPoll(w http.ResponseWriter, r *http.Request) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	p, ok := s.nativeProxyOAuthProfile(w, r)
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
	sess, err := s.nativeProxy.Poll(r.Context(), strconv.FormatInt(p.ID, 10), body.SessionID)
	if err != nil {
		writeNativeProxyErr(w, err)
		return
	}
	if sess.Status == "complete" && s.oauthApplied[p.ID] != body.SessionID {
		s.invalidateProfileAgents()
		if err := s.reapplyActiveProfileLocked(); err != nil {
			writeErr(w, 503, "Login completed, but the selected LLM runtime is unavailable")
			return
		}
		if s.oauthApplied == nil {
			s.oauthApplied = make(map[int64]string)
		}
		s.oauthApplied[p.ID] = body.SessionID
	}
	view := nativeProxyLoginView{
		Status: sess.Status, AuthorizationURL: sess.AuthorizationURL, Instructions: sess.Instructions,
		Progress: sess.Progress, Prompt: sess.Prompt, Email: sess.Email, ExpiresAt: sess.ExpiresAt,
	}
	if sess.Error != "" {
		view.Error = "login failed"
	}
	writeJSON(w, 200, view)
}

func (s *Server) oauthInput(w http.ResponseWriter, r *http.Request) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	p, ok := s.nativeProxyOAuthProfile(w, r)
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
	if err := s.nativeProxy.Input(r.Context(), strconv.FormatInt(p.ID, 10), body.SessionID, body.Value); err != nil {
		writeNativeProxyErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) oauthCancel(w http.ResponseWriter, r *http.Request) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	p, ok := s.nativeProxyOAuthProfile(w, r)
	if !ok {
		return
	}
	if err := s.nativeProxy.Cancel(r.Context(), strconv.FormatInt(p.ID, 10), r.PathValue("session_id")); err != nil {
		writeNativeProxyErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "cancelled"})
}

func (s *Server) oauthDisconnect(w http.ResponseWriter, r *http.Request) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	p, ok := s.nativeProxyOAuthProfile(w, r)
	if !ok {
		return
	}
	err := s.nativeProxy.Disconnect(r.Context(), strconv.FormatInt(p.ID, 10))
	s.invalidateProfileAgents()
	delete(s.oauthApplied, p.ID)
	runtimeErr := s.reapplyActiveProfileLocked()
	if err != nil {
		writeNativeProxyErr(w, err)
		return
	}
	if runtimeErr != nil && !errors.Is(runtimeErr, errLLMProfileUnavailable) {
		writeErr(w, 503, "Login disconnected, but the selected LLM runtime could not be reconciled")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// disconnectNativeProxyProfile drops the native proxy grant of a native-proxy profile whose binding is
// going away. Callers MUST NOT change the DB row unless this returns nil, so no
// active grant is left unmanaged.
func (s *Server) disconnectNativeProxyProfile(ctx context.Context, id int64) error {
	if s.nativeProxy == nil {
		return errNativeProxyUnavailable
	}
	return s.nativeProxy.Disconnect(ctx, strconv.FormatInt(id, 10))
}

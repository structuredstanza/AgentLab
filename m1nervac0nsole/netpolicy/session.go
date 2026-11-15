package netpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Caller is the subsystem asking for a session. The purposes a caller may
// request are fixed here, so a subsystem cannot promote itself to one it does
// not run, and no tool argument reaches the decision.
type Caller string

const (
	// CallerAgent is planner/worker tool execution. It always has a task.
	CallerAgent Caller = "agent"
	// CallerChat is a conversation, task-bound or unbound.
	CallerChat Caller = "chat"
	// CallerCurator is the Tool Curator ingest/install flow.
	CallerCurator Caller = "curator"
)

// callerPurposes is the capability matrix. A caller that asks for a purpose
// outside its row is refused, never downgraded.
var callerPurposes = map[Caller][]Purpose{
	CallerAgent:   {PurposeResearch, PurposeTesting},
	CallerChat:    {PurposeResearch, PurposeTesting},
	CallerCurator: {PurposeInstall},
}

// Issuer builds sessions from server-side rows. The task and conversation come
// from the caller's own state, never from a tool argument, and the session
// carries the task's current policy revision.
type Issuer struct{ src Source }

// NewIssuer returns the session issuer for a policy source.
func NewIssuer(src Source) *Issuer { return &Issuer{src: src} }

// Issue returns a session for one task-bound or unbound conversation.
//
// Testing requires a task: the grant a session is judged against hangs off a
// task row, so an unbound session would have nothing to authorize it. Install is
// operator/curator-initiated rather than task-scoped and is judged by the
// public-destination rule, so it is issued without one. An unbound conversation
// otherwise gets research only.
func (i *Issuer) Issue(ctx context.Context, caller Caller, taskID, conversationID int64, p Purpose) (Session, error) {
	purposes, ok := callerPurposes[caller]
	if !ok {
		return Session{}, fmt.Errorf("netpolicy: unknown caller %q", string(caller))
	}
	if !slices.Contains(purposes, p) {
		return Session{}, fmt.Errorf("netpolicy: caller %q may not request purpose %q", string(caller), string(p))
	}
	if taskID <= 0 && p != PurposeResearch && p != PurposeInstall {
		return Session{}, fmt.Errorf("netpolicy: purpose %q requires a task", string(p))
	}
	if i == nil || i.src == nil {
		return Session{}, errors.New("netpolicy: no policy source configured")
	}
	st, err := i.src.PolicyState(ctx, Session{TaskID: taskID, ConversationID: conversationID, Purpose: p})
	if err != nil {
		return Session{}, fmt.Errorf("netpolicy: issue session: %w", err)
	}
	id, err := newSessionID()
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID:             id,
		TaskID:         taskID,
		ConversationID: conversationID,
		Purpose:        p,
		Revision:       st.Revision,
	}, nil
}

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("netpolicy: session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ProxyURL returns the proxy URL a run's tool environment carries: addr with the
// session credential as its user name, which is how the gateway resolves the
// session a proxied request runs under. It returns "" when the session has no
// credential or addr is empty, so a run with no session gets no proxy at all
// rather than a bare address the gateway would refuse.
//
// This is the only place a tool-facing proxy URL is built: every spawn site
// (Bash env, WebFetch, Chromium, the custom http tool, a manifest run) calls it
// with the session of the run it belongs to, never a process-wide address.
//
// An address that already carries a user part is returned unchanged, and so is a
// socks5 one: those are the operator's own proxy credentials (for socks5, SOCKS
// auth), and the gateway address has neither.
func ProxyURL(s Session, addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.TrimSpace(s.Credential) == "" {
		return ""
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.User != nil || strings.HasPrefix(u.Scheme, "socks") {
		return u.String()
	}
	u.User = url.User(s.Credential)
	return u.String()
}

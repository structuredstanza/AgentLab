package netpolicy

import (
	"context"
	"fmt"
	"net"
)

// Store is the DB-backed Authorizer. It loads the session's policy state
// through a Source and judges the destination. There is no decision cache: the
// state is read on every call, so a verdict computed from an earlier read could
// only outlive the state it was judged under - a revoke, or another task's
// target set changing, would be served stale.
//
// A session that claims a revision the database does not have is refused:
// revisions only move forward, so that session is forged or the database was
// rolled back.
type Store struct {
	src Source
}

// NewAuthorizer returns the DB-backed authorizer for a policy source.
func NewAuthorizer(src Source) *Store {
	return &Store{src: src}
}

// Authorize implements Authorizer for the policy stage, before any name is
// resolved.
func (a *Store) Authorize(ctx context.Context, s Session, d Destination) Decision {
	return a.authorize(ctx, s, d, nil, false)
}

// AuthorizeResolved is the dns stage: the caller resolved the destination and
// passes every A/AAAA answer, so an exclusion covering one of them, a mixed
// answer set, or a research destination that resolves into a private or target
// address is refused before the dial.
//
// It is deliberately not part of the Authorizer interface: the interface is the
// pre-resolution question, and a caller that has resolved holds the addresses.
func (a *Store) AuthorizeResolved(ctx context.Context, s Session, d Destination, addrs []net.IP) Decision {
	return a.authorize(ctx, s, d, addrs, false)
}

// AuthorizeRecorded checks a task-recorded mapping without letting a hostname
// grant stand in for approval of the addresses the task claims.
func (a *Store) AuthorizeRecorded(ctx context.Context, s Session, d Destination, addrs []net.IP) Decision {
	return a.authorize(ctx, s, d, addrs, true)
}

func (a *Store) authorize(ctx context.Context, s Session, d Destination, addrs []net.IP, recorded bool) Decision {
	st, refusal := a.load(ctx, s)
	if refusal != nil {
		return *refusal
	}
	return decide(s.Purpose, st, d, addrs, recorded)
}

// load reads the session's state and applies the checks that must precede any
// verdict. A nil refusal means the state may be judged.
func (a *Store) load(ctx context.Context, s Session) (State, *Decision) {
	if a == nil || a.src == nil {
		d := refuse(StagePolicy, "no policy source configured")
		return State{}, &d
	}
	st, err := a.src.PolicyState(ctx, s)
	if err != nil {
		d := refuse(StagePolicy, "policy unavailable: "+err.Error())
		return State{}, &d
	}
	if s.Revision > st.Revision {
		d := refuse(StagePolicy, fmt.Sprintf("session revision %d is ahead of the stored policy revision %d", s.Revision, st.Revision))
		return State{}, &d
	}
	return st, nil
}

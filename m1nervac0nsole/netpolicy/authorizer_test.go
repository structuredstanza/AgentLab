package netpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// scriptedSource returns its states in call order, repeating the last one, so a
// test can prove the state is loaded on every call.
type scriptedSource struct {
	states []State
	err    error
	calls  int
}

func (s *scriptedSource) PolicyState(context.Context, Session) (State, error) {
	s.calls++
	if s.err != nil {
		return State{}, s.err
	}
	if len(s.states) == 0 {
		return State{}, nil
	}
	i := s.calls - 1
	if i >= len(s.states) {
		i = len(s.states) - 1
	}
	return s.states[i], nil
}

func TestAuthorizeDeniesOnSourceError(t *testing.T) {
	src := &scriptedSource{err: errors.New("connection refused")}
	dec := NewAuthorizer(src).Authorize(context.Background(), Session{ID: "s1", Purpose: PurposeTesting},
		Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"})
	if dec.Allow {
		t.Fatal("a database error must deny")
	}
	if dec.Stage != StagePolicy || !strings.Contains(dec.Reason, "policy unavailable") {
		t.Fatalf("stage=%q reason=%q", dec.Stage, dec.Reason)
	}
}

func TestAuthorizeWithoutSourceDenies(t *testing.T) {
	dec := NewAuthorizer(nil).Authorize(context.Background(), Session{ID: "s1", Purpose: PurposeTesting},
		Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"})
	if dec.Allow || !strings.Contains(dec.Reason, "no policy source") {
		t.Fatalf("allow=%v reason=%q", dec.Allow, dec.Reason)
	}
}

// A session that claims a revision the database does not have is forged or the
// database was rolled back; either way it is not judged against live policy.
func TestAuthorizeDeniesAheadRevision(t *testing.T) {
	src := &scriptedSource{states: []State{{Revision: 3, Rules: []Rule{include("api.example.com")}}}}
	dec := NewAuthorizer(src).Authorize(context.Background(), Session{ID: "s1", TaskID: 7, Purpose: PurposeTesting, Revision: 9},
		Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"})
	if dec.Allow || !strings.Contains(dec.Reason, "ahead of the stored policy revision") {
		t.Fatalf("allow=%v reason=%q", dec.Allow, dec.Reason)
	}
}

// The verdict is recomputed from the state loaded on every call, so a policy
// change is seen on the next request even when the revision has not moved: a
// research session's target set changes with another task's rules.
func TestAuthorizeFollowsTheSourceOnEveryCall(t *testing.T) {
	src := &scriptedSource{states: []State{
		{Revision: 1, Rules: []Rule{include("api.example.com")}},
		{Revision: 1},
	}}
	a := NewAuthorizer(src)
	s := Session{ID: "s1", TaskID: 7, Purpose: PurposeTesting, Revision: 1}
	d := Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"}

	if dec := a.Authorize(context.Background(), s, d); !dec.Allow {
		t.Fatalf("first call denied: %s", dec.Reason)
	}
	if dec := a.Authorize(context.Background(), s, d); dec.Allow {
		t.Fatal("the second call reused a verdict the loaded state no longer supports")
	}
	if src.calls != 2 {
		t.Fatalf("source calls=%d, want 2 (the state is loaded per call so a revoke is seen)", src.calls)
	}
}

// AuthorizeResolved is the dns stage: an exclusion over a resolved address, and
// a research answer inside a protected range, are refused before the dial.
func TestAuthorizeResolved(t *testing.T) {
	tests := []struct {
		name   string
		state  State
		p      Purpose
		dest   Destination
		addrs  []string
		allow  bool
		stage  string
		reason string
	}{
		{
			name:  "hostname grant with an excluded answer",
			state: State{Revision: 1, Rules: []Rule{include("*.corp.example"), exclude("10.0.0.0/8")}},
			p:     PurposeTesting,
			dest:  Destination{Scheme: "https", Host: "api.corp.example", Port: 443, Protocol: "http"},
			addrs: []string{"10.1.2.3"},
			stage: StageDNS, reason: "excluded by 10.0.0.0/8",
		},
		{
			name:  "hostname grant with an unnamed answer",
			state: State{Revision: 1, Rules: []Rule{include("api.example.com")}},
			p:     PurposeTesting,
			dest:  Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"},
			addrs: []string{"192.0.2.9"},
			allow: true, stage: StagePolicy,
		},
		{
			name:  "research answer inside a protected range",
			state: State{Revision: 1},
			p:     PurposeResearch,
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: []string{"10.0.0.5"},
			stage: StageDNS, reason: "private address 10.0.0.5",
		},
		{
			name:  "research answer inside a task target",
			state: State{Revision: 1, Targets: []string{"203.0.113.0/24"}},
			p:     PurposeResearch,
			dest:  Destination{Scheme: "https", Host: "docs.example.com", Port: 443, Protocol: "http"},
			addrs: []string{"203.0.113.5"},
			stage: StageDNS, reason: "task target",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &scriptedSource{states: []State{tc.state}}
			dec := NewAuthorizer(src).AuthorizeResolved(context.Background(),
				Session{ID: "s1", TaskID: 7, Purpose: tc.p, Revision: 1}, tc.dest, addrs(tc.addrs...))
			if dec.Allow != tc.allow {
				t.Fatalf("allow=%v, want %v (stage %q reason %q)", dec.Allow, tc.allow, dec.Stage, dec.Reason)
			}
			if dec.Stage != tc.stage {
				t.Fatalf("stage=%q, want %q (reason %q)", dec.Stage, tc.stage, dec.Reason)
			}
			if tc.reason != "" && !strings.Contains(dec.Reason, tc.reason) {
				t.Fatalf("reason=%q, want it to contain %q", dec.Reason, tc.reason)
			}
		})
	}
}

func TestAuthorizeRecordedRequiresTestingAndAddresses(t *testing.T) {
	d := Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"}
	a := NewAuthorizer(&scriptedSource{states: []State{{Rules: []Rule{include(d.Host)}}}})

	t.Run("empty mapping", func(t *testing.T) {
		dec := a.AuthorizeRecorded(t.Context(), Session{Purpose: PurposeTesting}, d, nil)
		if dec.Allow || dec.Stage != StageDNS || !strings.Contains(dec.Reason, "no recorded address") {
			t.Fatalf("decision = %+v, want an empty mapping refusal", dec)
		}
	})
	t.Run("research", func(t *testing.T) {
		dec := a.AuthorizeRecorded(t.Context(), Session{Purpose: PurposeResearch}, d, addrs("93.184.216.34"))
		if dec.Allow || dec.Stage != StagePolicy || !strings.Contains(dec.Reason, "only testing sessions") {
			t.Fatalf("decision = %+v, want a non-testing mapping refusal", dec)
		}
	})
}

package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fixedSource struct {
	state State
	err   error
}

// fixedSource mirrors the DB contract: an unbound session has no task row and
// therefore revision 0.
func (f fixedSource) PolicyState(_ context.Context, s Session) (State, error) {
	if s.TaskID <= 0 {
		return State{}, f.err
	}
	return f.state, f.err
}

// The issuer is the only place a purpose is chosen. A subsystem cannot promote
// itself to a purpose it does not run, and an unbound conversation has nothing
// to authorize testing. Install is operator/curator-initiated rather than
// task-scoped, so it is issued with or without a task.
func TestIssuePurposeMatrix(t *testing.T) {
	tests := []struct {
		name   string
		caller Caller
		p      Purpose
		taskID int64
		ok     bool
	}{
		{name: "agent research", caller: CallerAgent, p: PurposeResearch, taskID: 7, ok: true},
		{name: "agent testing", caller: CallerAgent, p: PurposeTesting, taskID: 7, ok: true},
		{name: "agent install is refused", caller: CallerAgent, p: PurposeInstall, taskID: 7},
		{name: "chat research bound", caller: CallerChat, p: PurposeResearch, taskID: 7, ok: true},
		{name: "chat testing bound", caller: CallerChat, p: PurposeTesting, taskID: 7, ok: true},
		{name: "chat testing unbound is refused", caller: CallerChat, p: PurposeTesting},
		{name: "chat research unbound", caller: CallerChat, p: PurposeResearch, ok: true},
		{name: "curator install", caller: CallerCurator, p: PurposeInstall, taskID: 7, ok: true},
		{name: "curator install unbound", caller: CallerCurator, p: PurposeInstall, ok: true},
		{name: "curator testing is refused", caller: CallerCurator, p: PurposeTesting, taskID: 7},
		{name: "unknown caller is refused", caller: Caller("bogus"), p: PurposeResearch, taskID: 7},
		{name: "unknown purpose is refused", caller: CallerAgent, p: Purpose("bogus"), taskID: 7},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer := NewIssuer(fixedSource{state: State{Revision: 4}})
			s, err := issuer.Issue(context.Background(), tc.caller, tc.taskID, 11, tc.p)
			if tc.ok {
				if err != nil {
					t.Fatalf("Issue() = %v, want a session", err)
				}
				if s.TaskID != tc.taskID || s.ConversationID != 11 || s.Purpose != tc.p || s.ID == "" {
					t.Fatalf("session = %+v", s)
				}
				if tc.taskID > 0 && s.Revision != 4 {
					t.Fatalf("revision = %d, want the stored 4", s.Revision)
				}
				if tc.taskID == 0 && s.Revision != 0 {
					t.Fatalf("unbound revision = %d, want 0", s.Revision)
				}
				return
			}
			if err == nil {
				t.Fatalf("Issue() = %+v, want a refusal", s)
			}
		})
	}
}

func TestIssuePropagatesMissingTask(t *testing.T) {
	issuer := NewIssuer(fixedSource{err: ErrNoTask})
	_, err := issuer.Issue(context.Background(), CallerAgent, 7, 11, PurposeTesting)
	if !errors.Is(err, ErrNoTask) {
		t.Fatalf("Issue() = %v, want it to wrap ErrNoTask", err)
	}
}

func TestIssueWithoutSource(t *testing.T) {
	if _, err := NewIssuer(nil).Issue(context.Background(), CallerAgent, 7, 0, PurposeTesting); err == nil {
		t.Fatal("Issue() with no source must fail")
	}
}

func TestIssueReturnsDistinctSessionIDs(t *testing.T) {
	issuer := NewIssuer(fixedSource{})
	a, err := issuer.Issue(context.Background(), CallerAgent, 7, 0, PurposeTesting)
	if err != nil {
		t.Fatal(err)
	}
	b, err := issuer.Issue(context.Background(), CallerAgent, 7, 0, PurposeTesting)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatalf("two sessions share the id %q", a.ID)
	}
}

// ProxyURL is the one place a tool-facing proxy URL is built. It carries the
// session credential because the gateway accepts no anonymous request, and it is
// empty rather than bare when there is nothing to carry: a tool handed the
// address alone can only be refused at the policy stage.
func TestProxyURL(t *testing.T) {
	issued := Session{ID: "s", TaskID: 1, Purpose: PurposeTesting, Revision: 1, Credential: "cred"}

	tests := []struct {
		name string
		sess Session
		addr string
		want string
	}{
		// user AND password: Python's urllib/urllib3 send Proxy-Authorization
		// only when both are set. The gateway reads the user part.
		{"gateway", issued, "http://127.0.0.1:8788", "http://cred:cred@127.0.0.1:8788"},
		{"no scheme", issued, "127.0.0.1:8788", "http://cred:cred@127.0.0.1:8788"},
		{"trailing space", issued, " http://127.0.0.1:8788 ", "http://cred:cred@127.0.0.1:8788"},
		{"no credential", Session{ID: "s"}, "http://127.0.0.1:8788", ""},
		{"blank credential", Session{ID: "s", Credential: "  "}, "http://127.0.0.1:8788", ""},
		{"no address", issued, "", ""},
		{"blank address", issued, "   ", ""},
		{"unparseable", issued, "http://", ""},
		// The operator's own proxy credentials are never replaced, and a socks5
		// user part is SOCKS auth rather than a gateway credential.
		{"operator credentials", issued, "http://user:pw@10.0.0.1:3128", "http://user:pw@10.0.0.1:3128"},
		{"socks5", issued, "socks5://10.0.0.1:1080", "socks5://10.0.0.1:1080"},
	}
	for _, tc := range tests {
		if got := ProxyURL(tc.sess, tc.addr); got != tc.want {
			t.Errorf("%s: ProxyURL(%q) = %q, want %q", tc.name, tc.addr, got, tc.want)
		}
	}
}

// The credential is authority: printing a session must not print it.
func TestSessionStringOmitsTheCredential(t *testing.T) {
	s := Session{ID: "s", TaskID: 3, ConversationID: 4, Purpose: PurposeTesting, Revision: 9, Credential: "secret-credential"}
	for _, format := range []string{"%v", "%+v", "%s"} {
		if got := fmt.Sprintf(format, s); strings.Contains(got, s.Credential) {
			t.Errorf("%s printed the credential: %q", format, got)
		}
	}
}

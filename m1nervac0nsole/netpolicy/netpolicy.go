// Package netpolicy holds the session and destination contract shared by the
// backend, the HTTP gateway and the execution supervisor (network-boundary
// plan, "Binding interface contract").
//
// A Session is issued by the backend from server-side state: the task row, the
// conversation row and the purpose chosen by the calling subsystem. Nothing a
// tool, a spawned process or a model can pass in may mint or widen one. The
// gateway accepts no anonymous request, so an issued session also carries the
// credential it is resolved by; that credential reaches a run only inside the
// proxy URL its tool environment carries (ProxyURL), and nowhere else.
//
// Authorization is a computed verdict over operator-written rows, not a sentence
// in a prompt. Three properties are deliberate:
//
//   - fail-closed: a task with no authorized rule, an unreadable policy or a
//     database error denies, and each has its own reason;
//   - an exclusion is applied before an include, so a broad grant never covers
//     an excluded subrange;
//   - the predicate is pure: the caller passes the addresses a name resolved
//     to, so a mixed answer set is judged without a resolver here.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

// Purpose is why a session exists. It decides which policy constructor applies;
// a caller cannot promote itself from research to testing.
type Purpose string

const (
	// PurposeResearch reads public material (docs, advisories, repositories)
	// and must never reach a task's engagement targets or internal services.
	PurposeResearch Purpose = "research"
	// PurposeTesting reaches an engagement's authorized destinations.
	PurposeTesting Purpose = "testing"
	// PurposeInstall stages and validates tools through the approved bounded
	// install path.
	PurposeInstall Purpose = "install"
)

// Valid reports whether p is a purpose the backend may issue.
func (p Purpose) Valid() bool {
	switch p {
	case PurposeResearch, PurposeTesting, PurposeInstall:
		return true
	}
	return false
}

// Stage values. They name where a refusal happened, not what the target did.
const (
	StagePolicy    = "policy"
	StageDNS       = "dns"
	StageDial      = "dial"
	StageTLS       = "tls"
	StageTransport = "transport"
)

// Session is one backend-issued execution identity.
type Session struct {
	// ID identifies this session. It is opaque to tools and must be unique per
	// issued session so pooled connections can be keyed by it.
	ID string
	// TaskID is the engagement task, or 0 for an unbound chat.
	TaskID int64
	// ConversationID is the chat that issued the session, or 0 when none.
	ConversationID int64
	// Purpose is the subsystem-chosen purpose; never a tool argument.
	Purpose Purpose
	// Revision is tasks.policy_revision at issue time. Any change invalidates
	// pooled connections and the verdicts judged against the old revision.
	Revision int64
	// Credential is what the gateway resolves this session from. It is minted
	// with the session and leaves the backend only inside the proxy URL a run's
	// tool environment carries, so a request cannot claim a session it was not
	// handed. It is never logged, and String omits it.
	Credential string
}

// String reports the session without its credential, so a log line or an error
// that prints one cannot leak the authority it carries.
func (s Session) String() string {
	return fmt.Sprintf("session %s (task %d, conversation %d, purpose %s, revision %d)",
		s.ID, s.TaskID, s.ConversationID, s.Purpose, s.Revision)
}

// Destination is one concrete thing a request wants to reach.
type Destination struct {
	// Scheme is "http", "https", or "" for a raw connection.
	Scheme string
	// Host is the hostname or address as requested, before resolution.
	Host string
	// Port is the resolved destination port.
	Port int
	// Protocol is "http", "ws", "tcp", "udp" or "dns".
	Protocol string
}

// Decision is the structured outcome of an authorization check. Stage names the
// pipeline stage that decided, so a denial can be told apart from a failure.
type Decision struct {
	Allow  bool
	Stage  string // policy | dns | dial | tls | transport
	Reason string
}

// Authorizer decides whether a session may reach a destination. Implementations
// must deny on missing policy or storage failure.
type Authorizer interface {
	Authorize(ctx context.Context, s Session, d Destination) Decision
}

// Exit is the gateway's upstream exit selection, implemented by the gateway hook
// and consumed by the supervisor.
type Exit struct {
	// ProxyURL is the operator's global proxy; empty means a direct exit.
	ProxyURL string
}

// Rule is one operator-written boundary line, as loaded from task_scope_rules.
// An unauthorized rule is still a rule: an exclusion binds without approval,
// while only an authorized include authorizes.
type Rule struct {
	ID         int64
	TaskID     int64
	Effect     string // include | exclude
	Pattern    string // host, *.host, CIDR, or a single address
	Protocol   string // any, or one exact protocol
	Ports      []int  // empty = any port
	Authorized bool
	Note       string
}

// State is everything one session is judged against, loaded server-side.
//
// Rules are the session task's own rows. Targets are the authorized include
// patterns of every live task: research must not reach a destination another
// task is authorized to test, however public it looks.
type State struct {
	Revision int64
	Rules    []Rule
	Targets  []string
}

// Source loads a session's policy state. *db.DB implements it, so the predicate
// never touches SQL.
type Source interface {
	PolicyState(ctx context.Context, s Session) (State, error)
}

// ErrNoTask reports a session whose task does not exist or is no longer live.
// The issuer returns it, and the authorizer turns it into a refusal.
var ErrNoTask = errors.New("task does not exist or is not live")

// knownProtocols are the protocol values a rule may name. Any of them can be
// written by an operator; "any" is the default and matches every protocol.
var knownProtocols = map[string]bool{"any": true, "http": true, "ws": true, "tcp": true, "udp": true, "dns": true}

// ValidateRule refuses a rule that could never authorize what its author meant.
// It runs where a rule is written, so the predicate never has to guess.
func ValidateRule(r Rule) error {
	switch r.Effect {
	case "include", "exclude":
	default:
		return fmt.Errorf("netpolicy: rule effect %q must be include or exclude", r.Effect)
	}
	if err := scope.Problem(r.Pattern); err != nil {
		return fmt.Errorf("netpolicy: %w", err)
	}
	// A network rule judges a host, a wildcard, a network or a single address.
	// A path glob could never match a Destination, and a grant that can never
	// fire is worse than a refused one.
	if strings.Contains(r.Pattern, "/") {
		if _, _, err := net.ParseCIDR(r.Pattern); err != nil {
			return fmt.Errorf("netpolicy: %q is a url glob; a network rule names a host, a wildcard, a network or a single address", r.Pattern)
		}
	}
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	if proto == "" {
		proto = "any"
	}
	if !knownProtocols[proto] {
		return fmt.Errorf("netpolicy: protocol %q must be any, http, ws, tcp, udp or dns", r.Protocol)
	}
	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("netpolicy: port %d is outside 1-65535", p)
		}
	}
	return nil
}

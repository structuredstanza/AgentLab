package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// The task policy API is the operator's authorization surface (network-boundary
// plan, section B): it shows the effective revision and every rule, and it is
// the only place a rule becomes a grant. Discovery and agent writes never reach
// these handlers, so a discovered host cannot promote itself into authorization.
//
// Every mutation goes through the DB accessors, which write their audit row and
// move tasks.policy_revision in the same transaction, so a cached verdict or a
// pooled origin connection issued under the old revision stops being trusted.

// policyActor is the audit identity of an operator change made through the admin
// API. Agent-written rules carry their own actor at their own call site.
const policyActor = pgdb.OperatorActor

// policyRuleDTO is the wire shape of a rule. netpolicy.Rule is a domain type with
// no wire contract, and this API is snake_case like every other endpoint.
type policyRuleDTO struct {
	ID         int64  `json:"id"`
	Effect     string `json:"effect"`
	Pattern    string `json:"pattern"`
	Protocol   string `json:"protocol"`
	Ports      []int  `json:"ports"`
	Authorized bool   `json:"authorized"`
	Note       string `json:"note"`
}

func policyRuleDTOs(rules []netpolicy.Rule) []policyRuleDTO {
	out := make([]policyRuleDTO, 0, len(rules))
	for _, r := range rules {
		ports := r.Ports
		if ports == nil {
			ports = []int{}
		}
		out = append(out, policyRuleDTO{
			ID:         r.ID,
			Effect:     r.Effect,
			Pattern:    r.Pattern,
			Protocol:   r.Protocol,
			Ports:      ports,
			Authorized: r.Authorized,
			Note:       r.Note,
		})
	}
	return out
}

// taskPolicy returns a task's current policy revision and every rule, authorized
// or not, so the operator view can tell a grant from a row that was only written.
func (s *Server) taskPolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	// A testing session loads the task's own rules and revision and skips the
	// research target set, which this view does not show.
	st, err := s.m.PG().PolicyState(r.Context(), netpolicy.Session{TaskID: taskID, Purpose: netpolicy.PurposeTesting})
	if err != nil {
		if errors.Is(err, netpolicy.ErrNoTask) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"revision": st.Revision, "rules": policyRuleDTOs(st.Rules)})
}

// taskPolicyRuleAdd stores one rule. A rule is a grant only when the request says
// so; otherwise it is recorded unauthorized and authorizes nothing.
func (s *Server) taskPolicyRuleAdd(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var body struct {
		Effect     string `json:"effect"`
		Pattern    string `json:"pattern"`
		Protocol   string `json:"protocol"`
		Ports      []int  `json:"ports"`
		Note       string `json:"note"`
		Authorized bool   `json:"authorized"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	rule := netpolicy.Rule{
		Effect:     strings.TrimSpace(body.Effect),
		Pattern:    strings.TrimSpace(body.Pattern),
		Protocol:   strings.TrimSpace(body.Protocol),
		Ports:      body.Ports,
		Note:       body.Note,
		Authorized: body.Authorized,
	}
	if err := ruleContract(rule); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	id, err := s.m.PG().AddPolicyRule(r.Context(), taskID, rule, policyActor)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

// ruleContract refuses a rule the destination contract cannot express. The
// vocabulary check is netpolicy's; this adds the one combination it accepts but
// no destination can ever match: a DNS grant is the session resolver, which the
// contract describes at the DNS port, so a dns rule naming other ports can never
// fire and is a grant that only looks like one.
func ruleContract(rule netpolicy.Rule) error {
	if err := netpolicy.ValidateRule(rule); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(rule.Protocol), "dns") && len(rule.Ports) > 0 {
		for _, p := range rule.Ports {
			if p == 53 {
				return nil
			}
		}
		return errors.New("a dns rule names the resolver, which the contract describes on port 53; list 53 or no ports")
	}
	return nil
}

func (s *Server) taskPolicyRuleAuthorize(w http.ResponseWriter, r *http.Request) {
	s.setPolicyRuleAuthorized(w, r, true)
}

func (s *Server) taskPolicyRuleRevoke(w http.ResponseWriter, r *http.Request) {
	s.setPolicyRuleAuthorized(w, r, false)
}

// setPolicyRuleAuthorized approves or revokes one rule. A revoke takes effect on
// the next request: the authorizer re-reads the rules every time, and the
// revision change is what invalidates a cached verdict.
func (s *Server) setPolicyRuleAuthorized(w http.ResponseWriter, r *http.Request, authorized bool) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	ruleID, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil || ruleID <= 0 {
		writeErr(w, 400, "invalid rule id")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if err := s.m.PG().SetPolicyRuleAuthorized(r.Context(), taskID, ruleID, authorized, policyActor); err != nil {
		if errors.Is(err, pgdb.ErrPolicyRuleNotFound) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "authorized": authorized})
}

// taskCertExceptions lists the task's unexpired origin certificate exceptions.
func (s *Server) taskCertExceptions(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	list, err := s.m.PG().ListCertExceptions(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []pgdb.CertException{}
	}
	writeJSON(w, 200, map[string]any{"exceptions": list})
}

// taskCertExceptionAdd approves an origin certificate exception for one task and
// authority. It never disables verification globally and never authorizes a
// destination: it only lets the TLS stage accept that authority's certificate.
func (s *Server) taskCertExceptionAdd(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var body struct {
		Authority string `json:"authority"`
		Reason    string `json:"reason"`
		// ExpiresAt is RFC3339. Empty means the exception does not expire.
		ExpiresAt string `json:"expires_at"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	authority := strings.ToLower(strings.TrimSpace(body.Authority))
	if authority == "" {
		writeErr(w, 400, "authority is required")
		return
	}
	var expires *time.Time
	if raw := strings.TrimSpace(body.ExpiresAt); raw != "" {
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeErr(w, 400, "expires_at must be RFC3339")
			return
		}
		if !at.After(time.Now()) {
			writeErr(w, 400, "expires_at is in the past")
			return
		}
		expires = &at
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if err := s.m.PG().AddCertException(r.Context(), taskID, authority, body.Reason, expires, policyActor); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

// taskCertExceptionDelete removes one exception. A row that is not this task's
// is a 404, so a stale operator view cannot delete another task's exception.
func (s *Server) taskCertExceptionDelete(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("eid"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid exception id")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	if err := s.m.PG().DeleteCertException(r.Context(), taskID, id, policyActor); err != nil {
		if errors.Is(err, pgdb.ErrCertExceptionNotFound) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

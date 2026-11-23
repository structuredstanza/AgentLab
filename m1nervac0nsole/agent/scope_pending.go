package agent

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

// ScopePending, if set, tells the operator a discovered target outside the
// authorized boundary now has a pending (unapproved) network rule. Wired by the
// server, which owns the activity stream.
var ScopePending func(taskID int64, pattern string, ruleID int64)

// scopeRuleCovers treats recorded addresses as claims, not hostname grants.
func scopeRuleCovers(pattern string, ips []net.IP, rules []scope.Rule) bool {
	status := scope.Evaluate(scope.ParseAsset(pattern), rules).Status
	if len(ips) == 0 || status == scope.Out {
		return status != scope.Unknown
	}
	for _, ip := range ips {
		if scope.Evaluate(scope.ParseAsset(ip.String()), rules).Status != scope.In {
			return false
		}
	}
	return true
}

// flagPending records a pending include rule for a discovered target that no
// authorized rule covers. kind is a task_scope kind; value its domain or net.
// A hostname with recorded addresses is covered only if every address is in
// scope. Returns the pending pattern, or "" when nothing was created.
func (t *ToolSet) flagPending(kind, value string) string {
	if t.as == nil || t.taskID <= 0 {
		return ""
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	pattern := value
	switch kind {
	case "root_domain":
		pattern = "*." + value
	case "subdomain":
	case "ip", "cidr":
		if p, err := netip.ParsePrefix(value); err == nil && p.Bits() == p.Addr().BitLen() {
			pattern = p.Addr().String()
		}
	default:
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rules, err := t.as.TaskPolicyRules(ctx, t.taskID)
	if err != nil {
		log.Printf("[scope] task %d: list policy rules: %v", t.taskID, err)
		return ""
	}
	var sr []scope.Rule
	for _, r := range rules {
		if strings.EqualFold(strings.TrimSpace(r.Pattern), pattern) {
			return "" // already written, in any state
		}
		if r.Effect == "exclude" || r.Authorized {
			sr = append(sr, scope.Rule{Effect: scope.Effect(r.Effect), Pattern: netpolicy.RulePattern(r.Pattern)})
		}
	}
	var ips []net.IP
	if kind == "subdomain" || kind == "root_domain" {
		ips, err = t.as.TaskHostAddrs(t.taskID, value)
		if err != nil {
			log.Printf("[scope] task %d: read addresses for %s: %v", t.taskID, value, err)
			return ""
		}
	}
	if scopeRuleCovers(pattern, ips, sr) {
		return ""
	}
	id, err := t.as.AddPendingPolicyRule(ctx, t.taskID, netpolicy.Rule{
		Effect: "include", Pattern: pattern, Protocol: "any",
		Note: "discovered: " + kind + " " + value,
	})
	if err != nil {
		log.Printf("[scope] task %d: pending rule %s: %v", t.taskID, pattern, err)
		return ""
	}
	if ScopePending != nil {
		ScopePending(t.taskID, pattern, id)
	}
	return pattern
}

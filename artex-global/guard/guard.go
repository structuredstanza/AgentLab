// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [Built-in] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
	scope       ScopeChecker           // optional; nil disables scope enforcement
}

// ScopeChecker decides whether an asset is inside the engagement's boundary.
// The guard only blocks on a positive exclusion: an engagement whose rules are
// still empty reports every asset as unknown, and treating unknown as out would
// refuse every tool call on a fresh task.
type ScopeChecker interface {
	// Judge returns "out" when the asset is explicitly excluded, and the reason.
	Judge(asset string) (out bool, reason string)
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

// WithScope attaches the engagement boundary. A tool call naming an asset the
// boundary excludes is refused before it runs, which is the difference between
// a scope rule that is advice and one that is enforced.
func (g *Guard) WithScope(sc ScopeChecker) *Guard {
	g.scope = sc
	return g
}

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch intercept.CanonicalToolName(ctx, ev.ToolName) {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// Record once, after the decision: recording "allow" up front and again from
	// block() made one denied call appear as both allow and block, and the block
	// row carried no command because block() passes "".
	res := g.applyIntercept(ctx, ev)
	if res.Decision != "block" && g.scope != nil {
		if blocked, reason := g.checkScope(ev); blocked {
			res = g.block(ev.ToolName, reason, cmd)
		}
	}
	action := "allow"
	if res.Decision == "block" {
		action = "block"
	}
	g.record(ev.ToolName, action, res.Message, cmd)
	return res
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	canonical := intercept.CanonicalToolName(ctx, ev.ToolName)
	if !g.interceptor.IsToolEnabled(canonical) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(canonical, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, canonical, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// Observation: a deny hit does not block approval; it directly records one denied entry (visible on the history / task intercept page).
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// F14 brain-preservation judgment: the two block reasons below and the systemBlockMessage framing must not be translated
		// without translating it, keeping the original Chinese text. This string flows from g.block → hook.Result.Message to the agent
		// to the agent as tool_result (intentional steering text to keep the pentest agent from mistaking the block for a target defense and attempting a bypass
		// Deliberate manipulative phrasing that discourages attempts, BRIEF [A] performance-preservation target. Moreover
		// Unlike the deny path, the ask block path does not go through Interceptor.Log, so g.block → g.record
		// carries the same framing text verbatim into the audit log as well (GET /api/audit → entries[].reason).
		// In other words, one string serves as both agent input and display (F16 isomorph). To separate out only the display into Korean,
		// g.block would need to be restructured to carry the two strings separately, but since this is high-risk and low-value, it is on hold.
		//
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("Work was canceled; platform security controls blocked execution"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("Manual approval was not granted (the user denied it or the approval timed out)"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("Tool execution prohibited" / "User denied") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【Platform control · not target defense】This call was blocked by the platform. " +
		"Reason: " + reason + ". This operation is forbidden."
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(ctx context.Context, ev hook.Event) hook.Result {
	if intercept.CanonicalToolName(ctx, ev.ToolName) != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

// block returns the decision only; preToolUse records it exactly once.
func (g *Guard) block(tool, reason, cmd string) hook.Result {
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}

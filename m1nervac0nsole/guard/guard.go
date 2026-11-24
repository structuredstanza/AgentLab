// Package guard implements the safety boundary layer (docs §11): user-configured
// intercept-rule evaluation and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [Built-in] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/intercept"
	"github.com/structuredstanza/norma/hook"
)

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
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
	g := &Guard{interceptor: ic}
	g.reg = hook.NewRegistry().On(hook.PreToolUse, g.preToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	res := g.applyIntercept(ctx, ev)
	if res.Decision != "block" && g.scope != nil {
		if blocked, reason := g.checkScope(ev); blocked {
			res = g.block(reason)
		}
	}
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
		return g.block(systemBlockMessage(dec.Message))
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// The ask-block reasons and framing reach the model as a tool result so
		// it can distinguish a platform block from a target response. Unlike the
		// deny path, this framing is not recorded in interception history.
		//
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(systemBlockMessage("Work was canceled; platform security controls blocked execution"))
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(systemBlockMessage("Manual approval was not granted (the user denied it or the approval timed out)"))
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as a platform-governance
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
	return "[platform control - not target defense]This call was blocked by the platform. " +
		"Reason: " + reason + ". This operation is forbidden."
}

// block returns a refusal for the harness to hand back as the tool result.
func (g *Guard) block(reason string) hook.Result {
	return hook.Result{Decision: "block", Message: reason}
}

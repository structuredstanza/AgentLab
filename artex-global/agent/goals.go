package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/norma/agentcore"
	"github.com/structuredstanza/norma/llm"
	acperm "github.com/structuredstanza/norma/permission"
	actool "github.com/structuredstanza/norma/tool"
	"github.com/structuredstanza/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (section [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration-test goal decomposer. Your responsibility is to identify the **final outcome to be achieved** from the user's input, not to plan attack steps.

**Step 1 (before decomposing goals): Extract operational constraints**
From the "Task Goal / Task Description", identify the operator's explicit rules about **what operations may or may not be performed**, and call set_constraints to register each one (if neither the description nor the goal contains operational constraints, do not extract any):
- type=deny: prohibited operations (e.g., "do not scan ports", "do not perform write/delete operations on the production environment", "no brute forcing", "do not touch a particular subdomain").
- type=allow: explicitly permitted or restricted operational scope (e.g., "passive reconnaissance only", "only this domain").
- A constraint is neither a goal nor an attack step: it defines the boundaries of permitted actions.
- **Constraints must be self-contained and name concrete targets**: replace referential terms such as "current target/current port/current IP/current domain/this site" with the **specific values** from the task goal/description. Constraints are injected separately into execution-stage prompts; once separated from context, references like these cannot be resolved.
  Example: if the target is https://abc.example.net, write "Only test abc.example.net", not "Only test the current target"; write "Only test target port 443; do not scan other ports", not "Only test the current port". If the source says only "current target" but gives a clear target address, fill in that address.
- **Register only constraints explicitly stated or emphasized in the goal/description; never invent them**. If unsure of the type, use deny (more conservative).
- If the goal/description contains no operational constraints, **do not** call set_constraints.
After registering any constraints (if any), continue with the goal decomposition below.

**A goal is a final deliverable or verifiable result.**

**The following are not goals (do not list them as sub-goals):**
- Information gathering, reconnaissance, or endpoint scanning
- Vulnerability analysis or validation processes
- Attack steps or exploitation techniques
- Result-validation steps

**Decomposition principles:**
- If the user describes one final goal, output one.
- If there are multiple **independent** final deliverables, list them separately.
- Assign vulnclass when a goal corresponds to a clearly defined vulnerability class; leave it blank for information-gathering or business-logic goals.
- Never invent goals the user did not mention.

Call set_goals to submit the result.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Additional duty: Register the test asset scope**
In addition to decomposing goals, identify the **explicitly stated test asset scope** in the "Task Goal / Task Description" and register it by calling add_task_scope (this is the task's authorization boundary and the denominator for asset test coverage). **Minimum-scope principle: register only the single target the user explicitly identifies; never expand the scope yourself.**
- If the target is a URL or an address with a hostname (e.g., https://xxx.example.com/path, app.example.com), take its **full hostname**; kind=subdomain, value=the full hostname.
  Example: target https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**not** example.net).
  **Never** shorten a hostname containing a subdomain to the root domain—seeing xxx.example.com and registering the entire example.com would expand the scope beyond the user's target and violate the minimum-scope principle.
- Use kind=root_domain, value=example.com **only** when the user provides a **bare root domain with no subdomain** (e.g., directly writes example.com), or explicitly says "the entire site / all subdomains / the whole domain".
- A single IP or CIDR range → kind=ip / cidr, value=the IP or CIDR.
- **Do not** register company scope (company): when a task has just been created, the company usually does not yet exist in the asset system and cannot be registered; company-level scope is handled in the later plan phase.
Other rules:
- Register only scope **explicitly written in the goal/description**; never invent or infer an unmentioned domain/IP.
- Give a brief reason stating which sentence supports the scope, for auditing.
- If there is no explicit asset scope in the goal/description, **do not** call add_task_scope.
Register scope (if any) with add_task_scope first, then call set_goals to submit the goals.`

// goalsSystem assembles the goals-decomposer system prompt: the rendered body
// [A] (DB-overridable), the code-owned scope-extraction tail when add_task_scope
// is wired (withScope), and the code-owned English output-language tail [C] last —
// mirroring chatSystem/plannerSystem so a DB-edited body can never drop the tail.
// DecomposeGoalsWithProvider uses this one assembly, so the langDirective tail can't
// drift between runtime and callers. EngagementDescription is intentionally left
// empty: the task description rides in the user message, not the
// {{.EngagementDescription}} var (see DecomposeGoalsWithProvider).
func goalsSystem(dataDir string, withScope bool) string {
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	if withScope {
		sys += goalsScopeTail
	}
	return sys + langDirective()
}

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine: it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (target scope / flag count / notes).
// It is fed alongside the goal so the decomposer does not split blind; the prompt
// still forbids inventing anything the two texts do not state.
//
// emit, when non-nil, receives every LLM step with Worker="planner" so the
// round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case.
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// The goal breakdown is a one-shot call: no transcript store is attached, so agentcore does not attach to ctx
	// session id (it is only attached when a writer exists; see agentcore.Prompt). And the session-id header
	// for prompt caching / sticky routing (opencode zen returns 400 directly when x-opencode-session is missing
	// MissingSessionID) reads this value from ctx -- without it, "the conversation works normally, but decomposition returns 400."
	// Explicitly attach a stable id: breakdown requests for the same exploration share it (which helps hit the cache), and the naming does not conflict with
	// planner/worker do not conflict, and llmrec.parseSession can attribute them correctly.
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// goalsSystem appends the scope-extraction tail in lockstep (withScope) so the
	// prompt never asks for a tool that isn't present, and it owns the output-language
	// tail last so a DB-edited body can't drop it. Description rides in the user
	// message, NOT the {{.EngagementDescription}} var, so a prompt can't inject it twice.
	withScope := as != nil && taskID > 0
	sys := goalsSystem(dataDir, withScope)
	// set_constraints is always available (it does not depend on the asset store): the prompt text already includes the step "extract operation constraints first, then break down the goal"
	// (the wording can be edited on the agent editing page), so here we only need to wire up the tool.
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	if withScope {
		tools = append(tools, tsx.addTaskScope())
	}
	userMsg := "Task goals:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background: may include target scope, flag count or engagement notes; reference only - do not invent anything it does not state):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// Each of the 3 steps (extract constraints → register scope → decompose goals) needs one tool call each, so give enough turns to avoid missing set_goals before wrapping up.
		MaxTurns:     8,
		NonStreaming: nonStreaming, // When this profile selects non-streaming, call Provider.Complete
		MaxTokens:    maxTokens,    // 0 = no upper limit on sending; the server-side default decides
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}

package agent

import (
	"strings"

	"github.com/Autumn-27/norma/harness"
)

// Wrap-up / settlement prompt: when the agent is terminated because the step budget is exhausted (MaxTurns) or
// the time limit is reached (run_seconds/MaxDuration), the SDK's settlement phase injects this prompt,
// so the agent first persists the content it has already identified but not yet written back, then outputs a one-sentence summary, avoiding an abrupt ending.
//
// Each agent's wrap-up prompt can be overridden on demand from the backend (stored in agents.wrapup_prompt); if left empty, the built-in default here is used.
// built-in default. Only the prompt body is editable; which tools are disabled and how many turns the wrap-up itself is given are fixed by code policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. The worker reuses the historically hard-coded settleWrapUpPrompt
// (defined in worker.go); planner/mainagent each have a version. Those that do not match (custom agent) fall back to the generic default.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: Built-in default turn budgets for each agent's own wrap-up phase (can be overridden by a background value >0).
// Give each one 10 rounds to ensure there are enough steps in the wrap-up phase to persist to the database. If no match is found, fall back to genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "The step budget for this planning round is about to run out. However, only this round is ending; the system will wake you again as conditions change so that planning can continue. The overall task is not finished, so there is no need to wrap up the entire plan here. Put the conclusions you have already clearly reached in this round into effect so the round is not wasted, but **do not invent intents just to have something to finish with** (zero intents in this round is a completely normal result). (1) If you have already determined search directions that should be dispatched **right now**, submit them together with one add_intent call (do not hold onto decisions you have already made; send them immediately). (2) For any goal that a finding or fact has already proven achieved, mark it met with prove_goal (do not omit any). (3) If you identified a serial exploitation chain that must be broken into steps, record it with TodoWrite so it can be dispatched step by step when you wake up next time. Once everything is done, end this round immediately and do not output summary text."

const mainAgentWrapUpDefault = "The step budget is about to run out and this interaction is about to end. Do not start any new exploration or manipulation. **In a single sentence of plain text only**, summarize for the user in English the current progress, the key conclusions, and the recommended next steps."

const genericWrapUpDefault = "The budget is about to run out and this run will end soon. First record the results you have completed but not yet saved, then **in a single sentence of plain text only**, summarize in English what you did and what key conclusions you obtained (this one sentence will be displayed as the result of this run)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        withWrapupLang(resolveWrapup(agentKey)),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// withWrapupLang appends the display-language directive (langDirective) after the wrap-up prompt.
// Unlike the system prompt, the wrap-up prompt does not automatically get the langDirective tail,
// so attaching it directly like this makes the final user-visible one-sentence summary come out in English.
// The wrap-up prose itself is an operational instruction read by the model (kept in Korean), and this tail, with the highest priority,
// Only enforces the language of user-facing text. Harmless for the planner family, which does not produce summaries.
func withWrapupLang(prompt string) string {
	if strings.TrimSpace(prompt) == "" {
		return prompt
	}
	return prompt + langDirective()
}

// ---------- Task-level timeout wrap-up terms (see docs/Task-Level Timeout and Wrap-Up Design.md) ----------
//
// This is a *separate* set from the per-run wrap-up wording: per-run means "the budget for this one run is used up"; task timeout means
// "the whole task has reached its deadline and is about to end." The meanings often run in opposite directions (especially for the planner: per-run says "don't stop, keep planning,"
// The task timeout says "stop planning at the deadline and make the final judgment"). Only configure for worker/planner.

// WrapupTaskTimeoutOverride / …TurnsOverride: DB overrides for the task-timeout wrap-up wording and turn count
// (wire to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The entire task has reached its time limit and will end shortly** (this is the end of the whole exploration, not this run's budget). This is your last chance. (1) **Save everything** you have already identified but not yet recorded. Record new assets with insert_assets, exploration conclusions and facts with record_fact, and confirmed vulnerabilities with report_finding. (2) Do not start any new commands or detections. (3) **At the very end, use only a single sentence of plain text** to summarize in English the key conclusions obtained from this intent."

const plannerTaskTimeoutDefault = "**The entire task has reached its time limit and will end soon** (this is not the end of this round; the whole task ends). Make a final goal determination based on all facts and findings to date. Mark every goal that evidence has proven achieved as met with prove_goal (do not omit any). **Do not generate any new intents** (dispatching intents now will no longer run). Once the determination is complete, exit immediately and do not output summary text."

// TaskTimeoutWrapupDefault returns an agent's built-in task-timeout wrap-up wording (used for background placeholders / restoring the default).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // Unconfigured (mainagent/chat) returns an empty string
}

// resolveTaskTimeoutWrapup: DB override (if non-empty) > built-in default. An empty string means the agent has no task-timeout wording
// (not worker/planner); in this case the caller should fall back to the per-run wording.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // By default, keep using the per-run turn count.
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run was clamped by the task deadline: if it ends due to Timeout, the task has reached its time limit → use the task-timeout wording;
//     if it ends due to MaxTurns, the steps within the clamped window were exhausted first while the task still has a few minutes left → fall back to the per-run wording.
//   - clamped=false → there is still time left in the task: use the per-run wording for both reason values (i.e., it degrades to wrapupSettlement).
//
// The PromptByReason handed to the harness selects the wording at wrap-up time based on the *actual* reason; without a build, the wording would be mismatched.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := withWrapupLang(resolveWrapup(agentKey))
	st := &harness.Settlement{
		Prompt:        perRun, // Fallback (also the value for both reason values when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  withWrapupLang(tt), // Task reached its deadline
				harness.ReasonMaxTurns: perRun,             // Steps run out first, with time still left in the task
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}

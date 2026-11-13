package agent

import (
	"strings"
	"testing"

	"github.com/structuredstanza/norma/harness"
	actool "github.com/structuredstanza/norma/tool"
)

// per-run and task-timeout must have different meanings (especially for the planner): per-run means "only this round
// "ends" and task-timeout is "the entire task ends". The constant mapping must not be mixed up if they change.
func TestWrapupDefaultsRouting(t *testing.T) {
	if WrapupDefault("worker") != settleWrapUpPrompt {
		t.Error("worker per-run default is not settleWrapUpPrompt")
	}
	if WrapupDefault("planner") != plannerWrapUpDefault {
		t.Error("planner per-run default is not plannerWrapUpDefault")
	}
	if WrapupDefault("mainagent") != mainAgentWrapUpDefault {
		t.Error("mainagent per-run default is not mainAgentWrapUpDefault")
	}
	// Unregistered keys (custom agents) fall back to generic.
	if WrapupDefault("unknown-agent") != genericWrapUpDefault {
		t.Error("an unregistered key does not fall back to genericWrapUpDefault")
	}
	// task-timeout is only present in worker/planner; elsewhere it is an empty string (callers fall back to per-run).
	if TaskTimeoutWrapupDefault("worker") != workerTaskTimeoutDefault {
		t.Error("worker task-timeout default is not workerTaskTimeoutDefault")
	}
	if TaskTimeoutWrapupDefault("planner") != plannerTaskTimeoutDefault {
		t.Error("planner task-timeout default is not plannerTaskTimeoutDefault")
	}
	if TaskTimeoutWrapupDefault("mainagent") != "" {
		t.Error("mainagent must not have a task-timeout message (empty string)")
	}
	// If the per-run and task-timeout wording are identical, the semantic distinction is lost.
	if workerTaskTimeoutDefault == settleWrapUpPrompt {
		t.Error("worker per-run and task-timeout messages are identical")
	}
	if plannerTaskTimeoutDefault == plannerWrapUpDefault {
		t.Error("planner per-run and task-timeout messages are identical")
	}
}

// TestWrapupCarriesReflectStepOnlyWhenBound: a run cut off by its budget is the
// one with the most to pass on, so every worker wrap-up wording - per-run,
// task-timeout and an operator override of either body - must ask for the
// reflect call before the closing sentence, which is where settlement stops.
// It must not ask when the resolved tool list has no reflect tool: an operator
// can unbind it in the tools table.
func TestWrapupCarriesReflectStepOnlyWhenBound(t *testing.T) {
	oldPrompt, oldTimeout := WrapupOverride, WrapupTaskTimeoutOverride
	t.Cleanup(func() { WrapupOverride, WrapupTaskTimeoutOverride = oldPrompt, oldTimeout })

	reflect := actool.Build(actool.Spec{Name: "reflect"})
	bound := []actool.CoreTool{reflect}
	check := func(name, prompt string) {
		t.Helper()
		if !strings.Contains(prompt, wrapupReflectStep) {
			t.Errorf("%s: wrap-up does not order a reflect call before the closing sentence: %q", name, prompt)
		}
		// The language tail stays last: it is the highest-priority rule.
		if i, j := strings.Index(prompt, wrapupReflectStep), strings.Index(prompt, "Output language rule"); i < 0 || j < 0 || i > j {
			t.Errorf("%s: reflect step is missing or after the language tail", name)
		}
	}

	check("per-run default", wrapupSettlement("worker", nil, bound...).Prompt)
	st := wrapupSettlementForTask("worker", nil, true, bound...)
	check("task-timeout default", st.PromptByReason[harness.ReasonTimeout])
	check("clamped max-turns", st.PromptByReason[harness.ReasonMaxTurns])

	WrapupOverride = func(key string) (string, bool) {
		return "Custom body. End with one sentence.", key == "worker"
	}
	WrapupTaskTimeoutOverride = func(key string) (string, bool) {
		return "Custom deadline body. End with one sentence.", key == "worker"
	}
	check("operator override", wrapupSettlement("worker", nil, bound...).Prompt)
	check("operator timeout override", wrapupSettlementForTask("worker", nil, true, bound...).PromptByReason[harness.ReasonTimeout])

	// Without reflect in the resolved tool list the step must not be ordered.
	if p := wrapupSettlement("worker", nil).Prompt; strings.Contains(p, wrapupReflectStep) {
		t.Errorf("wrap-up orders reflect although the tool is not bound: %q", p)
	}
	// mainagent has no reflect tool in its call site, so it must never get the step.
	if p := wrapupSettlement("mainagent", nil, bound...).Prompt; strings.Contains(p, wrapupReflectStep) {
		t.Errorf("mainagent wrap-up asks for reflect: %q", p)
	}
}

package agent

import "testing"

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

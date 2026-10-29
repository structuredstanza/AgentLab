package agent

import "testing"

// per-run and task-timeout must have different meanings (especially for the planner): per-run means "only this round
// "ends" and task-timeout is "the entire task ends". The constant mapping must not be mixed up if they change.
func TestWrapupDefaultsRouting(t *testing.T) {
	if WrapupDefault("worker") != settleWrapUpPrompt {
		t.Error("worker per-run 기본값이 settleWrapUpPrompt 가 아니다")
	}
	if WrapupDefault("planner") != plannerWrapUpDefault {
		t.Error("planner per-run 기본값이 plannerWrapUpDefault 가 아니다")
	}
	if WrapupDefault("mainagent") != mainAgentWrapUpDefault {
		t.Error("mainagent per-run 기본값이 mainAgentWrapUpDefault 가 아니다")
	}
	// Unregistered keys (custom agents) fall back to generic.
	if WrapupDefault("unknown-agent") != genericWrapUpDefault {
		t.Error("미등록 키가 genericWrapUpDefault 로 떨어지지 않는다")
	}
	// task-timeout is only present in worker/planner; elsewhere it is an empty string (callers fall back to per-run).
	if TaskTimeoutWrapupDefault("worker") != workerTaskTimeoutDefault {
		t.Error("worker task-timeout 기본값이 workerTaskTimeoutDefault 가 아니다")
	}
	if TaskTimeoutWrapupDefault("planner") != plannerTaskTimeoutDefault {
		t.Error("planner task-timeout 기본값이 plannerTaskTimeoutDefault 가 아니다")
	}
	if TaskTimeoutWrapupDefault("mainagent") != "" {
		t.Error("mainagent 은 task-timeout 문구가 없어야 한다(빈 문자열)")
	}
	// If the per-run and task-timeout wording are identical, the semantic distinction is lost.
	if workerTaskTimeoutDefault == settleWrapUpPrompt {
		t.Error("worker 의 per-run 과 task-timeout 문구가 동일하다")
	}
	if plannerTaskTimeoutDefault == plannerWrapUpDefault {
		t.Error("planner 의 per-run 과 task-timeout 문구가 동일하다")
	}
}

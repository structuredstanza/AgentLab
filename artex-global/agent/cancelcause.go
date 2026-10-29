package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "The user paused the task",
		"The user paused the task via the task control API (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was cancelled; running intents return to frontier(open) and are claimed and restarted from scratch when the task resumes.")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "The orchestrator Agent paused the task",
		"The orchestrator Agent called the pause_task tool to pause this task. This Planner/Worker run was cancelled; running intents return to frontier(open) and are restarted when the task resumes.")
	AbortTaskDeleted = cause("task_deleted", "The task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the deletion barrier cancelled its running Planner, Worker, and main Agent. This run's result will no longer be used.")
	AbortPausedOnReload = cause("paused_on_reload", "The backend restored the task's paused state",
		"On startup the backend restored the task's paused state from persisted database state. This run was cancelled; normally no Agent is running during the recovery phase.")
	AbortGoalMet = cause("goal_met", "The planner determined the task goal was met",
		"The planner determined the task goal was met and set the task to done, then cancelled the still-running Workers; these intents are marked stopped, not failed.")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "The wait for task-timeout settlement ran out",
		"After the task reached its timeout, running Workers were given time to settle gracefully, but the 90-second drain grace period was not enough, so a hard cancel was executed. Intents are marked exhausted; facts and assets already written during settlement are kept.")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "The planner terminated this intent",
		"The planner called kill_work to terminate this intent, usually because the direction drifted or it no longer had value. The intent is marked stopped and is not claimed again automatically.")
	AbortWorkPausedByUser = cause("work_paused_by_user", "The user paused this Worker intent",
		"The user paused the running Worker. This call was cancelled and the intent changes to paused; registered intents, facts, findings, and activity records are all kept, and the Worker restarts from scratch on resume.")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "The user deleted this Worker intent",
		"The user deleted the running Worker. This call was cancelled; after the Worker exits its write section, the server handles the intent according to the deletion mode the user chose: a soft delete only marks it deleted and keeps all output, while a hard delete cascades to the intent and any downstream nodes supported only by it.")
	AbortWorkFinished = cause("work_finished", "The Worker finished normally and released its context",
		"The Worker finished normally and the engine released its context resources in detachWork. This is not a run interruption; if it appears in an interruption message, cancellation raced with the wrap-up event.")
	AbortPausedRaceGuard = cause("paused_race_guard", "New run start refused while the task is paused",
		"While the task is paused, the engine refuses to issue new execution contexts to prevent a race between claim and pause from letting a Worker keep starting; claimed intents return to frontier.")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "The user stopped this conversation turn",
		"The user clicked stop, actively aborting this main Agent or session Agent run. Activity records already produced are kept, and the next message can be sent.")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "Task paused and the main Agent conversation aborted",
		"When the user paused the task, the running main Agent conversation was cancelled in sync. Activity records already produced are kept; the turn's messages are not replayed automatically when the task resumes.")
	AbortChatTurnFinished = cause("chat_turn_finished", "This conversation turn finished normally and released its context",
		"This conversation turn finished normally and the server is releasing its context resources. This is not a run interruption; if it appears in an interruption message, cancellation raced with the wrap-up event.")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "The backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating, or shutting down. All running Agents are cancelled; leftover running intents are reset to open and re-executed after restart.")
	AbortRunHardTimeout = cause("run_hard_timeout", "The single-run hard timeout backstop fired",
		"The single run exceeded its soft wall-clock budget plus extra grace, meaning a model request or a tool did not return for a long time, so normal turn-boundary wrap-up could not run. Focus on the last tool call that had not returned before the interruption.")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "The upstream context reached its deadline",
			"The upstream context reached its deadline, but the setter did not attach a named reason via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "The canceller attached no named reason",
			"The upstream context was cancelled, but the canceller did not attach a named reason via context.WithCancelCause; register a reason in agent/cancelcause.go and wire it into this cancellation point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}

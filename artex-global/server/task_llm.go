package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type taskAgentBundle struct {
	runtime        *taskLLMRuntime // goal decomposition runtime
	plannerRuntime *taskLLMRuntime
	workerRuntime  *taskLLMRuntime
	mainRuntime    *taskLLMRuntime
	pl             *agent.Planner
	wk             *agent.Worker
	main           *agent.MainAgent
}

type llmAuditProfile struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Format string `json:"format"`
	Model  string `json:"model"`
}

type llmTransitionAudit struct {
	Mode     string           `json:"mode"` // automatic | manual | exhausted
	Reason   string           `json:"reason"`
	Previous *llmAuditProfile `json:"previous,omitempty"`
	Next     *llmAuditProfile `json:"next,omitempty"`
}

type llmActivityMetadata struct {
	LLMTransition llmTransitionAudit `json:"llm_transition"`
}

type taskLLMRuntime struct {
	s        *Server
	taskID   string
	agentKey string
}

type taskLLMError struct {
	taskID         string
	chainExhausted bool
	cause          error
}

func (e *taskLLMError) Error() string {
	if e.chainExhausted {
		return fmt.Sprintf("task %s LLM profile chain exhausted: %v", e.taskID, e.cause)
	}
	return e.cause.Error()
}

func (e *taskLLMError) Unwrap() error { return e.cause }

func isTaskLLMRuntimeError(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target)
}

func isTaskLLMChainExhausted(err error) bool {
	var target *taskLLMError
	return errors.As(err, &target) && target.chainExhausted
}

// isQuotaExhaustedError is intentionally strict. A generic 429, auth error,
// network failure, or 5xx does not rotate providers; the response must explicitly
// identify quota, credits, billing balance, or payment exhaustion.
func isQuotaExhaustedError(err error) bool {
	return err != nil && agent.IsQuotaExhaustedMessage(err.Error())
}

// Consecutive-failure escalation (ouroboros cost-tier take, #99): quota
// exhaustion already advances the chain, but a profile that keeps failing with
// plain runtime errors (bad key, persistent 5xx, broken model output) would
// otherwise burn the whole same-provider retry budget on every call. After
// llmFailStreakThreshold consecutive failed calls on the same chain profile
// the chain advances exactly like a quota exhaust, carrying the true reason.
// Deliberately escalation-only: no auto-downgrade (a mid-task model swap-down
// risks behavior drift and flapping; the operator can reset the chain).
const llmFailStreakThreshold = 3

var llmFailStreaks = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

func llmFailKey(taskID string, profileID int64) string {
	return taskID + ":" + strconv.FormatInt(profileID, 10)
}

// noteLLMCallFailure records one failed call on (task, profile) and reports
// whether the escalation threshold was just reached. The streak resets when it
// fires and on every success, so the counter tracks consecutive failures only.
func noteLLMCallFailure(taskID string, profileID int64) bool {
	llmFailStreaks.Lock()
	defer llmFailStreaks.Unlock()
	k := llmFailKey(taskID, profileID)
	llmFailStreaks.m[k]++
	if llmFailStreaks.m[k] >= llmFailStreakThreshold {
		delete(llmFailStreaks.m, k) // armed and consumed — next failure starts a fresh streak
		return true
	}
	return false
}

// resetLLMFailStreaksForTest clears every streak; test isolation only (the
// escalation counter is package-global in-memory state).
func resetLLMFailStreaksForTest() {
	llmFailStreaks.Lock()
	llmFailStreaks.m = map[string]int{}
	llmFailStreaks.Unlock()
}

func resetLLMFailStreak(taskID string, profileID int64) {
	llmFailStreaks.Lock()
	defer llmFailStreaks.Unlock()
	delete(llmFailStreaks.m, llmFailKey(taskID, profileID))
}

// llmProfilePin carries a per-run chain-head override through the call stack
// (#85 per-intent rotation). The engine sets it when launching a worker run;
// resolution stays within the task's chain and never bypasses failover state.
type llmProfilePinKey struct{}

func withLLMProfilePin(ctx context.Context, profileID int64) context.Context {
	return context.WithValue(ctx, llmProfilePinKey{}, profileID)
}

func llmProfilePinFrom(ctx context.Context) (int64, bool) {
	if ctx == nil {
		return 0, false
	}
	id, ok := ctx.Value(llmProfilePinKey{}).(int64)
	return id, ok
}

type llmRequestMessagesKey struct{}

func withLLMRequestMessages(ctx context.Context, messages []llm.Message) context.Context {
	return context.WithValue(ctx, llmRequestMessagesKey{}, messages)
}

func llmRequestMessagesFrom(ctx context.Context) []llm.Message {
	if ctx == nil {
		return nil
	}
	msgs, _ := ctx.Value(llmRequestMessagesKey{}).([]llm.Message)
	return msgs
}

type taskLLMSelection struct {
	task         *Task
	profileID    int64
	revision     int64
	provider     llm.Provider
	nonStreaming bool
	// retry is the retry parameters resolved from the configuration selected this time (profile override → global policy → built-in default).
	// Retries within the same provider's safety window follow it, so switching to a different profile means switching to a different retry cadence.
	retry                agent.RetryConfig
	refusalFallback      []db.RefusalFallbackEntry
	fallbackProvider     func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error)
	primaryModel         string
	primaryEffort        string
	currentModel         string
	currentEffort        string
	isNative             bool
	initialFallbackIndex int
}

func (s taskLLMSelection) fallbackChoices() []agent.NativeModelChoice {
	choices := make([]agent.NativeModelChoice, 0, len(s.refusalFallback)+1)
	if s.primaryModel != "" {
		choices = append(choices, agent.NativeModelChoice{Model: s.primaryModel, ReasoningEffort: s.primaryEffort})
	}
	for _, entry := range s.refusalFallback {
		if entry.Model == "" {
			continue
		}
		effort := entry.ReasoningEffort
		if effort == "" {
			effort = s.primaryEffort
		}
		choices = append(choices, agent.NativeModelChoice{Model: entry.Model, ReasoningEffort: effort})
	}
	return choices
}

type taskLLMStreamHooks struct {
	current    func() (taskLLMSelection, error)
	currentFor func(context.Context) (taskLLMSelection, error)
	exhaust    func(taskLLMSelection, error) (db.TaskLLMTransition, error)
	transition func(taskLLMSelection, db.TaskLLMTransition, error)
	// refusalFallback reports the opt-in setting; nil means off.
	refusalFallback func() bool
}

func (h taskLLMStreamHooks) resolveCurrent(ctx context.Context) (taskLLMSelection, error) {
	if h.currentFor != nil {
		return h.currentFor(ctx)
	}
	if h.current != nil {
		return h.current()
	}
	return taskLLMSelection{}, errors.New("no current provider resolver configured")
}
func (h taskLLMStreamHooks) refusalFallbackOn() bool {
	return h.refusalFallback != nil && h.refusalFallback()
}

// errProviderRefused is the cause of a refusal-driven failover. It stays apart from
// quota errors so a refused entry is recorded as refused, not quota_exhausted.
var errProviderRefused = errors.New("provider refused the request")

// current resolves the provider this role runs on, by precedence:
// Agent binding → task LLM configuration chain → global/environment configuration.
// The binding takes precedence over the task chain: if a role has been explicitly assigned a model, it always runs on that model; if the binding does not exist or
// construction fails, it only falls back to the task chain, and when the task chain is empty it falls back to the global configuration.
// The returned profile id is non-zero only when the task chain is used; streamTaskLLM relies on this to decide whether a quota error should advance the task's failover state.
// should advance the task's failover state (the binding/global paths do not change task chain state; the existing semantics are kept).
func (r *taskLLMRuntime) current() (taskLLMSelection, error) {
	return r.currentFor(context.Background())
}

// currentFor resolves like current, honoring a per-run profile pin set by the
// engine for per-intent rotation (#85). A pin is only a dispatch preference:
// the chain must still be in a ready state (an exhausted chain with no active
// head stays exhausted) and the pinned id must belong to the task's chain.
func (r *taskLLMRuntime) currentFor(ctx context.Context) (taskLLMSelection, error) {
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return taskLLMSelection{}, err
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil {
		return taskLLMSelection{}, err
	}
	if pt == nil {
		return taskLLMSelection{}, fmt.Errorf("task %s not found", r.taskID)
	}
	r.s.syncTaskLLMState(pt)
	t, _ := r.s.m.Task(r.taskID)
	sel := taskLLMSelection{task: t, revision: pt.LLMChainRevision}
	if prov, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		sel.provider, sel.retry = prov, cfg.Retry
		sel.nonStreaming = !cfg.Stream || llm.RequiresComplete(prov)
		return sel, nil
	}
	if len(pt.LLMProfileIDs) > 0 {
		if pt.ActiveLLMProfileID == nil {
			return sel, &taskLLMError{taskID: r.taskID, chainExhausted: true, cause: errors.New("all selected profiles are quota exhausted")}
		}
		sel.profileID = *pt.ActiveLLMProfileID
		if pin, ok := llmProfilePinFrom(ctx); ok && pin != sel.profileID {
			for _, id := range pt.LLMProfileIDs {
				if id == pin {
					sel.profileID = pin
					break
				}
			}
		}
		prov, cfg, ok := r.s.providerForProfile(sel.profileID)
		if !ok {
			return sel, fmt.Errorf("LLM profile #%d is missing or invalid", sel.profileID)
		}
		p, _ := r.s.m.pg.ProfileByID(sel.profileID)
		if p != nil {
			sel.primaryModel = p.Model
			sel.primaryEffort = p.ReasoningEffort
			sel.refusalFallback = p.RefusalFallback
		}
		// If the context carries prior turn messages, check if a previous refusal in this session
		// already transitioned to a valid branch model on the same profile/provider chain.
		if p != nil && len(p.RefusalFallback) > 0 {
			msgs := llmRequestMessagesFrom(ctx)
			if len(msgs) > 0 {
				allowedChainModels := make([]string, 0, len(p.RefusalFallback)+1)
				if p.Model != "" {
					allowedChainModels = append(allowedChainModels, p.Model)
				}
				for _, entry := range p.RefusalFallback {
					if entry.Model != "" {
						allowedChainModels = append(allowedChainModels, entry.Model)
					}
				}
				nativeProv := nativeProxyProvider(p.AuthMethod)
				pidStr := strconv.FormatInt(sel.profileID, 10)
				if branchModel, branchEffort, ok := agent.DeriveSessionChainModel(ctx, msgs, pidStr, nativeProv, allowedChainModels); ok {
					primaryEffort := p.ReasoningEffort
					if branchModel == p.Model && branchEffort == primaryEffort {
						sel.currentModel = branchModel
						sel.currentEffort = branchEffort
						sel.initialFallbackIndex = -1
					} else {
						matched := false
						for idx, entry := range p.RefusalFallback {
							eff := entry.ReasoningEffort
							if eff == "" {
								eff = p.ReasoningEffort
							}
							if entry.Model == branchModel && eff == branchEffort {
								sel.currentModel = branchModel
								sel.currentEffort = branchEffort
								sel.initialFallbackIndex = idx
								if bProv, bCfg, bOk := r.s.providerForProfileFallback(sel.profileID, entry.Model, entry.ReasoningEffort); bOk {
									prov = bProv
									cfg = bCfg
								}
								matched = true
								break
							}
						}
						if !matched {
							return sel, fmt.Errorf("session active branch %s (effort %q) not found in profile #%d chain", branchModel, branchEffort, sel.profileID)
						}
					}
				}
			}
		}

		if p != nil {
			sel.isNative = nativeProxyProvider(p.AuthMethod) != ""
		}

		sel.provider, sel.retry = prov, cfg.Retry
		sel.nonStreaming = !cfg.Stream || llm.RequiresComplete(prov)
		if !sel.nonStreaming {
			for _, id := range pt.LLMProfileIDs {
				member, err := r.s.m.pg.ProfileByID(id)
				if err != nil {
					return sel, err
				}
				if member != nil && nativeProxyProvider(member.AuthMethod) != "" {
					sel.nonStreaming = true
					break
				}
			}
		}
		sel.fallbackProvider = func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			fProv, fCfg, fOk := r.s.providerForProfileFallback(sel.profileID, entry.Model, entry.ReasoningEffort)
			if !fOk {
				return nil, agent.RetryConfig{}, fmt.Errorf("failed to build fallback provider for profile #%d model %s", sel.profileID, entry.Model)
			}
			return fProv, fCfg.Retry, nil
		}
		return sel, nil
	}
	prov, cfg, ok := r.s.globalProvider()
	if !ok {
		return sel, fmt.Errorf("task %s has no available fallback LLM provider", r.taskID)
	}
	sel.provider, sel.retry = prov, cfg.Retry
	sel.nonStreaming = !cfg.Stream || llm.RequiresComplete(prov)
	return sel, nil
}

// activeCfg resolves the task's currently-active LLM config, mirroring current()'s
// source precedence (agent binding → active chain profile → global). Read-only and
// best-effort: ok=false when nothing resolves, leaving the per-setting fallback to
// the caller. If failover switches profiles, the change takes effect on the next
// agent run (a fresh Session is built per run in captureRun).
func (r *taskLLMRuntime) activeCfg() (agent.Config, bool) {
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return agent.Config{}, false
	}
	pt, err := r.s.m.pg.GetTask(taskNum)
	if err != nil || pt == nil {
		return agent.Config{}, false
	}
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg, true
	}
	if len(pt.LLMProfileIDs) > 0 && pt.ActiveLLMProfileID != nil {
		if _, cfg, ok := r.s.providerForProfile(*pt.ActiveLLMProfileID); ok {
			return cfg, true
		}
	}
	if _, cfg, ok := r.s.globalProvider(); ok {
		return cfg, true
	}
	return agent.Config{}, false
}

// nonStreaming includes every selected route that may receive this call.
func (r *taskLLMRuntime) nonStreaming() bool {
	selection, err := r.current()
	return err == nil && selection.nonStreaming
}

type preparedTaskLLMSelectionKey struct{ runtime *taskLLMRuntime }

func (r *taskLLMRuntime) RequiresComplete() bool { return r.nonStreaming() }

func (r *taskLLMRuntime) PrepareModelCall(ctx context.Context, req llm.CompletionRequest, _ bool) (context.Context, bool, error) {
	selection, err := r.currentFor(withLLMRequestMessages(ctx, req.Messages))
	if err != nil {
		return ctx, false, err
	}
	return context.WithValue(ctx, preparedTaskLLMSelectionKey{r}, selection), selection.nonStreaming, nil
}

// maxTokens returns the currently-active source's per-reply output cap.
// Unresolvable → 0, i.e. send no cap, matching the pre-setting behaviour.
func (r *taskLLMRuntime) maxTokens() int {
	cfg, _ := r.activeCfg() // Zero value 0 when no configuration was resolved.
	return cfg.MaxTokens
}

func parseTaskID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid task id %q", id)
	}
	return n, nil
}

// streamHooks builds the failover/exhaustion callbacks shared by Stream and
// Complete: how to read the current profile selection, how to mark it quota
// exhausted, and how to emit a failover transition.
func (r *taskLLMRuntime) streamHooks(ctx context.Context) taskLLMStreamHooks {
	resolve := r.currentFor
	if prepared, ok := ctx.Value(preparedTaskLLMSelectionKey{r}).(taskLLMSelection); ok {
		first := true
		resolve = func(ctx context.Context) (taskLLMSelection, error) {
			if first {
				first = false
				return prepared, nil
			}
			return r.currentFor(ctx)
		}
	}
	return taskLLMStreamHooks{
		current:         r.current,
		currentFor:      resolve,
		refusalFallback: r.s.m.LLMRefusalFallbackEnabled,
		exhaust: func(selection taskLLMSelection, cause error) (db.TaskLLMTransition, error) {
			taskNum, _ := parseTaskID(r.taskID)
			mark := r.s.m.pg.MarkTaskLLMProfileQuotaExhaustedAtRevision
			if errors.Is(cause, errProviderRefused) {
				mark = r.s.m.pg.MarkTaskLLMProfileRefusedAtRevision
			}
			transition, err := mark(taskNum, selection.profileID, selection.revision, cause.Error())
			if err != nil {
				return transition, err
			}
			if pt, getErr := r.s.m.pg.GetTask(taskNum); getErr == nil && pt != nil {
				r.s.syncTaskLLMState(pt)
			}
			return transition, nil
		},
		transition: func(selection taskLLMSelection, transition db.TaskLLMTransition, cause error) {
			r.s.emitTaskLLMTransition(selection.task, transition, cause)
		},
	}
}

func (r *taskLLMRuntime) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	ctx = withLLMRequestMessages(ctx, req.Messages)
	return streamTaskLLM(ctx, r.taskID, req, r.streamHooks(ctx))
}

// Complete is the non-streaming counterpart of Stream. A non-streaming call is
// atomic — it never delivers partial output — so every failure is safe to retry
// on the same provider or fail over to the next profile without risking
// duplicated model output or tool execution (the "committed" bookkeeping the
// streaming path needs is unnecessary here).
func (r *taskLLMRuntime) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx = llmrec.WithTaskID(ctx, r.taskID)
	ctx = withLLMRequestMessages(ctx, req.Messages)
	return completeTaskLLM(ctx, r.taskID, req, r.streamHooks(ctx))
}

func completeTaskLLM(ctx context.Context, taskID string, req llm.CompletionRequest, hooks taskLLMStreamHooks) (llm.Message, string, llm.Usage, error) {
	for {
		selection, err := hooks.resolveCurrent(ctx)
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		selCtx := ctx
		if len(selection.refusalFallback) > 0 {
			selCtx = agent.WithAllowedFallbackChoices(selCtx, selection.fallbackChoices())
		}

		currentProvider := selection.provider
		currentRetry := selection.retry
		fallbackIndex := selection.initialFallbackIndex
		if selection.currentModel == "" {
			fallbackIndex = -1
		}
		for {
			var (
				msg     llm.Message
				sr      string
				usage   llm.Usage
				callErr error
			)
			// Retries within the same provider's safety window: a non-streaming call either succeeds as a whole or fails as a whole, with no
			// partially delivered output midway, so any transient failure can be retried as-is.
			var callCtx context.Context
			retries, backoffOf := sameProviderRetryPolicy(currentRetry)
			for attempt := 0; ; attempt++ {
				callCtx = llmrec.WithRefusalSink(selCtx)
				msg, sr, usage, callErr = currentProvider.Complete(callCtx, req)
				if callErr != nil && !errors.Is(callErr, llm.ErrHistoryRejected) && ctx.Err() == nil &&
					attempt < retries && isRetryableStreamError(callErr) {
					backoff := backoffOf(attempt)
					log.Printf("[task-llm] task %s non-streaming call failed; retrying with the same provider after %v (%d/%d): %v",
						taskID, backoff, attempt+1, retries, callErr)
					if sleepCtx(ctx, backoff) {
						break // If ctx is cancelled during backoff → stop retrying
					}
					continue
				}
				break
			}
			if errors.Is(callErr, llm.ErrHistoryRejected) {
				return llm.Message{}, "", llm.Usage{}, callErr
			}
			if callErr == nil {
				refused := sr == "refusal" || llmrec.RefusalObserved(callCtx)
				if !refused || selection.profileID == 0 || !hooks.refusalFallbackOn() {
					resetLLMFailStreak(taskID, selection.profileID)
					return msg, sr, usage, nil
				}
				// Before advancing the task chain, try the next entry in this profile's refusal fallback chain.
				if fallbackIndex+1 < len(selection.refusalFallback) && selection.fallbackProvider != nil {
					fallbackIndex++
					entry := selection.refusalFallback[fallbackIndex]
					fbProv, fbRetry, fbErr := selection.fallbackProvider(entry)
					if fbErr != nil {
						return llm.Message{}, "", llm.Usage{}, fbErr
					}
					currentProvider = fbProv
					currentRetry = fbRetry
					if selection.isNative {
						fromList := make([]string, 0, fallbackIndex+1)
						if selection.currentModel != "" {
							fromList = append(fromList, selection.currentModel)
						} else if selection.primaryModel != "" {
							fromList = append(fromList, selection.primaryModel)
						}
						for k := range fallbackIndex {
							if selection.refusalFallback[k].Model != "" {
								fromList = append(fromList, selection.refusalFallback[k].Model)
							}
						}
						selCtx = llmrec.WithHandoffMetadata(selCtx, llmrec.HandoffMetadata{
							FromModels:  fromList,
							ToModel:     entry.Model,
							Kind:        "readable_history",
							PrefixCount: len(req.Messages),
						})
					}
					continue
				}
				// Complete is atomic and nothing was delivered, so the same request can move on.
				transition, markErr := hooks.exhaust(selection, errProviderRefused)
				if markErr != nil {
					return llm.Message{}, "", llm.Usage{}, fmt.Errorf("mark profile refused: %w", markErr)
				}
				if transition.Advanced && !transition.Stale && hooks.transition != nil {
					hooks.transition(selection, transition, errProviderRefused)
				}
				if !transition.Stale && transition.NextProfileID == nil {
					return llm.Message{}, "", llm.Usage{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: errProviderRefused}
				}
				break
			}
			// profileID=0: the explicit chain has been cleared; non-quota error: pass through. Neither case changes the task failover state.
			// Non-quota failures on a chain profile escalate after a consecutive
			// streak (#99): same advance path as quota exhaust, truthful reason.
			if selection.profileID != 0 && !isQuotaExhaustedError(callErr) && ctx.Err() == nil {
				if noteLLMCallFailure(taskID, selection.profileID) {
					cause := fmt.Errorf("profile #%d failed %d consecutive calls (last: %w)", selection.profileID, llmFailStreakThreshold, callErr)
					transition, markErr := hooks.exhaust(selection, cause)
					if markErr != nil {
						return llm.Message{}, "", llm.Usage{}, fmt.Errorf("mark profile exhausted after %v: %w", callErr, markErr)
					}
					if transition.Advanced && !transition.Stale && hooks.transition != nil {
						hooks.transition(selection, transition, callErr)
					}
					if !transition.Stale && transition.NextProfileID == nil {
						return llm.Message{}, "", llm.Usage{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: callErr}
					}
					break // replay the same logical request on the next profile
				}
				return llm.Message{}, "", llm.Usage{}, callErr
			}
			// profileID=0: the explicit chain has been cleared; non-quota error: pass through. Neither case changes the task failover state.
			if selection.profileID == 0 || !isQuotaExhaustedError(callErr) {
				return llm.Message{}, "", llm.Usage{}, callErr
			}
			transition, markErr := hooks.exhaust(selection, callErr)
			if markErr != nil {
				return llm.Message{}, "", llm.Usage{}, fmt.Errorf("mark profile quota exhausted after %v: %w", callErr, markErr)
			}
			if transition.Advanced && !transition.Stale && hooks.transition != nil {
				hooks.transition(selection, transition, callErr)
			}
			if !transition.Stale && transition.NextProfileID == nil {
				return llm.Message{}, "", llm.Usage{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: callErr}
			}
			// No output has been delivered to the caller, so it is safe to replay the same logical request with the next profile.
			break
		}
	}
}

func streamTaskLLM(ctx context.Context, taskID string, req llm.CompletionRequest, hooks taskLLMStreamHooks) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for {
			selection, err := hooks.resolveCurrent(ctx)
			if err != nil {
				yield(llm.StreamEvent{}, err)
				return
			}
			if selection.nonStreaming || llm.RequiresComplete(selection.provider) {
				yield(llm.StreamEvent{}, llm.ErrModelRouteChanged)
				return
			}

			selCtx := ctx
			if len(selection.refusalFallback) > 0 {
				selCtx = agent.WithAllowedFallbackChoices(selCtx, selection.fallbackChoices())
			}

			currentProvider := selection.provider
			currentRetry := selection.retry
			fallbackIndex := selection.initialFallbackIndex
			if selection.currentModel == "" {
				fallbackIndex = -1
			}
			var committed bool
			for {
				var pending []llm.StreamEvent
				var streamErr error
				var refused bool
				var callCtx context.Context
				retries, backoffOf := sameProviderRetryPolicy(currentRetry)
				// Retry within the same provider's safe window: before committed (no output has been delivered to the caller yet)
				// transient failures can be replayed as-is without repeating model output or tool execution. After committed,
				// a ctx cancellation, or a deterministic/quota error, breaks out and hands off to the existing passthrough/failover logic below.
				for attempt := 0; ; attempt++ {
					committed = false
					pending = nil
					streamErr = nil
					refused = false
					callCtx = llmrec.WithRefusalSink(selCtx)
					for event, err := range currentProvider.Stream(callCtx, req) {
						if err != nil {
							streamErr = err
							break
						}
						if event.Type == llm.SEMessageDelta && event.StopReason == "refusal" {
							refused = true
						}
						if !committed && !streamEventCommitsOutput(event) {
							pending = append(pending, event)
							continue
						}
						if !committed {
							for _, buffered := range pending {
								if !yield(buffered, nil) {
									return
								}
							}
							pending = nil
							committed = true
						}
						if !yield(event, nil) {
							return
						}
					}
					if streamErr != nil && !errors.Is(streamErr, llm.ErrHistoryRejected) && !committed && ctx.Err() == nil &&
						attempt < retries && isRetryableStreamError(streamErr) {
						backoff := backoffOf(attempt)
						log.Printf("[task-llm] task %s stream failed before commitment; retrying with the same provider after %v (%d/%d): %v",
							taskID, backoff, attempt+1, retries, streamErr)
						if sleepCtx(ctx, backoff) {
							break // If ctx is cancelled during backoff → stop retrying
						}
						continue
					}
					break
				}
				if errors.Is(streamErr, llm.ErrHistoryRejected) {
					yield(llm.StreamEvent{}, streamErr)
					return
				}
				if streamErr == nil {
					if (refused || llmrec.RefusalObserved(callCtx)) && selection.profileID != 0 && hooks.refusalFallbackOn() {
						// Before advancing the task chain, try the next entry in this profile's refusal fallback chain (if output not committed).
						if !committed && fallbackIndex+1 < len(selection.refusalFallback) && selection.fallbackProvider != nil {
							fallbackIndex++
							entry := selection.refusalFallback[fallbackIndex]
							fbProv, fbRetry, fbErr := selection.fallbackProvider(entry)
							if fbErr != nil {
								yield(llm.StreamEvent{}, fbErr)
								return
							}
							currentProvider = fbProv
							currentRetry = fbRetry
							if selection.isNative {
								fromList := make([]string, 0, fallbackIndex+1)
								if selection.currentModel != "" {
									fromList = append(fromList, selection.currentModel)
								} else if selection.primaryModel != "" {
									fromList = append(fromList, selection.primaryModel)
								}
								for k := range fallbackIndex {
									if selection.refusalFallback[k].Model != "" {
										fromList = append(fromList, selection.refusalFallback[k].Model)
									}
								}
								selCtx = llmrec.WithHandoffMetadata(selCtx, llmrec.HandoffMetadata{
									FromModels:  fromList,
									ToModel:     entry.Model,
									Kind:        "readable_history",
									PrefixCount: len(req.Messages),
								})
							}
							continue
						}
						transition, markErr := hooks.exhaust(selection, errProviderRefused)
						if markErr != nil {
							yield(llm.StreamEvent{}, fmt.Errorf("mark profile refused: %w", markErr))
							return
						}
						if transition.Advanced && !transition.Stale && hooks.transition != nil {
							hooks.transition(selection, transition, errProviderRefused)
						}
						// Nothing reached the caller yet: drop the pending refusal and replay the same request on next profile in task chain.
						if !committed && (transition.Stale || transition.NextProfileID != nil) {
							break
						}
						// Output already reached the caller: replaying would duplicate tool execution,
						// and reporting success would hide the refusal.
						yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: errProviderRefused})
						return
					}
					resetLLMFailStreak(taskID, selection.profileID)
					for _, buffered := range pending {
						if !yield(buffered, nil) {
							return
						}
					}
					return
				}
				// Non-quota failures on a chain profile escalate after a consecutive
				// streak (#99), mirroring completeTaskLLM. Escalation only applies to
				// uncommitted streams: once events reached the caller, replaying on a
				// new profile could duplicate delivered output, so the error surfaces.
				if selection.profileID != 0 && !committed && !isQuotaExhaustedError(streamErr) && ctx.Err() == nil {
					if noteLLMCallFailure(taskID, selection.profileID) {
						cause := fmt.Errorf("profile #%d failed %d consecutive calls (last: %w)", selection.profileID, llmFailStreakThreshold, streamErr)
						transition, markErr := hooks.exhaust(selection, cause)
						if markErr != nil {
							yield(llm.StreamEvent{}, fmt.Errorf("mark profile exhausted after %v: %w", streamErr, markErr))
							return
						}
						if transition.Advanced && !transition.Stale && hooks.transition != nil {
							hooks.transition(selection, transition, streamErr)
						}
						if !transition.Stale && transition.NextProfileID == nil {
							yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: streamErr})
							return
						}
						break // nothing delivered — safe to replay on the next profile
					}
				}
				// profileID=0 means the explicit chain was cleared while this stable task
				// bundle was still in use. Agent/global fallback errors follow the legacy
				// behavior and never mutate task failover state.
				if selection.profileID == 0 || !isQuotaExhaustedError(streamErr) {
					for _, buffered := range pending {
						if !yield(buffered, nil) {
							return
						}
					}
					yield(llm.StreamEvent{}, streamErr)
					return
				}
				transition, markErr := hooks.exhaust(selection, streamErr)
				if markErr != nil {
					cause := fmt.Errorf("mark profile quota exhausted after %v: %w", streamErr, markErr)
					if committed {
						// Output may already have driven tool execution. Report the persistence
						// failure, but classify it as router-handled so the worker does not
						// replay the entire intent and duplicate those side effects.
						yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, cause: cause})
					} else {
						yield(llm.StreamEvent{}, cause)
					}
					return
				}
				if transition.Advanced && !transition.Stale && hooks.transition != nil {
					hooks.transition(selection, transition, streamErr)
				}
				if committed || (!transition.Stale && transition.NextProfileID == nil) {
					yield(llm.StreamEvent{}, &taskLLMError{taskID: taskID, chainExhausted: transition.ChainExhausted, cause: streamErr})
					return
				}
				// No event reached the caller, so replaying the same logical request on
				// the next profile cannot duplicate model output or tool execution.
				break
			}
		}
	}
}

func streamEventCommitsOutput(event llm.StreamEvent) bool {
	switch event.Type {
	case llm.SETextDelta, llm.SEToolInputJSON:
		return event.Text != ""
	case llm.SEToolUseStart:
		return true
	default:
		return false
	}
}

// The default number of retries against the same provider within the pre-commit safe window. The SDK's doStream only retries the
// connection phase (before a 200 is received); once the stream starts, transient failures such as mid-stream disconnects, overloaded, or 429 inside the stream
// bubble up directly as model_error with zero retries. As long as not a single token has been handed to the caller (!committed), replaying
// Identical requests won't repeat model output or tool side effects, so we add a same-provider backoff retry layer here,
// to absorb these blips before the whole intent is re-run. Can be overridden by the LLM configuration's retry settings or rewritten by the global retry policy.
const sameProviderStreamRetries = 2

// sameProviderRetryBackoff is the [default] backoff before the attempt-th retry (0.5s, 1s…, capped at 4s),
// the same style as the SDK's exponential schedule but with a smaller cap, so it doesn't hold up the worker's wind-down or cancellation response.
// Exposed as a variable so tests can set the backoff to zero.
var sameProviderRetryBackoff = func(attempt int) time.Duration {
	return min(500*time.Millisecond*(1<<attempt), 4*time.Second)
}

// sameProviderRetryPolicy resolves which set of same-provider retry parameters applies to this call: if the configuration sets a count, then
// if an interval is set, it replaces the exponential backoff with a fixed interval, and when neither is set,
// it behaves byte-for-byte identically to before the settings were made configurable.
func sameProviderRetryPolicy(r agent.RetryConfig) (retries int, backoff func(int) time.Duration) {
	retries, backoff = sameProviderStreamRetries, sameProviderRetryBackoff
	if r.StreamAttempts != 0 {
		retries = max(r.StreamAttempts, 0)
	}
	if r.StreamInterval > 0 {
		d := r.StreamInterval
		backoff = func(int) time.Duration { return d }
	}
	return retries, backoff
}

// isRetryableStreamError determines whether a "pre-commit stream failure" is worth replaying on the same provider.
// Transient transport interruptions, provider overload, and rate limiting recover on their own and are safe to retry; the following three categories are not retried:
//   - Quota exhausted: leave it to profile failover; don't burn retries here for nothing
//   - Context too long: replaying the same request won't help; leave it to the harness's reactive compression as the fallback
//   - Deterministic 4xx rejections (400/401/403/404/422): these will fail regardless of which provider it goes to
func isRetryableStreamError(err error) bool {
	if err == nil {
		return false
	}
	if isQuotaExhaustedError(err) {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "too long") || strings.Contains(s, "context length") ||
		strings.Contains(s, "context_length") || strings.Contains(s, "maximum context") ||
		strings.Contains(s, "status 413") {
		return false
	}
	for _, code := range []string{"status 400", "status 401", "status 403", "status 404", "status 422"} {
		if strings.Contains(s, code) {
			return false
		}
	}
	// Everything else (transport reset/EOF/timeout, 408/429/5xx, in-stream error events such as anthropic
	// overloaded_error, etc.) is treated as transient and retries are allowed.
	return true
}

// CompactionWindow mirrors current()'s precedence so the context window always
// matches the provider the role will actually stream on.
func (r *taskLLMRuntime) CompactionWindow() int {
	if _, cfg, ok := r.s.agentBindingProvider(r.agentKey); ok {
		return cfg.CompactionWindow()
	}
	taskNum, err := parseTaskID(r.taskID)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	chain, err := r.s.m.pg.TaskLLMProfiles(taskNum)
	if err != nil {
		return (agent.Config{}).CompactionWindow()
	}
	if len(chain) == 0 {
		if _, cfg, ok := r.s.globalProvider(); ok {
			return cfg.CompactionWindow()
		}
		return (agent.Config{}).CompactionWindow()
	}
	minimum := 0
	for _, entry := range chain {
		if cfg, ok := r.s.loadProfileConfig(entry.ProfileID); ok {
			window := cfg.CompactionWindow()
			if minimum == 0 || window < minimum {
				minimum = window
			}
		}
	}
	if minimum == 0 {
		return (agent.Config{}).CompactionWindow()
	}
	return minimum
}

// agentBindingProvider resolves the profile a role is explicitly bound to
// (agents.llm_profile_id) — the highest-precedence level for task agents. ok=false
// when the role has no binding or the bound profile no longer builds, so callers
// fall through to the task chain. A bound profile stays exclusive unless
// llm_pool_bind_fallback is on, which is what poolForBinding encodes.
func (s *Server) agentBindingProvider(agentKey string) (llm.Provider, agent.Config, bool) {
	id := s.effectiveProfileForAgent(agentKey, nil)
	if id == nil {
		return nil, agent.Config{}, false
	}
	prov, cfg, ok := s.providerForProfile(*id)
	if !ok {
		return nil, agent.Config{}, false
	}
	return s.poolForBinding(*id, prov, cfg), cfg, true
}

// globalProvider returns the process-wide provider (persisted active profile or
// environment config) — the last resort once a role has neither a binding nor a
// task chain.
func (s *Server) globalProvider() (llm.Provider, agent.Config, bool) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if !s.llmOn || s.llmProv == nil {
		return nil, agent.Config{}, false
	}
	return s.llmProv, s.llmCfg, true
}

// taskRuntimeAvailable reports whether every listed role can resolve a provider
// under the runtime precedence in current(): the role's own binding first, then
// the task chain, then global. An exhausted chain is a hard stop for unbound
// roles rather than a silent fall through to global — same as current().
func (s *Server) taskRuntimeAvailable(t *Task, agentKeys ...string) bool {
	if t == nil || len(agentKeys) == 0 {
		return false
	}
	state := t.llmStateSnapshot()
	unboundReady := false
	if len(state.ProfileIDs) > 0 {
		if state.ActiveID != nil {
			_, _, unboundReady = s.providerForProfile(*state.ActiveID)
		}
	} else {
		_, _, unboundReady = s.globalProvider()
	}
	for _, key := range agentKeys {
		if _, _, ok := s.agentBindingProvider(key); ok {
			continue
		}
		if !unboundReady {
			return false
		}
	}
	return true
}

func (s *Server) invalidateTaskAgents() {
	s.taskAgentMu.Lock()
	s.taskAgents = map[string]*taskAgentBundle{}
	s.taskAgentMu.Unlock()
}

func (s *Server) agentsForTask(t *Task) *taskAgentBundle {
	s.taskAgentMu.Lock()
	defer s.taskAgentMu.Unlock()
	if bundle := s.taskAgents[t.ID]; bundle != nil {
		return bundle
	}
	goalRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "goals"}
	plannerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "planner"}
	workerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "worker"}
	mainRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "mainagent"}
	tx := transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
	window := workerRuntime.CompactionWindow()
	wk := agent.NewWorker(workerRuntime, "task-router", s.m.dir, tx, window, s.agentMaxTurns("worker"))
	wk.SetFindingRecorder(s.evidenceStore())
	wk.SetCompactionWindowResolver(workerRuntime.CompactionWindow)
	wk.SetNonStreaming(workerRuntime.nonStreaming) // Per the task's currently active profile's streaming toggle (read every turn)
	wk.SetMaxTokens(workerRuntime.maxTokens)       // Same as above: the output limit also follows the currently active profile
	wk.SetNoaEnabled(s.m.NoaCompactionEnabled)     // Experimental feature: noa context compression (platform-level switch, read per run)
	wk.SetRunTimeout(time.Duration(s.agentRunSeconds("worker")) * time.Second)
	wk.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	wk.SetWebSearch(s.webSearchFor("worker"))
	wk.SetConstraintInject(s.constraintInjectWorker) // Operation-constraint injection worker (configurable, enabled by default)
	pl := agent.NewPlanner(plannerRuntime, "task-router", s.m.dir, tx, plannerRuntime.CompactionWindow(), s.agentMaxTurns("planner"))
	pl.SetFindingRecorder(s.evidenceStore())
	pl.SetGuard(t.Guard)
	pl.SetCompactionWindowResolver(plannerRuntime.CompactionWindow)
	pl.SetNonStreaming(plannerRuntime.nonStreaming)
	pl.SetMaxTokens(plannerRuntime.maxTokens)
	pl.SetNoaEnabled(s.m.NoaCompactionEnabled) // Experimental feature: noa context compression (platform-level switch, read per run)
	pl.SetKillWork(s.engine.KillWork)
	pl.SetSteerWork(s.engine.SteerWork)
	pl.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	pl.SetWebSearch(s.webSearchFor("planner"))
	pl.SetConstraintInject(s.constraintInjectPlanner) // Operation-constraint injection planner (configurable, enabled by default)
	// cold-digest §7: Background compaction of cold nodes. The engine is actually driven by the authoritative resolver through this per-task planner
	// (agentsForTask), the Compactor must be wired in here. It goes through the planner provider chosen by task routing (§4: same model as the agent, resolved along the task's LLM chain), and compaction generates the body in one shot via Complete.
	// Same model, parsed along with the task LLM chain; compression uses Complete to generate the body in one shot.
	pl.SetCompactor(agent.NewCompactor(plannerRuntime, "task-router"))
	// RSI shadow mode: select evidence-backed lessons for this task. Off by
	// default; shadow logs what would be shown, inject appends the block.
	s.wireTaskLessons(t, wk, pl)
	main := agent.NewMainAgent(mainRuntime, "task-router", s.m.dir, tx, mainRuntime.CompactionWindow(), s.agentMaxTurns("mainagent"))
	main.SetFindingRecorder(s.evidenceStore())
	main.SetGuard(t.Guard)
	main.SetCompactionWindowResolver(mainRuntime.CompactionWindow)
	main.SetNonStreaming(mainRuntime.nonStreaming)
	main.SetMaxTokens(mainRuntime.maxTokens)
	main.SetNoaEnabled(s.m.NoaCompactionEnabled) // Experimental feature: noa context compression (platform-level switch, read per run)
	main.SetProxy(s.m.ProxyAddr(), s.m.ProxyCACert())
	main.SetWebSearch(s.webSearchFor("mainagent"))
	main.SetSteerWork(s.engine.SteerWork) // steer_work: real-time human course correction of a running work item
	bundle := &taskAgentBundle{
		runtime: goalRuntime, plannerRuntime: plannerRuntime, workerRuntime: workerRuntime,
		mainRuntime: mainRuntime, pl: pl, wk: wk, main: main,
	}
	s.taskAgents[t.ID] = bundle
	return bundle
}

func (s *Server) syncTaskLLMState(pt *db.Task) {
	if pt == nil {
		return
	}
	id := fmt.Sprintf("%d", pt.ID)
	s.m.mu.Lock()
	if task := s.m.tasks[id]; task != nil {
		task.setLLMState(pt.LLMProfileID, pt.ActiveLLMProfileID, pt.LLMProfileIDs, pt.LLMChainRevision, pt.LLMFailoverState, pt.LLMFailoverReason)
	}
	s.m.mu.Unlock()
}

func (s *Server) emitTaskLLMTransition(t *Task, transition db.TaskLLMTransition, cause error) {
	if t == nil {
		return
	}
	previous := s.llmAuditProfile(transition.PreviousProfileID)
	var next *llmAuditProfile
	if transition.NextProfileID != nil {
		next = s.llmAuditProfile(*transition.NextProfileID)
	}
	mode := "automatic"
	kind := "llm_switch"
	summary := fmt.Sprintf("%s quota exhausted", llmAuditProfileLabel(previous))
	if transition.NextProfileID != nil {
		summary += fmt.Sprintf(", subsequent calls switch to %s", llmAuditProfileLabel(next))
	} else {
		mode = "exhausted"
		kind = "llm_failover"
		summary += ", the configuration chain is exhausted"
	}
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: mode, Reason: cause.Error(), Previous: previous, Next: next,
	}})
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: kind, IsError: transition.ChainExhausted, Summary: summary, Detail: cause.Error(), Metadata: metadata})
	log.Printf("[llm-failover] task %s: %s", t.ID, summary)
}

func (s *Server) llmAuditProfile(id int64) *llmAuditProfile {
	if id <= 0 || s.m == nil || s.m.pg == nil {
		return nil
	}
	p, err := s.m.pg.ProfileByID(id)
	if err != nil || p == nil {
		return &llmAuditProfile{ID: id, Name: fmt.Sprintf("Profile #%d", id)}
	}
	return &llmAuditProfile{ID: p.ID, Name: p.Name, Format: p.Format, Model: p.Model}
}

func llmAuditProfileLabel(profile *llmAuditProfile) string {
	if profile == nil {
		return "Default profile"
	}
	name := profile.Name
	if name == "" {
		name = fmt.Sprintf("Profile #%d", profile.ID)
	}
	detail := []string{}
	if profile.Format != "" {
		detail = append(detail, profile.Format)
	}
	if profile.Model != "" {
		detail = append(detail, profile.Model)
	}
	if len(detail) == 0 {
		return name
	}
	return fmt.Sprintf("%s（%s）", name, strings.Join(detail, " / "))
}

func sameOptionalID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *Server) emitManualTaskLLMSwitch(t *Task, previousID, nextID *int64) db.Activity {
	previous := (*llmAuditProfile)(nil)
	next := (*llmAuditProfile)(nil)
	if previousID != nil {
		previous = s.llmAuditProfile(*previousID)
	}
	if nextID != nil {
		next = s.llmAuditProfile(*nextID)
	}
	summary := fmt.Sprintf("User manually switched the task LLM from %s to %s", llmAuditProfileLabel(previous), llmAuditProfileLabel(next))
	metadata, _ := json.Marshal(llmActivityMetadata{LLMTransition: llmTransitionAudit{
		Mode: "manual", Reason: "User manually switched the task LLM", Previous: previous, Next: next,
	}})
	return s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "llm_switch", Summary: summary, Detail: summary, Metadata: metadata})
}

package server

import (
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Server-side retry policy resolution; see docs/LLM\u91cd\u8bd5\u8bbe\u8ba1.md. Of the five layers:
//   - Connection setup / empty response / same-provider safety window are "endpoint-bound" and can be overridden per LLM configuration
//     with the global defaults (if a profile leaves a field blank, it inherits the global value; if the global value is also unset, the built-in default is used);
//   - Circuit breaker / intent re-run are process-level, with only one global instance.
//
// The global policy reads one row of settings from the DB once. All call sites are on low-frequency paths (building a provider, wrapping up a work item,
// saving configs), so an extra caching layer is not worth it. The circuit-breaker parameters are the exception: they are read on every failure path, so
// applyRetryPolicy pushes them to the Registry, which stores them.

// retryPolicy reads the global policy; a nil DB yields the zero policy (all
// layers on their built-in defaults).
func (s *Server) retryPolicy() db.LLMRetryPolicy {
	if s.m == nil || s.m.pg == nil {
		return db.LLMRetryPolicy{}
	}
	return s.m.pg.LLMRetryPolicy()
}

// resolveRetry layers one profile's override on top of the global policy and
// converts the result into the form agent.Config carries. Rules combine field by
// field, so a profile that only pins an interval still inherits the global count.
func resolveRetry(o db.RetryOverride, pol db.LLMRetryPolicy) agent.RetryConfig {
	connect := o.Connect.Or(pol.Connect)
	empty := o.Empty.Or(pol.Empty)
	stream := o.Stream.Or(pol.Stream)
	return agent.RetryConfig{
		// Counts keep their raw semantics here: "0 = default / negative = disabled". SDK MaxRetries /
		// EmptyResponseRetries is structurally identical, so just let it parse itself.
		ConnectAttempts: connect.Attempts, ConnectInterval: connect.Interval(),
		EmptyAttempts: empty.Attempts, EmptyInterval: empty.Interval(),
		StreamAttempts: stream.Attempts, StreamInterval: stream.Interval(),
	}
}

// applyProfileRetry fills cfg.Retry for a profile read from the DB.
func (s *Server) applyProfileRetry(cfg *agent.Config, p *db.LLMProfile) {
	if p == nil {
		return
	}
	cfg.Retry = resolveRetry(p.Retry, s.retryPolicy())
}

// Default values for the circuit breaker (round-robin cooldown), matching the ones built into llmpool — only override here when the user has configured a value.
// The default values for intent reruns are in engine.go's modelErrorRetries / modelErrorRetryBackoff.

// applyRetryPolicy pushes the process-wide layers of the policy into the objects
// that consume them on a hot path: the circuit-breaker registry. Called at
// startup and whenever the policy is saved.
func (s *Server) applyRetryPolicy() {
	pol := s.retryPolicy()
	if s.llmHealth != nil {
		s.llmHealth.SetPolicy(pol.Breaker.Attempts, pol.Breaker.Interval())
	}
}

// modelErrorRetryPolicy resolves the intent-level replay knobs (layer ⑤): how
// many times a model_error work is re-run and how long to back off between runs.
func (e *Engine) modelErrorRetryPolicy() (retries int, backoff time.Duration) {
	retries, backoff = modelErrorRetries, modelErrorRetryBackoff
	if e == nil || e.m == nil || e.m.pg == nil {
		return retries, backoff
	}
	rule := e.m.pg.LLMRetryPolicy().Intent
	if rule.Attempts != 0 {
		retries = max(rule.Attempts, 0)
	}
	if d := rule.Interval(); d > 0 {
		backoff = d
	}
	return retries, backoff
}

// emptyTurnNudgeLimit resolves how many empty-turn continuations one work may
// inject (see steerHooks.Stop). It deliberately reuses layer ②'s knob —— "empty response retry count": the two are two means to the same end.
// retry count": the two are two means to the same end. The SDK layer handles "no content block was produced at all", and the means is to turn
// The SDK layer handles "no content blocks at all"; its means is to resend the exact same request. This layer handles "only thinking, with neither body text nor tool calls"; its means is to append an instruction that lets the model
// the model continue with its existing thinking (resending verbatim is pointless for this context-shaped stall). The emptiness criteria
// differ because the SDK checks whether any event has been yielded, and thinking deltas are themselves events—but when users configure
// What "retry empty responses N times" is meant to express is "if the model produces no substantive content, try again once more"; both layers share a single count.
// only lines up with this mental model.
//
// Read the global policy rather than a profile's override: a run may switch profiles mid-way due to failover, and this
// is the overall cap for the entire intent and should not change just because the endpoint changes. Semantics are isomorphic with the SDK's emptyRetries():
// 0 = use the default defaultEmptyTurnNudges; -1 (negative) = disable empty-turn continuation; >0 = use that value.
func (e *Engine) emptyTurnNudgeLimit() int {
	if e == nil || e.m == nil || e.m.pg == nil {
		return defaultEmptyTurnNudges
	}
	switch n := e.m.pg.LLMRetryPolicy().Empty.Attempts; {
	case n == 0:
		return defaultEmptyTurnNudges
	case n < 0:
		return 0
	default:
		return n
	}
}

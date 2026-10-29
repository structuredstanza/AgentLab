package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sdkbridge"
	"github.com/Autumn-27/norma/llm"
)

// TestRefusalFallbackChainTriedInOrderOnSameProfile verifies that when a model refuses,
// entries in the profile's refusal fallback chain are tried in order on the same profile
// before any advance of the task chain.
func TestRefusalFallbackChainTriedInOrderOnSameProfile(t *testing.T) {
	defer withZeroRetryBackoff()()

	primary := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	fallbackOne := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	fallbackTwo := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "success-from-fallback-2"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}

	var triedModels []string
	selection := taskLLMSelection{
		profileID: 42,
		revision:  1,
		provider:  primary,
		refusalFallback: []db.RefusalFallbackEntry{
			{Model: "fallback-model-1", ReasoningEffort: "low"},
			{Model: "fallback-model-2", ReasoningEffort: "high"},
		},
		fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			triedModels = append(triedModels, entry.Model)
			if entry.Model == "fallback-model-1" {
				return fallbackOne, agent.RetryConfig{}, nil
			}
			if entry.Model == "fallback-model-2" {
				return fallbackTwo, agent.RetryConfig{}, nil
			}
			return nil, agent.RetryConfig{}, errors.New("unknown model")
		},
	}

	exhaustCalled := false
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) { return selection, nil },
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			exhaustCalled = true
			return db.TaskLLMTransition{}, nil
		},
		refusalFallback: func() bool { return true },
	}

	events, err := collectTaskLLMStream(streamTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks))
	if err != nil {
		t.Fatalf("expected stream to succeed via fallback, got %v", err)
	}
	if exhaustCalled {
		t.Fatal("hooks.exhaust must NOT be called when a fallback model on the same profile succeeds")
	}
	if len(triedModels) != 2 || triedModels[0] != "fallback-model-1" || triedModels[1] != "fallback-model-2" {
		t.Fatalf("fallback models not tried in order: got %v", triedModels)
	}
	if primary.calls != 1 || fallbackOne.calls != 1 || fallbackTwo.calls != 1 {
		t.Fatalf("expected each provider called once: primary=%d, fb1=%d, fb2=%d", primary.calls, fallbackOne.calls, fallbackTwo.calls)
	}
	var texts []string
	for _, ev := range events {
		if ev.Type == llm.SETextDelta {
			texts = append(texts, ev.Text)
		}
	}
	if strings.Join(texts, "") != "success-from-fallback-2" {
		t.Fatalf("unexpected stream output: %q", strings.Join(texts, ""))
	}
}

// TestRefusalFallbackCompleteNonStreamingOrder verifies fallback order for completeTaskLLM.
func TestRefusalFallbackCompleteNonStreamingOrder(t *testing.T) {
	defer withZeroRetryBackoff()()

	primary := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	fallback := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "non-streaming-ok"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}

	var tried []string
	selection := taskLLMSelection{
		profileID: 42,
		revision:  1,
		provider:  primary,
		refusalFallback: []db.RefusalFallbackEntry{
			{Model: "fb-model-1"},
		},
		fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			tried = append(tried, entry.Model)
			return fallback, agent.RetryConfig{}, nil
		},
	}

	exhaustCalled := false
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) { return selection, nil },
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			exhaustCalled = true
			return db.TaskLLMTransition{}, nil
		},
		refusalFallback: func() bool { return true },
	}

	msg, sr, _, err := completeTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks)
	if err != nil {
		t.Fatalf("completeTaskLLM failed: %v", err)
	}
	if exhaustCalled {
		t.Fatal("hooks.exhaust must not be called when fallback succeeds")
	}
	if len(tried) != 1 || tried[0] != "fb-model-1" {
		t.Fatalf("fallback model not tried: %v", tried)
	}
	if sr != "end_turn" || msg.Text() != "non-streaming-ok" {
		t.Fatalf("unexpected message: text=%q sr=%q", msg.Text(), sr)
	}
}

// TestRefusalFallbackEffortOverrideApplied verifies that reasoning_effort override
// is passed to fallbackProvider, and empty effort preserves the profile default.
func TestRefusalFallbackEffortOverrideApplied(t *testing.T) {
	defer withZeroRetryBackoff()()

	primary := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	fallbackSuccess := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "done"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}

	var receivedEffort string
	selection := taskLLMSelection{
		profileID: 10,
		revision:  1,
		provider:  primary,
		refusalFallback: []db.RefusalFallbackEntry{
			{Model: "override-model", ReasoningEffort: "medium"},
		},
		fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			receivedEffort = entry.ReasoningEffort
			return fallbackSuccess, agent.RetryConfig{}, nil
		},
	}

	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) { return selection, nil },
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			return db.TaskLLMTransition{}, nil
		},
		refusalFallback: func() bool { return true },
	}

	_, err := collectTaskLLMStream(streamTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks))
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if receivedEffort != "medium" {
		t.Fatalf("expected effort override 'medium', got %q", receivedEffort)
	}
}

// TestRefusalFallbackExhaustedFallsThroughToTaskChain verifies that when all fallback models
// on the profile refuse, the task chain advances via hooks.exhaust.
func TestRefusalFallbackExhaustedFallsThroughToTaskChain(t *testing.T) {
	defer withZeroRetryBackoff()()

	primary := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	fallbackOne := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	secondProfileProvider := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "success-from-profile-2"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}

	selectionOne := taskLLMSelection{
		profileID: 101,
		revision:  1,
		provider:  primary,
		refusalFallback: []db.RefusalFallbackEntry{
			{Model: "fb-1"},
		},
		fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			return fallbackOne, agent.RetryConfig{}, nil
		},
	}

	selectionTwo := taskLLMSelection{
		profileID: 102,
		revision:  2,
		provider:  secondProfileProvider,
	}

	currentSelection := selectionOne
	var exhaustCauses []error
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) { return currentSelection, nil },
		exhaust: func(sel taskLLMSelection, cause error) (db.TaskLLMTransition, error) {
			exhaustCauses = append(exhaustCauses, cause)
			currentSelection = selectionTwo
			next := int64(102)
			return db.TaskLLMTransition{PreviousProfileID: sel.profileID, NextProfileID: &next, Advanced: true}, nil
		},
		refusalFallback: func() bool { return true },
	}

	events, err := collectTaskLLMStream(streamTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks))
	if err != nil {
		t.Fatalf("expected second profile to succeed, got %v", err)
	}
	if len(exhaustCauses) != 1 || !errors.Is(exhaustCauses[0], errProviderRefused) {
		t.Fatalf("expected hooks.exhaust called once with errProviderRefused, got %v", exhaustCauses)
	}
	if primary.calls != 1 || fallbackOne.calls != 1 || secondProfileProvider.calls != 1 {
		t.Fatalf("unexpected call counts: primary=%d, fb1=%d, p2=%d", primary.calls, fallbackOne.calls, secondProfileProvider.calls)
	}
	var texts []string
	for _, ev := range events {
		if ev.Type == llm.SETextDelta {
			texts = append(texts, ev.Text)
		}
	}
	if strings.Join(texts, "") != "success-from-profile-2" {
		t.Fatalf("unexpected text output: %q", strings.Join(texts, ""))
	}
}

// TestRefusalFallbackCommittedOutputNeverReplayed verifies that if text or tool output
// was already delivered, refusal does not trigger fallback and does not replay.
func TestRefusalFallbackCommittedOutputNeverReplayed(t *testing.T) {
	defer withZeroRetryBackoff()()

	primary := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "partial-committed-text"},
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	fallback := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "should-not-reach-here"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}

	selection := taskLLMSelection{
		profileID: 42,
		revision:  1,
		provider:  primary,
		refusalFallback: []db.RefusalFallbackEntry{
			{Model: "fb-model"},
		},
		fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			return fallback, agent.RetryConfig{}, nil
		},
	}

	exhaustCalls := 0
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) { return selection, nil },
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			exhaustCalls++
			return db.TaskLLMTransition{ChainExhausted: true}, nil
		},
		refusalFallback: func() bool { return true },
	}

	events, err := collectTaskLLMStream(streamTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks))
	if err == nil || !errors.Is(err, errProviderRefused) {
		t.Fatalf("committed refusal must terminate with errProviderRefused, got err=%v", err)
	}
	if fallback.calls != 0 {
		t.Fatalf("fallback provider must NEVER be called after committed output, calls=%d", fallback.calls)
	}
	if len(events) == 0 || events[0].Type != llm.SETextDelta || events[0].Text != "partial-committed-text" {
		t.Fatalf("expected committed text before failure: %v", events)
	}
}

// TestRefusalFallbackValidationRejectsInvalidEntries tests validation rules:
// - > 8 entries rejected
// - duplicate models rejected
// - repeating primary model rejected
// - subscription model not in catalog rejected
// - unsupported reasoning effort rejected
// - valid entry accepted
func TestRefusalFallbackValidationRejectsInvalidEntries(t *testing.T) {
	// Fake bridge server that returns catalog models with supported_efforts
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"id": "claude-3-7-sonnet", "name": "Sonnet 3.7", "supported_efforts": []string{"low", "medium", "high"}},
					{"id": "claude-3-5-haiku", "name": "Haiku 3.5", "supported_efforts": []string{}},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	sdk, err := sdkbridge.New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("new sdk bridge: %v", err)
	}

	ctx := context.Background()

	// 1. More than 8 entries
	pMax := &db.LLMProfile{
		Model: "primary-model",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "m1"}, {Model: "m2"}, {Model: "m3"}, {Model: "m4"},
			{Model: "m5"}, {Model: "m6"}, {Model: "m7"}, {Model: "m8"},
			{Model: "m9"},
		},
	}
	if err := validateRefusalFallback(ctx, pMax, sdk); err == nil || !strings.Contains(err.Error(), "cannot exceed 8") {
		t.Fatalf("expected >8 error, got %v", err)
	}

	// 2. Duplicate models in fallback chain
	pDup := &db.LLMProfile{
		Model: "primary-model",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "m1"}, {Model: "m1"},
		},
	}
	if err := validateRefusalFallback(ctx, pDup, sdk); err == nil || !strings.Contains(err.Error(), "duplicate model") {
		t.Fatalf("expected duplicate model error, got %v", err)
	}

	// 3. Repeating primary model
	pRepeat := &db.LLMProfile{
		Model: "primary-model",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "primary-model"},
		},
	}
	if err := validateRefusalFallback(ctx, pRepeat, sdk); err == nil || !strings.Contains(err.Error(), "cannot repeat the primary model") {
		t.Fatalf("expected cannot repeat primary model error, got %v", err)
	}

	// 4. Subscription profile with model not in bridge catalog
	pSubBadModel := &db.LLMProfile{
		AuthMethod: "claude_code",
		Model:      "claude-3-7-sonnet",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "non-existent-model"},
		},
	}
	if err := validateRefusalFallback(ctx, pSubBadModel, sdk); err == nil || !strings.Contains(err.Error(), "not found in catalog") {
		t.Fatalf("expected not found in catalog error, got %v", err)
	}

	// 5. Subscription profile with unsupported reasoning effort
	pSubBadEffort := &db.LLMProfile{
		AuthMethod: "claude_code",
		Model:      "claude-3-7-sonnet",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "claude-3-5-haiku", ReasoningEffort: "high"}, // Haiku has empty supported_efforts
		},
	}
	if err := validateRefusalFallback(ctx, pSubBadEffort, sdk); err == nil || !strings.Contains(err.Error(), "does not support reasoning effort") {
		t.Fatalf("expected unsupported reasoning effort error, got %v", err)
	}

	// 6. Valid subscription fallback entry (effort in supported_efforts)
	pSubValid := &db.LLMProfile{
		AuthMethod: "claude_code",
		Model:      "claude-opus-4",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "claude-3-7-sonnet", ReasoningEffort: "medium"},
			{Model: "claude-3-5-haiku", ReasoningEffort: ""}, // Empty effort = profile default, valid
		},
	}
	if err := validateRefusalFallback(ctx, pSubValid, sdk); err != nil {
		t.Fatalf("expected valid entry to pass validation, got %v", err)
	}
}

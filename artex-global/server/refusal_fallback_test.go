package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/nativeproxy"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
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
// - duplicate effective choices rejected
// - repeated primary choices rejected
// - subscription model not in catalog rejected
// - unsupported reasoning effort rejected
// - valid entry accepted
func TestRefusalFallbackValidationRejectsInvalidEntries(t *testing.T) {
	// Fake native proxy server that returns catalog models with supported_efforts
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

	nativeProxy, err := nativeproxy.New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("new native proxy client: %v", err)
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
	if err := validateRefusalFallback(ctx, pMax, nativeProxy); err == nil {
		t.Fatalf("expected >8 error, got nil")
	}

	// 2. Duplicate choices in fallback chain (same model and same effective effort)
	pDup := &db.LLMProfile{
		Model: "primary-model",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "m1", ReasoningEffort: "low"}, {Model: "m1", ReasoningEffort: "low"},
		},
	}
	if err := validateRefusalFallback(ctx, pDup, nativeProxy); err == nil {
		t.Fatal("expected duplicate choice error, got nil")
	}

	// 3. Repeating primary choice (explicit effort matches primary)
	pRepeat := &db.LLMProfile{
		Model:           "primary-model",
		ReasoningEffort: "high",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "primary-model", ReasoningEffort: "high"},
		},
	}
	if err := validateRefusalFallback(ctx, pRepeat, nativeProxy); err == nil {
		t.Fatal("expected repeating primary choice error, got nil")
	}

	// 4. Repeating primary choice via empty effort inheritance
	pRepeatInherited := &db.LLMProfile{
		Model:           "primary-model",
		ReasoningEffort: "high",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "primary-model", ReasoningEffort: ""},
		},
	}
	if err := validateRefusalFallback(ctx, pRepeatInherited, nativeProxy); err == nil {
		t.Fatal("expected repeating primary choice with inherited effort to fail, got nil")
	}

	// 5. Subscription profile with model not in proxy catalog
	pSubBadModel := &db.LLMProfile{
		AuthMethod: "claude_code",
		Model:      "claude-3-7-sonnet",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "non-existent-model"},
		},
	}
	if err := validateRefusalFallback(ctx, pSubBadModel, nativeProxy); err == nil {
		t.Fatal("expected not found in catalog error, got nil")
	}

	// 6. Subscription profile with unsupported reasoning effort
	pSubBadEffort := &db.LLMProfile{
		AuthMethod: "claude_code",
		Model:      "claude-3-7-sonnet",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "claude-3-5-haiku", ReasoningEffort: "high"}, // Haiku has empty supported_efforts
		},
	}
	if err := validateRefusalFallback(ctx, pSubBadEffort, nativeProxy); err == nil {
		t.Fatal("expected unsupported reasoning effort error, got nil")
	}

	// 7. Valid chain: Primary A/high -> A/low -> B/high -> B/low
	pValidChain := &db.LLMProfile{
		AuthMethod:      "claude_code",
		Model:           "claude-3-7-sonnet",
		ReasoningEffort: "high",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "claude-3-7-sonnet", ReasoningEffort: "low"},
			{Model: "claude-opus-4", ReasoningEffort: "high"},
			{Model: "claude-opus-4", ReasoningEffort: "low"},
		},
	}
	// Ensure claude-opus-4 is in catalog with high and low
	srvOpus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"id": "claude-3-7-sonnet", "name": "Sonnet 3.7", "supported_efforts": []string{"low", "medium", "high"}},
					{"id": "claude-opus-4", "name": "Opus 4", "supported_efforts": []string{"low", "medium", "high"}},
					{"id": "claude-3-5-haiku", "name": "Haiku 3.5", "supported_efforts": []string{}},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srvOpus.Close()
	nativeProxyOpus, err := nativeproxy.New(srvOpus.URL, "test-token")
	if err != nil {
		t.Fatalf("new native proxy client: %v", err)
	}
	if err := validateRefusalFallback(ctx, pValidChain, nativeProxyOpus); err != nil {
		t.Fatalf("expected valid primary A/high -> A/low -> B/high -> B/low to pass validation, got %v", err)
	}

	// 8. Valid subscription fallback entry (effort in supported_efforts)
	pSubValid := &db.LLMProfile{
		AuthMethod: "claude_code",
		Model:      "claude-opus-4",
		RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "claude-3-7-sonnet", ReasoningEffort: "medium"},
			{Model: "claude-3-5-haiku", ReasoningEffort: ""}, // Empty effort = profile default, valid
		},
	}
	if err := validateRefusalFallback(ctx, pSubValid, nativeProxy); err != nil {
		t.Fatalf("expected valid entry to pass validation, got %v", err)
	}
}

func TestRefusalFallbackBranchContinuationAcrossTurns(t *testing.T) {
	defer withZeroRetryBackoff()()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	stamp := time.Now().UnixNano()
	profileID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: fmt.Sprintf("native-fallback-%d", stamp), Format: "anthropic", AuthMethod: "claude_code",
		Model: "model-a", ReasoningEffort: "high", RefusalFallback: []db.RefusalFallbackEntry{
			{Model: "model-a", ReasoningEffort: "low"}, {Model: "model-b", ReasoningEffort: "low"},
			{Model: "model-c", ReasoningEffort: "low"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetLLMRefusalFallbackEnabled(true); err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTaskWithOptions("native fallback dispatch", "test readable-history dispatch", db.TaskCreateOptions{
		LLMProfileIDs: []int64{profileID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
		_ = m.pg.DeleteProfile(profileID)
	})
	var modelCalls []string
	var effortCalls []string
	refuseALow := true
	refuseB := false
	refuseA := true
	infer := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/profiles/"+strconv.FormatInt(profileID, 10)+"/status" {
			_ = json.NewEncoder(w).Encode(map[string]any{"connected": true})
			return
		}
		if r.URL.Path != "/v1/profiles/"+strconv.FormatInt(profileID, 10)+"/infer" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Model string          `json:"model"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var input struct {
			OutputConfig struct {
				Effort string `json:"effort"`
			} `json:"output_config"`
		}
		_ = json.Unmarshal(body.Input, &input)
		effortCalls = append(effortCalls, input.OutputConfig.Effort)
		modelCalls = append(modelCalls, body.Model)
		stop, text := "end", "answer-"+body.Model
		if body.Model == "model-a" && ((input.OutputConfig.Effort == "high" && refuseA) ||
			(input.OutputConfig.Effort == "low" && refuseALow)) ||
			(body.Model == "model-b" && refuseB) {
			stop, text = "refusal", "refused"
		}
		state, _ := json.Marshal(map[string]any{
			"id": body.Model + "-" + strconv.Itoa(len(modelCalls)), "role": "assistant",
			"content": []map[string]string{{"type": "text", "text": text}},
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "done", "response": json.RawMessage(state), "state": json.RawMessage(state),
			"receipt": "receipt-" + body.Model, "stop": stop,
		})
	}
	proxyServer := httptest.NewServer(http.HandlerFunc(infer))
	t.Cleanup(proxyServer.Close)
	nativeProxy, err := nativeproxy.New(proxyServer.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, engine: NewEngine(m), ctx: context.Background(), nativeProxy: nativeProxy, provByProfile: map[int64]*provEntry{}}
	runtime := &taskLLMRuntime{s: s, taskID: task.ID, agentKey: "worker"}
	sessionCtx := func(id string) context.Context {
		return transcript.WithSessionID(context.Background(), id)
	}
	req1 := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("turn 1")}}
	msg1, _, _, err := runtime.Complete(sessionCtx("session-1"), req1)
	if err != nil || msg1.Text() != "answer-model-b" || len(modelCalls) != 3 ||
		modelCalls[0] != "model-a" || modelCalls[1] != "model-a" || modelCalls[2] != "model-b" {
		t.Fatalf("A/high->A/low->B native fallback: message=%q calls=%v err=%v", msg1.Text(), modelCalls, err)
	}
	msg1WithNativeState := msg1
	req2 := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("turn 1"), msg1WithNativeState, llm.UserText("turn 2")}}
	modelCalls = nil
	msg2, _, _, err := runtime.Complete(sessionCtx("session-1"), req2)
	if err != nil || msg2.Text() != "answer-model-b" || len(modelCalls) != 1 || modelCalls[0] != "model-b" {
		t.Fatalf("B continuation: message=%q calls=%v err=%v", msg2.Text(), modelCalls, err)
	}
	msg2WithNativeState := msg2
	req3 := llm.CompletionRequest{Messages: []llm.Message{
		llm.UserText("turn 1"), msg1WithNativeState, llm.UserText("turn 2"),
		msg2WithNativeState, llm.UserText("turn 3"),
	}}
	modelCalls = nil
	refuseB = true
	msg3, _, _, err := runtime.Complete(sessionCtx("session-1"), req3)
	if err != nil || msg3.Text() != "answer-model-c" || len(modelCalls) != 2 || modelCalls[0] != "model-b" || modelCalls[1] != "model-c" {
		t.Fatalf("B->C continuation: message=%q calls=%v err=%v", msg3.Text(), modelCalls, err)
	}
	refuseB = false
	modelCalls, effortCalls = nil, nil
	msgOther, _, _, err := runtime.Complete(sessionCtx("session-2"), req1)
	if err != nil || msgOther.Text() != "answer-model-b" || len(modelCalls) != 3 ||
		modelCalls[0] != "model-a" || modelCalls[1] != "model-a" || modelCalls[2] != "model-b" {
		t.Fatalf("independent session: message=%q calls=%v err=%v", msgOther.Text(), modelCalls, err)
	}
	refuseALow = false
	modelCalls, effortCalls = nil, nil
	low, _, _, err := runtime.Complete(sessionCtx("session-low"), req1)
	if err != nil || low.Text() != "answer-model-a" || len(modelCalls) != 2 ||
		effortCalls[0] != "high" || effortCalls[1] != "low" {
		t.Fatalf("A/high refusal->A/low success: message=%q models=%v efforts=%v err=%v", low.Text(), modelCalls, effortCalls, err)
	}
	modelCalls, effortCalls = nil, nil
	lowNext, _, _, err := runtime.Complete(sessionCtx("session-low"), llm.CompletionRequest{Messages: []llm.Message{
		llm.UserText("turn 1"), low, llm.UserText("turn 2"),
	}})
	if err != nil || lowNext.Text() != "answer-model-a" || len(modelCalls) != 1 || effortCalls[0] != "low" {
		t.Fatalf("A/low continuation: message=%q models=%v efforts=%v err=%v", lowNext.Text(), modelCalls, effortCalls, err)
	}
	refuseA = false
	modelCalls, effortCalls = nil, nil
	high, _, _, err := runtime.Complete(sessionCtx("session-high"), req1)
	if err != nil || high.Text() != "answer-model-a" || len(modelCalls) != 1 || effortCalls[0] != "high" {
		t.Fatalf("A/high success: message=%q models=%v efforts=%v err=%v", high.Text(), modelCalls, effortCalls, err)
	}
	modelCalls, effortCalls = nil, nil
	highNext, _, _, err := runtime.Complete(sessionCtx("session-high"), llm.CompletionRequest{Messages: []llm.Message{
		llm.UserText("turn 1"), high, llm.UserText("turn 2"),
	}})
	if err != nil || highNext.Text() != "answer-model-a" || len(modelCalls) != 1 || effortCalls[0] != "high" {
		t.Fatalf("A/high continuation: message=%q models=%v efforts=%v err=%v", highNext.Text(), modelCalls, effortCalls, err)
	}
}
func TestRefusalFallbackDispatchFallbackProviderError(t *testing.T) {
	wanted := errors.New("fallback unavailable")
	provider := &scriptedLLMProvider{events: []llm.StreamEvent{{Type: llm.SEMessageDelta, StopReason: "refusal"}}}
	selection := taskLLMSelection{
		profileID: 1, provider: provider, refusalFallback: []db.RefusalFallbackEntry{{Model: "fallback"}},
		fallbackProvider: func(db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			return nil, agent.RetryConfig{}, wanted
		},
	}
	hooks := taskLLMStreamHooks{
		current:         func() (taskLLMSelection, error) { return selection, nil },
		refusalFallback: func() bool { return true },
	}
	_, _, _, err := completeTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks)
	if !errors.Is(err, wanted) {
		t.Fatalf("Complete error = %v, want %v", err, wanted)
	}
	events := streamTaskLLM(context.Background(), "1", llm.CompletionRequest{}, hooks)
	for _, err := range events {
		if !errors.Is(err, wanted) {
			t.Fatalf("Stream error = %v, want %v", err, wanted)
		}
		return
	}
	t.Fatal("Stream returned without fallback provider error")
}

func TestRefusalFallbackStreamingBranchContinuationAcrossTurns(t *testing.T) {
	defer withZeroRetryBackoff()()

	var modelCalls []string
	modelA := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	modelB := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "stream-answer-b"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}
	modelBRefuses := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SEMessageDelta, StopReason: "refusal"},
	}}
	modelC := &scriptedLLMProvider{events: []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: "stream-answer-c"},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
	}}

	allowedFallbackModels := []string{"model-b", "model-c"}

	makeHooks := func(sel taskLLMSelection) taskLLMStreamHooks {
		return taskLLMStreamHooks{
			current: func() (taskLLMSelection, error) { return sel, nil },
			currentFor: func(ctx context.Context) (taskLLMSelection, error) {
				currentSel := sel
				msgs := llmRequestMessagesFrom(ctx)
				if branch, effort, ok := agent.DeriveSessionChainModel(ctx, msgs, "42", "claude", allowedFallbackModels); ok {
					currentSel.currentModel = branch
					currentSel.currentEffort = effort
					for idx, entry := range currentSel.refusalFallback {
						if entry.Model == branch {
							currentSel.initialFallbackIndex = idx
							if prov, retry, err := currentSel.fallbackProvider(entry); err == nil {
								currentSel.provider = prov
								currentSel.retry = retry
							}
							break
						}
					}
				}
				return currentSel, nil
			},
			exhaust:         func(taskLLMSelection, error) (db.TaskLLMTransition, error) { return db.TaskLLMTransition{}, nil },
			refusalFallback: func() bool { return true },
		}
	}

	selection := taskLLMSelection{
		profileID: 42,
		revision:  1,
		provider:  modelA,
		refusalFallback: []db.RefusalFallbackEntry{
			{Model: "model-b"},
			{Model: "model-c"},
		},
		fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
			modelCalls = append(modelCalls, entry.Model)
			if entry.Model == "model-b" {
				return modelB, agent.RetryConfig{}, nil
			}
			return modelC, agent.RetryConfig{}, nil
		},
	}

	hooks := makeHooks(selection)

	// 1. Initial turn Stream in Session 1: Model A refuses -> hops directly to Model B
	session1Ctx := transcript.WithSessionID(context.Background(), "session-stream-1")
	req1 := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("q1")}}
	events1, err1 := collectTaskLLMStream(streamTaskLLM(session1Ctx, "task-1", req1, hooks))
	if err1 != nil || len(events1) == 0 || events1[0].Text != "stream-answer-b" {
		t.Fatalf("stream turn 1 failed: err=%v events=%+v", err1, events1)
	}
	if len(modelCalls) != 1 || modelCalls[0] != "model-b" {
		t.Fatalf("stream turn 1 expected call to model-b, got %v", modelCalls)
	}

	// Turn 1 result gets native envelope for Model B
	envB := `{"version":2,"provider":"claude","model":"model-b","profile_id":"42","session_id":"session-stream-1","response_id":"resp-b1","state":{"role":"assistant"},"receipt":"receipt-b1"}`
	msg1WithNativeState := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{
			llm.TextBlock("stream-answer-b"),
			{Type: "provider_state", Input: json.RawMessage(envB)},
		},
	}

	// 2. Next turn Stream in Session 1: starts and stays on Model B
	modelCalls = nil
	req2 := llm.CompletionRequest{
		Messages: []llm.Message{
			llm.UserText("q1"),
			msg1WithNativeState,
			llm.UserText("q2"),
		},
	}
	events2, err2 := collectTaskLLMStream(streamTaskLLM(session1Ctx, "task-1", req2, hooks))
	if err2 != nil || len(events2) == 0 || events2[0].Text != "stream-answer-b" {
		t.Fatalf("stream turn 2 failed to stay on model-b: err=%v events=%+v", err2, events2)
	}
	if modelB.calls != 2 {
		t.Fatalf("stream turn 2 should call the already-selected model-b once more, calls=%d", modelB.calls)
	}

	// 3. Turn 3 Stream in Session 1: Model B refuses -> advances directly to Model C without retrying Model B
	selectionWithBRefusing := selection
	selectionWithBRefusing.fallbackProvider = func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
		modelCalls = append(modelCalls, entry.Model)
		if entry.Model == "model-b" {
			return modelBRefuses, agent.RetryConfig{}, nil
		}
		return modelC, agent.RetryConfig{}, nil
	}
	hooksTurn3 := makeHooks(selectionWithBRefusing)
	modelCalls = nil
	req3 := llm.CompletionRequest{
		Messages: []llm.Message{
			llm.UserText("q1"),
			msg1WithNativeState,
			llm.UserText("q2"),
			msg1WithNativeState,
			llm.UserText("q3"),
		},
	}
	events3, err3 := collectTaskLLMStream(streamTaskLLM(session1Ctx, "task-1", req3, hooksTurn3))
	if err3 != nil || len(events3) == 0 || events3[0].Text != "stream-answer-c" {
		t.Fatalf("stream turn 3 failed to advance directly to model-c: err=%v events=%+v", err3, events3)
	}
	if len(modelCalls) != 2 || modelCalls[0] != "model-b" || modelCalls[1] != "model-c" {
		t.Fatalf("stream turn 3 should select model-b from history then advance to model-c, got %v", modelCalls)
	}

	// 4. Simultaneous independent Session 2 Stream starts on Model A
	session2Ctx := transcript.WithSessionID(context.Background(), "session-stream-2")
	modelCalls = nil
	reqSession2 := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("s2")}}
	eventsS2, errS2 := collectTaskLLMStream(streamTaskLLM(session2Ctx, "task-1", reqSession2, hooks))
	if errS2 != nil || len(eventsS2) == 0 || eventsS2[0].Text != "stream-answer-b" {
		t.Fatalf("stream session 2 failed: err=%v events=%+v", errS2, eventsS2)
	}
	if len(modelCalls) != 1 || modelCalls[0] != "model-b" {
		t.Fatalf("stream session 2 expected hop from model A to model-b, got calls: %v", modelCalls)
	}
}

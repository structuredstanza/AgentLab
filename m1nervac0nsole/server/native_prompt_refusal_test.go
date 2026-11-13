package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/nativeproxy"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

func TestNativePromptRefusalUsesConfiguredFallbackWithoutTransportRetry(t *testing.T) {
	defer withZeroRetryBackoff()()
	for _, enabled := range []bool{true, false} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var calls []string
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/profiles/7/infer" || r.Header.Get("Authorization") != "Bearer fixture-token" {
					http.Error(w, "unexpected fixture request", http.StatusBadRequest)
					return
				}
				var request struct {
					Model string `json:"model"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					http.Error(w, "invalid fixture request", http.StatusBadRequest)
					return
				}
				mu.Lock()
				calls = append(calls, request.Model)
				mu.Unlock()
				state := json.RawMessage(`{"candidates":[],"promptFeedback":{"blockReason":"SAFETY"}}`)
				stop := "refusal"
				if request.Model == "fallback" {
					state = json.RawMessage(`{"candidates":[{"content":{"role":"model","parts":[{"text":"resolved by fallback"}]}}]}`)
					stop = "end"
				}
				w.Header().Set("Content-Type", "application/x-ndjson")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type": "done", "response": state, "state": state, "receipt": "fixture-receipt",
					"usage": map[string]int{"input_tokens": 12}, "stop": stop,
				})
			}))
			t.Cleanup(host.Close)
			proxy, err := nativeproxy.New(host.URL, "fixture-token")
			if err != nil {
				t.Fatal(err)
			}
			cfg := agent.Config{AuthMethod: "antigravity", Format: agent.FormatAntigravity, Model: "primary"}
			primary, err := cfg.NewProviderForProfile("7", proxy)
			if err != nil {
				t.Fatal(err)
			}
			selection := taskLLMSelection{
				profileID: 7, revision: 1, provider: primary, isNative: true, primaryModel: "primary",
				refusalFallback: []db.RefusalFallbackEntry{{Model: "fallback"}},
				fallbackProvider: func(entry db.RefusalFallbackEntry) (llm.Provider, agent.RetryConfig, error) {
					cfg.Model = entry.Model
					provider, err := cfg.NewProviderForProfile("7", proxy)
					return provider, agent.RetryConfig{}, err
				},
			}
			hooks := taskLLMStreamHooks{
				current:         func() (taskLLMSelection, error) { return selection, nil },
				refusalFallback: func() bool { return enabled },
				exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
					t.Fatal("a usable same-profile fallback must not exhaust the task chain")
					return db.TaskLLMTransition{}, nil
				},
			}
			ctx := transcript.WithSessionID(context.Background(), "fixture-session")
			msg, stop, usage, err := completeTaskLLM(ctx, "prompt-refusal-"+name, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("fixture prompt")}}, hooks)
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if enabled {
				if !reflect.DeepEqual(calls, []string{"primary", "fallback"}) || stop != "end_turn" || msg.Text() != "resolved by fallback" {
					t.Fatalf("fallback calls=%v stop=%q text=%q", calls, stop, msg.Text())
				}
			} else if !reflect.DeepEqual(calls, []string{"primary"}) || stop != "refusal" || msg.Text() != "" || usage.InputTokens != 12 {
				t.Fatalf("disabled fallback changed refusal semantics: calls=%v stop=%q message=%+v usage=%+v", calls, stop, msg, usage)
			}
		})
	}
}

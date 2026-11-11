package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/llmpool"
	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
	"github.com/structuredstanza/AgentLab/artex-global/sidequestion"
	"github.com/structuredstanza/norma/agentcore"
	"github.com/structuredstanza/norma/harness"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/permission"
	"github.com/structuredstanza/norma/tool"
	"github.com/structuredstanza/norma/transcript"
)

type modeBindingKey struct{}

type changingModeProvider struct {
	native                        *nativeProvider
	prepared, streamed, completed int
	nativeSelected                bool
}

func (p *changingModeProvider) PrepareModelCall(ctx context.Context, _ llm.CompletionRequest, _ bool) (context.Context, bool, error) {
	mode := p.nativeSelected
	p.prepared++
	// Simulate an edit after selection: this call must retain its captured API route.
	p.nativeSelected = true
	return context.WithValue(ctx, modeBindingKey{}, mode), mode, nil
}

func (p *changingModeProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		mode, bound := ctx.Value(modeBindingKey{}).(bool)
		if !bound {
			mode = p.nativeSelected
		}
		p.streamed++
		if mode {
			yield(llm.StreamEvent{}, errNativeStreamUnsupported)
			return
		}
		for _, event := range []llm.StreamEvent{
			{Type: llm.SEToolUseStart, ToolID: "api-call", ToolName: "probe"},
			{Type: llm.SEToolInputJSON, Text: `{"mode":"api"}`},
			{Type: llm.SEMessageDelta, StopReason: "tool_use"},
			{Type: llm.SEMessageStop},
		} {
			if !yield(event, nil) {
				return
			}
		}
	}
}

func (p *changingModeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	mode, bound := ctx.Value(modeBindingKey{}).(bool)
	if !bound || !mode {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("completion lost its prepared native route")
	}
	p.completed++
	return p.native.Complete(ctx, req)
}

func TestAgentRenegotiatesModeWithoutRepeatingToolsOrLosingNativeReplay(t *testing.T) {
	const state = `{"id":"native-tool","role":"assistant","content":[{"type":"thinking","thinking":"inspect the result","signature":"private-signature"},{"type":"redacted_thinking","data":"private-opaque-state"},{"type":"tool_use","id":"native-call","name":"probe","input":{"mode":"native"}}]}`
	const final = `{"id":"native-final","role":"assistant","content":[{"type":"text","text":"done"}]}`
	var requestsMu sync.Mutex
	var requests []nativeInferBody
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profiles/7/infer" || r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var body nativeInferBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		requestsMu.Lock()
		requests = append(requests, body)
		turn := len(requests)
		requestsMu.Unlock()
		response, stop := state, "tool"
		if turn > 1 {
			response, stop = final, "end"
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = fmt.Fprintf(w, `{"type":"done","response":%s,"state":%s,"receipt":"native-receipt-%d","usage":{"input_tokens":11,"output_tokens":7},"stop":%q}`+"\n", response, response, turn, stop)
	}))
	defer host.Close()
	client, err := nativeproxy.New(host.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	provider := &changingModeProvider{native: &nativeProvider{proxy: client, profileID: "7", provider: "claude", model: "fixed-model"}}
	var toolsMu sync.Mutex
	toolRuns := map[string]int{}
	probe := tool.Build(tool.Spec{Name: "probe", Schema: map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string"}}, "required": []string{"mode"}},
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			if ctx.Value(modeBindingKey{}) != nil {
				t.Error("model selection leaked into the tool context")
			}
			var value struct {
				Mode string `json:"mode"`
			}
			if err := json.Unmarshal(input, &value); err != nil {
				return tool.Result{}, err
			}
			toolsMu.Lock()
			toolRuns[value.Mode]++
			toolsMu.Unlock()
			if value.Mode == "api" {
				provider.nativeSelected = true
			}
			return tool.Result{Content: []llm.ContentBlock{llm.TextBlock(value.Mode + " executed")}}, nil
		},
	})
	ctx := transcript.WithSessionID(t.Context(), "mode-session")
	text, reason, err := captureRun(ctx, agentcore.Options{Provider: provider, Tools: []tool.CoreTool{probe}, PermissionMode: permission.ModeBypass, MaxTurns: 6, SessionID: "mode-session", WorkingDir: t.TempDir()}, "inspect, then continue on the selected model", nil)
	if err != nil || text != "done" || reason != harness.ReasonCompleted {
		t.Fatalf("live mode continuation: text=%q reason=%s err=%v", text, reason, err)
	}
	if provider.prepared != 3 || provider.streamed != 1 || provider.completed != 2 {
		t.Fatalf("mode boundaries: prepare=%d stream=%d complete=%d", provider.prepared, provider.streamed, provider.completed)
	}
	toolsMu.Lock()
	defer toolsMu.Unlock()
	if toolRuns["api"] != 1 || toolRuns["native"] != 1 {
		t.Fatalf("completed tool work repeated or lost: %v", toolRuns)
	}
	requestsMu.Lock()
	defer requestsMu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("native requests: %d", len(requests))
	}
	if len(requests[0].Replay) != 0 || len(requests[1].Replay) != 1 || requests[1].Replay[0].Receipt != "native-receipt-1" || !bytes.Equal(requests[1].Replay[0].State, []byte(state)) {
		t.Fatalf("whole native message/replay was lost: %+v", requests)
	}
	if !bytes.Contains(requests[1].Input, []byte("native executed")) {
		t.Error("native tool result was not sent on the next model call")
	}
}

type exhaustedModeAPI struct{}

func (exhaustedModeAPI) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, fmt.Errorf("mixed pool incorrectly selected Stream"))
	}
}

func (exhaustedModeAPI) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, fmt.Errorf("HTTP status 402: insufficient_quota")
}

func TestAgentMixedPoolPreservesWholeNativeMessage(t *testing.T) {
	const state = `{"id":"pool-native","role":"assistant","content":[{"type":"thinking","thinking":"inspect evidence","signature":"pool-signature"},{"type":"redacted_thinking","data":"pool-opaque"},{"type":"text","text":"native answer"}]}`
	p, _ := nativeTestProvider(t, "claude", `{"type":"done","response":`+state+`,"state":`+state+`,"receipt":"pool-receipt","stop":"end"}`+"\n")
	native := sidequestion.Bind(llm.RateLimited(p, llm.RateLimit{PerMinute: 60}), sidequestion.Model{ProfileID: 7, Model: "fixed-model"})
	pool := llmpool.New([]*llmpool.Member{
		{ID: 1, Rank: llmpool.RankActive, Prov: exhaustedModeAPI{}},
		{ID: 7, Prov: native},
	}, nil)
	ctx := transcript.WithSessionID(t.Context(), "pool-mode-session")
	ctx, session := newSession(ctx, agentcore.Options{Provider: pool, Tools: []tool.CoreTool{}, SessionID: "pool-mode-session", WorkingDir: t.TempDir()})
	defer session.Close()
	text, reason, err := captureRunSession(ctx, session, "inspect the evidence", nil)
	if err != nil || text != "native answer" || reason != harness.ReasonCompleted {
		t.Fatalf("mixed pool fallback: %q %s %v", text, reason, err)
	}
	history := append(session.Messages(), llm.UserText("continue"))
	_, replay, err := p.requestBody(ctx, llm.CompletionRequest{Messages: history})
	if err != nil || len(replay) != 1 || replay[0].Receipt != "pool-receipt" || !bytes.Equal(replay[0].State, []byte(state)) {
		t.Fatalf("pool discarded opaque native reasoning or replay state: %+v %v", replay, err)
	}
}

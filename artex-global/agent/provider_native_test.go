package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/llmrec"
	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

func TestNativeReasoningEncodersRequestVisibleSummariesAndThoughts(t *testing.T) {
	for _, provider := range []string{"codex", "antigravity"} {
		t.Run(provider, func(t *testing.T) {
			for _, effort := range []string{"", "high"} {
				p := &nativeProvider{provider: provider, thinking: "enabled", effort: effort}
				raw, err := p.encodeInput(llm.CompletionRequest{})
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatal(err)
				}
				if provider == "codex" {
					reasoning, ok := body["reasoning"].(map[string]any)
					if !ok || reasoning["summary"] != "auto" || effort != "" && reasoning["effort"] != effort {
						t.Fatalf("Codex reasoning config = %#v, effort %q", reasoning, effort)
					}
				} else {
					generation, _ := body["generationConfig"].(map[string]any)
					thinking, _ := generation["thinkingConfig"].(map[string]any)
					if thinking["includeThoughts"] != true || effort != "" && thinking["thinkingLevel"] != effort {
						t.Fatalf("Gemini thinking config = %#v, effort %q", thinking, effort)
					}
				}
			}

			p := &nativeProvider{provider: provider, thinking: "enabled", effort: "high"}
			raw, err := p.encodeInput(llm.CompletionRequest{Thinking: "disabled"})
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			if provider == "codex" && body["reasoning"] != nil {
				t.Fatalf("disabled Codex thinking emitted reasoning config: %#v", body["reasoning"])
			}
			generation, _ := body["generationConfig"].(map[string]any)
			if provider == "antigravity" && generation["thinkingConfig"] != nil {
				t.Fatalf("disabled Gemini thinking emitted config: %#v", generation["thinkingConfig"])
			}
		})
	}
}

func TestNativeReplayReceiptRoundTripAndProjectionGate(t *testing.T) {
	cases := []struct{ provider, state string }{
		{"claude", `{"id":"m1","role":"assistant","content":[{"type":"thinking","thinking":"plan","signature":"sig"},{"type":"redacted_thinking","data":"opaque"},{"type":"text","text":"ok"}]}`},
		{"codex", `{"id":"r1","output":[{"type":"reasoning","encrypted_content":"opaque","summary":[{"type":"summary_text","text":"plan"}]},{"type":"message","content":[{"type":"output_text","text":"ok"}]}]}`},
		{"antigravity", `{"responseId":"g1","candidates":[{"content":{"role":"model","parts":[{"text":"plan","thought":true,"thoughtSignature":"sig"},{"text":"ok"}]}}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			p := &nativeProvider{provider: tc.provider, model: "chosen-model", profileID: "7"}
			blocks, id, err := projectNative(tc.provider, json.RawMessage(tc.state))
			if err != nil {
				t.Fatal(err)
			}
			env, err := json.Marshal(nativeStateEnvelope{Version: 2, Provider: tc.provider, Model: p.model, ProfileID: p.profileID, SessionID: "session-a", ResponseID: id, State: json.RawMessage(tc.state), Receipt: "host-authenticated"})
			if err != nil {
				t.Fatal(err)
			}
			msg := llm.Message{Role: llm.RoleAssistant, Content: append(blocks, llm.ContentBlock{Type: nativeStateBlock, Input: env})}
			ctx := transcript.WithSessionID(context.Background(), "session-a")
			body, replay, err := p.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{msg}})
			if err != nil {
				t.Fatal(err)
			}
			if len(replay) != 1 || replay[0].Receipt != "host-authenticated" || string(replay[0].State) != tc.state {
				t.Fatalf("replay=%+v", replay)
			}
			var sent nativeInferBody
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Fatal(err)
			}
			if sent.Model != "chosen-model" || sent.Provider != tc.provider || sent.SessionID != "session-a" {
				t.Fatalf("identity fields changed: %+v", sent)
			}
			if tc.provider == "claude" && !strings.Contains(string(sent.Input), `"signature":"sig"`) {
				t.Errorf("Claude signed reasoning missing from native replay input: %s", sent.Input)
			}
			edited := llm.Message{Role: msg.Role, Content: append([]llm.ContentBlock(nil), msg.Content...)}
			for i := range edited.Content {
				if edited.Content[i].Type == llm.BlockText {
					edited.Content[i].Text = "altered"
					break
				}
			}
			if _, _, err := p.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{edited}}); err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("projection mismatch error=%v", err)
			}
		})
	}
}

func TestNativeReplayRejectsForeignLegacyAndCrossSessionState(t *testing.T) {
	state := json.RawMessage(`{"id":"m1","role":"assistant","content":[{"type":"text","text":"ok"}]}`)
	blocks, _, err := projectNative("claude", state)
	if err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]nativeStateEnvelope{
		"foreign provider": {Version: 2, Provider: "codex", Model: "m", ProfileID: "7", SessionID: "s", ResponseID: "r", State: state, Receipt: "signed"},
		"foreign profile":  {Version: 2, Provider: "claude", Model: "m", ProfileID: "8", SessionID: "s", ResponseID: "r", State: state, Receipt: "signed"},
		"foreign model":    {Version: 2, Provider: "claude", Model: "other", ProfileID: "7", SessionID: "s", ResponseID: "r", State: state, Receipt: "signed"},
		"foreign session":  {Version: 2, Provider: "claude", Model: "m", ProfileID: "7", SessionID: "other", ResponseID: "r", State: state, Receipt: "signed"},
		"legacy":           {Provider: "claude", Model: "m", ProfileID: "7", SessionID: "s", ResponseID: "r", State: state, Receipt: "signed"},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(env)
			msg := llm.Message{Role: llm.RoleAssistant, Content: append(blocks, llm.ContentBlock{Type: nativeStateBlock, Input: raw})}
			p := &nativeProvider{provider: "claude", model: "m", profileID: "7"}
			_, _, gotErr := p.requestBody(transcript.WithSessionID(context.Background(), "s"), llm.CompletionRequest{Messages: []llm.Message{msg}})
			if gotErr == nil {
				t.Fatalf("expected foreign or unverifiable state rejection, got %v", gotErr)
			}
		})
	}
}

func TestNativeCompletionRefusalErrorAndTruncation(t *testing.T) {
	state := `{"id":"m1","role":"assistant","content":[{"type":"text","text":"no"}]}`
	ctx := llmrec.WithRefusalSink(transcript.WithSessionID(context.Background(), "s"))
	p, _ := nativeTestProvider(t, "claude", `{"type":"done","response":`+state+`,"state":`+state+`,"receipt":"r","usage":{"input_tokens":4},"stop":"refusal"}`+"\n")
	_, stop, usage, err := p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil || stop != "refusal" || usage.InputTokens != 4 || !llmrec.RefusalObserved(ctx) {
		t.Fatalf("stop=%q usage=%+v refused=%v err=%v", stop, usage, llmrec.RefusalObserved(ctx), err)
	}
	p, _ = nativeTestProvider(t, "claude", `{"type":"error","code":"rate_limited","message":"provider details must not leak"}`+"\n")
	ctx2 := llmrec.WithRefusalSink(context.Background())
	_, _, _, err = p.Complete(transcript.WithSessionID(ctx2, "s"), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}})
	if err == nil || !strings.Contains(err.Error(), "rate_limited") || strings.Contains(err.Error(), "provider details") || llmrec.RefusalObserved(ctx2) {
		t.Fatalf("error=%v refusal=%v", err, llmrec.RefusalObserved(ctx2))
	}
	if _, err := readNativeTerminal(strings.NewReader(`{"type":"wire_sse","data":"event"}` + "\n")); err == nil {
		t.Fatal("stream without terminal accepted")
	}
	if _, err := readNativeTerminal(strings.NewReader("not json\n")); err == nil {
		t.Fatal("malformed event accepted")
	}
}

func TestNativeProviderProfileBindingRejectsCredentialAndEndpointOverrides(t *testing.T) {
	client, err := nativeproxy.New("http://127.0.0.1:1", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	base := Config{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "locked-model"}
	if _, err := base.NewProviderForProfile("7", client); err != nil {
		t.Fatalf("valid native profile rejected: %v", err)
	}
	cases := []Config{
		{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "m", BaseURL: "https://override.invalid"},
		{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "m", APIKey: "must-not-be-used"},
		{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "m", Proxy: "http://override.invalid"},
		{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "m", SessionHeaderKey: "x-session"},
	}
	for i, cfg := range cases {
		if _, err := cfg.NewProviderForProfile("7", client); err == nil {
			t.Errorf("override case %d accepted", i)
		}
	}
}

func nativeTestProvider(t *testing.T, provider, terminal string) (*nativeProvider, *string) {
	t.Helper()
	posted := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profiles/7/infer" || r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		posted = string(b)
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, terminal)
	}))
	t.Cleanup(srv.Close)
	client, err := nativeproxy.New(srv.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	return &nativeProvider{proxy: client, profileID: "7", provider: provider, model: "fixed-model"}, &posted
}

func TestNativeResponseIDFallbackIsDeterministicAndContentBound(t *testing.T) {
	response := json.RawMessage(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`)
	state := json.RawMessage(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]}}]}`)
	first := deriveNativeResponseID(response, state)
	if first == "" || first != deriveNativeResponseID(response, state) {
		t.Fatal("response ID is not deterministic")
	}
	changed := json.RawMessage(`{"candidates":[{"content":{"parts":[{"text":"changed"}]}}]}`)
	if first == deriveNativeResponseID(changed, state) {
		t.Fatal("response ID is not bound to exact response bytes")
	}
	changedState := json.RawMessage(`{"candidates":[{"content":{"role":"model","parts":[{"text":"changed"}]}}]}`)
	if first == deriveNativeResponseID(response, changedState) {
		t.Fatal("response ID is not bound to exact state bytes")
	}
}

func TestNativeCompleteStoresDerivedGeminiResponseID(t *testing.T) {
	response := `{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]}}]}`
	terminal := `{"type":"done","response":` + response + `,"state":` + response + `,"receipt":"r","stop":"end"}` + "\n"
	p, _ := nativeTestProvider(t, "antigravity", terminal)
	msg, _, _, err := p.Complete(transcript.WithSessionID(context.Background(), "s"), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range msg.Content {
		if block.Type != nativeStateBlock {
			continue
		}
		var env nativeStateEnvelope
		if err := json.Unmarshal(block.Input, &env); err != nil {
			t.Fatal(err)
		}
		if want := deriveNativeResponseID(json.RawMessage(response), json.RawMessage(response)); env.ResponseID != want {
			t.Fatalf("response_id=%q want %q", env.ResponseID, want)
		}
		return
	}
	t.Fatal("provider_state envelope missing")
}

func TestNativeStreamIsUnsupported(t *testing.T) {
	p := &nativeProvider{}
	var got error
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		got = err
	}
	if !errors.Is(got, errNativeStreamUnsupported) {
		t.Fatalf("Stream error=%v", got)
	}
}

func TestNativeFallbackReadableHistoryPrefixConversion(t *testing.T) {
	ctx := transcript.WithSessionID(context.Background(), "session-fallback")
	ctx = WithAllowedFallbackChoices(ctx, []NativeModelChoice{
		{Model: "primary-model-a", ReasoningEffort: "high"},
		{Model: "primary-model-a", ReasoningEffort: "low"},
		{Model: "fallback-model-b", ReasoningEffort: "low"},
		{Model: "fallback-model-c"},
	})

	// Prior model A state
	stateA := `{"id":"m1","role":"assistant","content":[{"type":"thinking","thinking":"opaque thought","signature":"sigA"},{"type":"tool_use","id":"call-1","name":"Bash","input":{"command":"ls"}},{"type":"text","text":"investigating"}]}`
	envA := nativeStateEnvelope{
		Version:         2,
		Provider:        "claude",
		Model:           "primary-model-a",
		ReasoningEffort: "high",
		ProfileID:       "7",
		SessionID:       "session-fallback",
		ResponseID:      "m1",
		State:           json.RawMessage(stateA),
		Receipt:         "receiptA",
	}
	rawEnvA, _ := json.Marshal(envA)
	blocksA, _, err := projectNative("claude", json.RawMessage(stateA))
	if err != nil {
		t.Fatal(err)
	}
	assistantTurnA := llm.Message{
		Role:    llm.RoleAssistant,
		Content: append(blocksA, llm.ContentBlock{Type: nativeStateBlock, Input: rawEnvA}),
	}
	toolResultTurn := llm.Message{
		Role: llm.RoleUser,
		Content: []llm.ContentBlock{
			llm.ToolResultText("call-1", "file1.txt\nfile2.txt", false),
		},
	}

	pFallbackB := &nativeProvider{profileID: "7", provider: "claude", model: "fallback-model-b", effort: "low"}

	// 1. Initial hop to fallback model B: prior model A history becomes readable prefix without native replay or signatures
	reqHop := llm.CompletionRequest{
		Messages: []llm.Message{
			llm.UserText("start"),
			assistantTurnA,
			toolResultTurn,
			llm.UserText("next step"),
		},
	}
	originalHistory, err := json.Marshal(reqHop.Messages)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, replays, err := pFallbackB.requestBody(ctx, reqHop)
	if err != nil {
		t.Fatalf("requestBody on fallback B failed: %v", err)
	}
	if len(replays) != 0 {
		t.Fatalf("replays on fallback B hop should be empty, got %d", len(replays))
	}
	bodyStr := string(bodyBytes)
	if strings.Contains(bodyStr, "sigA") || strings.Contains(bodyStr, "receiptA") || strings.Contains(bodyStr, "opaque thought") {
		t.Fatalf("outbound payload leaked opaque state from prior model A: %s", bodyStr)
	}
	var outbound struct {
		Input struct {
			Messages []struct {
				Content []struct{ Type, Text string }
			}
		}
	}
	if err := json.Unmarshal(bodyBytes, &outbound); err != nil {
		t.Fatal(err)
	}
	var history strings.Builder
	for _, message := range outbound.Input.Messages {
		for _, block := range message.Content {
			if block.Type != "text" {
				t.Fatalf("prior-choice history retained typed content: %s", block.Type)
			}
			history.WriteString(block.Text)
		}
	}
	for _, value := range []string{"Bash", "command", "ls", "file1.txt\nfile2.txt", "investigating"} {
		if !strings.Contains(history.String(), value) {
			t.Fatalf("readable history lost original task data %q", value)
		}
	}
	afterHistory, err := json.Marshal(reqHop.Messages)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalHistory, afterHistory) {
		t.Fatal("original history was mutated")
	}

	// 2. Next turn on Model B: Model B produces assistant turn B, which retains its native state and replay
	stateB := `{"id":"m2","role":"assistant","content":[{"type":"text","text":"found files"}]}`
	envB := nativeStateEnvelope{
		Version:         2,
		Provider:        "claude",
		Model:           "fallback-model-b",
		ReasoningEffort: "low",
		ProfileID:       "7",
		SessionID:       "session-fallback",
		ResponseID:      "m2",
		State:           json.RawMessage(stateB),
		Receipt:         "receiptB",
	}
	rawEnvB, _ := json.Marshal(envB)
	assistantTurnB := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{
			llm.TextBlock("found files"),
			{Type: nativeStateBlock, Input: rawEnvB},
		},
	}
	reqNext := llm.CompletionRequest{
		Messages: []llm.Message{
			llm.UserText("start"),
			assistantTurnA,
			toolResultTurn,
			llm.UserText("next step"),
			assistantTurnB,
			llm.UserText("continue"),
		},
	}
	bodyBytes2, replays2, err2 := pFallbackB.requestBody(ctx, reqNext)
	if err2 != nil {
		t.Fatalf("requestBody on subsequent turn for model B failed: %v", err2)
	}
	if len(replays2) != 1 || replays2[0].Receipt != "receiptB" {
		t.Fatalf("replays on model B subsequent turn should contain model B state, got %+v", replays2)
	}
	if !strings.Contains(string(bodyBytes2), `"model":"fallback-model-b"`) {
		t.Fatalf("payload missing fallback model B wire target: %s", string(bodyBytes2))
	}

	// 3. DeriveSessionChainModel detects branch model and effort B from history.
	derivedModel, derivedEffort, ok := DeriveSessionChainModel(ctx, reqNext.Messages, "7", "claude", []string{"primary-model-a", "fallback-model-b", "fallback-model-c"})
	if !ok || derivedModel != "fallback-model-b" || derivedEffort != "low" {
		t.Fatalf("DeriveSessionChainModel = (%q, %q, %v), want (fallback-model-b, low, true)", derivedModel, derivedEffort, ok)
	}

	pPrimary := &nativeProvider{profileID: "7", provider: "claude", model: "primary-model-a", effort: "high"}
	primaryBody, primaryReplay, primaryErr := pPrimary.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{assistantTurnA, toolResultTurn}})
	if primaryErr != nil || len(primaryReplay) != 1 || !strings.Contains(string(primaryBody), `"type":"tool_use"`) {
		t.Fatalf("primary native success did not preserve typed history: replay=%+v err=%v body=%s", primaryReplay, primaryErr, primaryBody)
	}

	pLower := &nativeProvider{profileID: "7", provider: "claude", model: "primary-model-a", effort: "low"}
	_, lowReplay, lowErr := pLower.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{assistantTurnA, toolResultTurn}})
	if lowErr != nil || len(lowReplay) != 0 {
		t.Fatalf("same-model effort handoff should omit prior replay: replay=%+v err=%v", lowReplay, lowErr)
	}
	marker := workerChatMarker("request-privacy")
	userWithMarker := llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("operator says " + marker + "continue")}}
	markerReq := llm.CompletionRequest{Messages: []llm.Message{userWithMarker}}
	markerBody, _, markerErr := pFallbackB.requestBody(ctx, markerReq)
	if markerErr != nil || strings.Contains(string(markerBody), marker) || !strings.Contains(userWithMarker.Content[0].Text, marker) {
		t.Fatalf("worker marker privacy or original-history preservation failed: err=%v body=%s", markerErr, markerBody)
	}

	unauthCtx := WithAllowedFallbackChoices(context.Background(), []NativeModelChoice{{Model: "unrelated-model"}})
	unauthCtx = transcript.WithSessionID(unauthCtx, "session-fallback")
	_, _, errUnauth := pFallbackB.requestBody(unauthCtx, reqHop)
	if errUnauth == nil {
		t.Fatal("unauthorized foreign model should be rejected")
	}

	uninspectableMsg := llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: "custom_binary_payload", Text: "bytes"}}}
	_, _, errUninspectable := pFallbackB.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{assistantTurnA, uninspectableMsg}})
	if errUninspectable == nil {
		t.Fatal("uninspectable attachment must be rejected")
	}

	nested := llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "call-1", Content: []llm.ContentBlock{{Type: "image"}}}}}
	_, _, nestedErr := pFallbackB.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{assistantTurnA, nested}})
	if nestedErr == nil {
		t.Fatal("nested tool-result attachment must be rejected")
	}
}

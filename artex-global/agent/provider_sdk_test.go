package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/sdkbridge"
	"github.com/Autumn-27/norma/llm"
)

const sdkToolUseLine = `{"type":"done","reason":"toolUse","message":{"role":"assistant","content":[` +
	`{"type":"thinking","thinking":"plan","thinkingSignature":"sig-1"},` +
	`{"type":"redactedThinking","data":"enc-9"},` +
	`{"type":"text","text":"Checking."},` +
	`{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"a.txt"}}],` +
	`"usage":{"input":11,"output":7,"cacheRead":3,"cacheWrite":2},"stopReason":"toolUse"}}` + "\n"

// fakeSDKBridge serves one canned NDJSON inference and returns the posted body.
func fakeSDKBridge(t *testing.T, ndjson string) (*sdkbridge.Client, *string) {
	t.Helper()
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/v1/profiles/7/infer" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		posted = string(b)
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, ndjson)
	}))
	t.Cleanup(srv.Close)
	c, err := sdkbridge.New(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	return c, &posted
}

func newTestSDKProvider(t *testing.T, ndjson string) (*sdkProvider, *string) {
	t.Helper()
	c, posted := fakeSDKBridge(t, ndjson)
	return &sdkProvider{bridge: c, profileID: "7", provider: "anthropic", model: "m"}, posted
}

func userText(s string) llm.Message {
	return llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: s}}}
}

func toolResultTurn(id, text string) llm.Message {
	return llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{
		Type: llm.BlockToolResult, ToolUseID: id,
		Content: []llm.ContentBlock{{Type: llm.BlockText, Text: text}},
	}}}
}

func TestSDKCompleteProjectsBlocksAndKeepsNativeState(t *testing.T) {
	p, _ := newTestSDKProvider(t, sdkToolUseLine)
	msg, stop, usage, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{userText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	if stop != "tool_use" {
		t.Errorf("stop = %q; want tool_use", stop)
	}
	if want := (llm.Usage{InputTokens: 11, OutputTokens: 7, CacheReadTokens: 3, CacheWriteTokens: 2}); usage != want {
		t.Errorf("usage = %+v; want %+v", usage, want)
	}
	if len(msg.Content) != 4 {
		t.Fatalf("blocks = %d; want thinking, text, tool_use, provider_state", len(msg.Content))
	}
	var thinking, text, tool, state *llm.ContentBlock
	for i := range msg.Content {
		b := &msg.Content[i]
		switch b.Type {
		case llm.BlockThinking:
			thinking = b
		case llm.BlockText:
			text = b
		case llm.BlockToolUse:
			tool = b
		case sdkStateBlock:
			state = b
		}
		// The redacted payload is opaque encrypted state and must not appear in readable neutral blocks.
		if b.Type != sdkStateBlock && strings.Contains(b.Thinking+b.Text+b.Signature, "enc-9") {
			t.Errorf("redacted payload leaked into readable block: %+v", b)
		}
	}
	if thinking == nil || thinking.Thinking != "plan" || thinking.Signature != "sig-1" {
		t.Errorf("signed thinking lost: %+v", thinking)
	}
	if text == nil || text.Text != "Checking." {
		t.Errorf("visible text lost: %+v", text)
	}
	if tool == nil || tool.ID != "call_1" || tool.Name != "read" || string(tool.Input) != `{"path":"a.txt"}` {
		t.Errorf("tool_use projection = %+v", tool)
	}
	if state == nil || !strings.Contains(string(state.Input), `"data":"enc-9"`) || !strings.Contains(string(state.Input), `"thinkingSignature":"sig-1"`) {
		t.Errorf("provider_state does not carry the full native message: %+v", state)
	}
}

func TestSDKReplaySendsNativeStateWhenProjectionMatches(t *testing.T) {
	p, _ := newTestSDKProvider(t, sdkToolUseLine)
	msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{userText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := p.requestBody(llm.CompletionRequest{Messages: []llm.Message{userText("hi"), msg, toolResultTurn("call_1", "file body")}})
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Context struct {
			Messages []map[string]any `json:"messages"`
		} `json:"context"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Context.Messages) != 3 {
		t.Fatalf("messages = %d; want user, assistant native, toolResult", len(req.Context.Messages))
	}
	asst := req.Context.Messages[1]
	content, _ := asst["content"].([]any)
	if asst["role"] != "assistant" || len(content) < 2 {
		t.Fatalf("assistant replay = %v", asst)
	}
	if first, _ := content[0].(map[string]any); first["thinkingSignature"] != "sig-1" {
		t.Errorf("native signature not replayed: %v", first)
	}
	if second, _ := content[1].(map[string]any); second["data"] != "enc-9" {
		t.Errorf("encrypted redacted thinking not replayed: %v", second)
	}
	if tr := req.Context.Messages[2]; tr["role"] != "toolResult" || tr["toolName"] != "read" {
		t.Errorf("tool result replay = %v", tr)
	}
}

func TestSDKReplayRejectsStateThatConflictsWithNeutral(t *testing.T) {
	p, _ := newTestSDKProvider(t, sdkToolUseLine)
	msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{userText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	edited := llm.Message{Role: llm.RoleAssistant, Content: append([]llm.ContentBlock(nil), msg.Content...)}
	edited.Content[2].Text = "edited after capture"
	edited.Content[2].Signature = "forged"
	_, err = p.requestBody(llm.CompletionRequest{Messages: []llm.Message{userText("hi"), edited, toolResultTurn("call_1", "x")}})
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("requestBody with edited neutral blocks: err = %v; want conflict error", err)
	}
}

func TestSDKCompleteRefusalMarksRefusal(t *testing.T) {
	line := `{"type":"done","reason":"stop","message":{"role":"assistant","content":[{"type":"text","text":"no"}],` +
		`"usage":{},"stopDetails":{"type":"refusal"}}}` + "\n"
	p, _ := newTestSDKProvider(t, line)
	ctx := llmrec.WithRefusalSink(context.Background())
	_, stop, _, err := p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{userText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	if stop != "refusal" || !llmrec.RefusalObserved(ctx) {
		t.Fatalf("stop = %q, observed = %v; want refusal recorded", stop, llmrec.RefusalObserved(ctx))
	}
}

func TestSDKCompleteFailureModes(t *testing.T) {
	cases := map[string]string{
		"eof without terminal": `{"type":"text"}` + "\n",
		"malformed line":       "not json\n",
		"bridge_error":         `{"type":"bridge_error","code":"upstream_failed"}` + "\n",
		"error terminal":       `{"type":"error","reason":"error","error":{"role":"assistant","content":[],"usage":{}}}` + "\n",
		"aborted":              `{"type":"done","reason":"aborted","message":{"role":"assistant","content":[],"usage":{}}}` + "\n",
		"unknown block":        `{"type":"done","reason":"stop","message":{"role":"assistant","content":[{"type":"future_block"}],"usage":{}}}` + "\n",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := newTestSDKProvider(t, line)
			if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{userText("hi")}}); err == nil {
				t.Fatal("Complete succeeded; want error")
			}
		})
	}
}

func TestSDKBridgeErrorCarriesCodeNotProse(t *testing.T) {
	p, _ := newTestSDKProvider(t, `{"type":"bridge_error","code":"upstream_failed","message":"secret provider prose"}`+"\n")
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{userText("hi")}})
	if err == nil || !strings.Contains(err.Error(), "upstream_failed") || strings.Contains(err.Error(), "secret provider prose") {
		t.Fatalf("err = %v; want safe code without provider prose", err)
	}
}

func TestSDKCompleteCanceledContextReturnsCancellation(t *testing.T) {
	p, _ := newTestSDKProvider(t, sdkToolUseLine)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{userText("hi")}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

func TestSDKStreamIsUnsupported(t *testing.T) {
	p := &sdkProvider{}
	var got error
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		got = err
	}
	if !errors.Is(got, errSDKStreamUnsupported) {
		t.Fatalf("Stream error = %v; want errSDKStreamUnsupported", got)
	}
}

func TestNewProviderForProfileValidation(t *testing.T) {
	c, _ := fakeSDKBridge(t, sdkToolUseLine)
	if _, err := (Config{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "m"}).NewProviderForProfile("7", nil); err == nil {
		t.Error("nil bridge accepted for SDK profile")
	}
	if _, err := (Config{AuthMethod: "claude_code", Format: llm.FormatOpenAI, Model: "m"}).NewProviderForProfile("7", c); err == nil {
		t.Error("claude_code with a non-anthropic format accepted")
	}
	prov, err := (Config{AuthMethod: "claude_code", Format: llm.FormatAnthropic, Model: "m"}).NewProviderForProfile("7", c)
	if err != nil {
		t.Fatal(err)
	}
	if sp, ok := prov.(*sdkProvider); !ok || sp.provider != "anthropic" || sp.profileID != "7" {
		t.Fatalf("provider = %#v; want *sdkProvider for anthropic profile 7", prov)
	}
}

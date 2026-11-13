package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/structuredstanza/norma/harness"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/permission"
	"github.com/structuredstanza/norma/tool"
	"github.com/structuredstanza/norma/transcript"
)

const nativeNumberArguments = `{"id":9007199254740993,"nested":[-9007199254740993,1.234567890123456789,1e40]}`

func TestNativeToolNumbersSurviveProjectionReplayAndReadableFallback(t *testing.T) {
	state := `{"id":"numeric-turn","role":"assistant","content":[{"type":"tool_use","id":"number-call","name":"capture_number","input":` + nativeNumberArguments + `}]}`
	terminal := `{"type":"done","response":` + state + `,"state":` + state + `,"receipt":"signed-fixture","usage":{"input_tokens":11,"output_tokens":7},"stop":"tool"}` + "\n"
	p, _ := nativeTestProvider(t, "claude", terminal)
	ctx := transcript.WithSessionID(context.Background(), "number-session")
	message, stop, _, err := p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("capture the number")}})
	if err != nil || stop != "tool_use" {
		t.Fatalf("tool turn: %q %v", stop, err)
	}
	blocks := message.Content
	if blocks[0].Type != llm.BlockToolUse || string(blocks[0].Input) != nativeNumberArguments {
		t.Fatalf("tool handler input lost exact numbers: %+v", blocks)
	}
	request := llm.CompletionRequest{Messages: []llm.Message{
		llm.UserText("capture the number"), {Role: llm.RoleAssistant, Content: blocks},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("number-call", "captured", false)}},
		llm.UserText("continue"),
	}}
	body, replay, err := p.requestBody(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay) != 1 || string(replay[0].State) != state || !bytes.Contains(body, []byte(nativeNumberArguments)) {
		t.Fatalf("next turn changed exact signed tool state: %s", body)
	}
	for name, input := range map[string]string{
		"rounded integer": strings.Replace(nativeNumberArguments, "9007199254740993", "9007199254740992", 1),
		"trailing JSON":   nativeNumberArguments + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			edited := request
			edited.Messages = append([]llm.Message(nil), request.Messages...)
			edited.Messages[1].Content = append([]llm.ContentBlock(nil), blocks...)
			edited.Messages[1].Content[0].Input = json.RawMessage(input)
			if _, _, err := p.requestBody(ctx, edited); err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("altered native tool arguments accepted: %v", err)
			}
		})
	}
	fallback := &nativeProvider{profileID: "7", provider: "claude", model: "next-model"}
	ctx = WithAllowedFallbackChoices(ctx, []NativeModelChoice{{Model: p.model, ReasoningEffort: p.effort}, {Model: fallback.model, ReasoningEffort: fallback.effort}})
	body, replay, err = fallback.requestBody(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay) != 0 || bytes.Contains(body, []byte("signed-fixture")) {
		t.Fatalf("readable handoff retained opaque state: %s", body)
	}
	for _, literal := range []string{"9007199254740993", "-9007199254740993", "1.234567890123456789", "1e40"} {
		if !bytes.Contains(body, []byte(literal)) {
			t.Fatalf("readable handoff changed %s: %s", literal, body)
		}
	}
	if bytes.Contains(body, []byte("9007199254740992")) {
		t.Fatalf("readable handoff rounded the integer: %s", body)
	}
}

func TestNativeAntigravityNeutralToolArgumentsStayRawAndValidated(t *testing.T) {
	p := &nativeProvider{provider: "antigravity", model: "model"}
	request := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockToolUse, ID: "number-call", Name: "capture_number", Input: json.RawMessage(nativeNumberArguments)},
	}}}}
	body, err := p.encodeInput(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"args":`+nativeNumberArguments)) {
		t.Fatalf("Antigravity neutral tool call rounded arguments: %s", body)
	}
	request.Messages[0].Content[0].Input = json.RawMessage(nativeNumberArguments + `{}`)
	if _, err := p.encodeInput(request); err == nil {
		t.Fatal("trailing tool JSON accepted")
	}
}

func TestNativeSDKToolComputesExactIntegerSuccessor(t *testing.T) {
	state := `{"id":"numeric-turn","role":"assistant","content":[{"type":"tool_use","id":"number-call","name":"capture_number","input":` + nativeNumberArguments + `}]}`
	terminal := `{"type":"done","response":` + state + `,"state":` + state + `,"receipt":"signed-fixture","usage":{},"stop":"tool"}` + "\n"
	p, _ := nativeTestProvider(t, "claude", terminal)
	registry := tool.NewRegistry(tool.Build(tool.Spec{
		Name:   "capture_number",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}, "required": []any{"id"}},
		Run: func(_ context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				ID json.Number `json:"id"`
			}
			if err := json.Unmarshal(input, &args); err != nil {
				return tool.Result{}, err
			}
			id, err := args.ID.Int64()
			if err != nil {
				return tool.Result{}, err
			}
			return tool.Result{Content: []llm.ContentBlock{llm.TextBlock(fmt.Sprintf("%d", id+1))}}, nil
		},
	}))
	calls := 0
	deps := harness.QueryDeps{CallModelSync: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		if calls == 1 {
			return p.Complete(ctx, req)
		}
		if calls != 2 {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("unexpected model call %d", calls)
		}
		result := req.Messages[len(req.Messages)-1].Content[0]
		if result.Type != llm.BlockToolResult || result.ToolUseID != "number-call" || result.IsError || toolResultText(result) != "9007199254740994" {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("integer successor tool result changed: %+v", result)
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
	}}
	input := harness.QueryInput{Messages: []llm.Message{llm.UserText("compute the exact integer successor")},
		Tools: registry, NonStreaming: true, PermissionMode: permission.ModeBypass, WorkingDir: t.TempDir()}
	ctx := transcript.WithSessionID(context.Background(), "number-session")
	var result *harness.Terminal
	for event, err := range harness.Query(ctx, input, deps) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == harness.KindResult {
			result = event.Terminal
		}
	}
	if result == nil || result.Reason != harness.ReasonCompleted || result.Text != "done" || calls != 2 {
		t.Fatalf("native tool cycle did not complete: %+v, calls=%d", result, calls)
	}
}

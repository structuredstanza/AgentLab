package harness

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/permission"
	"github.com/structuredstanza/norma/tool"
)

// gateHooks records every tool name the pre-tool gate is asked about and blocks
// the one it was told to.
type gateHooks struct {
	blocked string
	seen    []string
}

func (h *gateHooks) PreToolUse(_ context.Context, name string, _ []byte) (bool, string, []byte) {
	h.seen = append(h.seen, name)
	if name == h.blocked {
		return true, "denied by an intercept rule", nil
	}
	return false, "", nil
}

func (h *gateHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}

func (h *gateHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

// A tool invoked through ExecuteExtraTool is its own call, so the pre-tool gate
// must see the inner tool's name and its verdict must stop the call. Before
// this, the gate only saw the wrapper name and a deny rule written for the inner
// tool never fired.
func TestExecuteExtraToolGatesTheInnerTool(t *testing.T) {
	ran := false
	inner := tool.Build(tool.Spec{
		Name:        "inner_tool",
		Description: "fixture tool reached through ExecuteExtraTool",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			ran = true
			return tool.Text("inner ran"), nil
		},
	})
	reg := tool.NewRegistry(inner)
	reg.Add(tool.NewExecuteExtraTool(reg, nil))

	hooks := &gateHooks{blocked: "inner_tool"}
	m := &scriptedModel{turns: [][]llm.StreamEvent{
		toolTurn("c1", tool.ExecuteExtraToolName, `{"tool_name":"inner_tool","params":{}}`),
		textTurn("done"),
	}}
	in := QueryInput{
		Messages:       []llm.Message{llm.UserText("go")},
		Tools:          reg,
		PermissionMode: permission.ModeBypass,
		WorkingDir:     t.TempDir(),
		Hooks:          hooks,
	}
	term := drain(t, in, QueryDeps{CallModel: m.call})

	if ran {
		t.Fatal("the inner tool ran although the pre-tool gate denied it")
	}
	res := term.Messages[2].Content[0]
	if !res.IsError || !strings.Contains(res.Content[0].Text, "not permitted") {
		t.Fatalf("expected a blocked tool result, got %+v", res)
	}
	if len(hooks.seen) != 2 ||
		hooks.seen[0] != tool.ExecuteExtraToolName || hooks.seen[1] != "inner_tool" {
		t.Fatalf("pre-tool gate saw %v, want the wrapper then the inner tool", hooks.seen)
	}
}

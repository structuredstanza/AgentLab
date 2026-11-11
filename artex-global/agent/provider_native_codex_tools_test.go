package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
	"github.com/structuredstanza/norma/harness"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/permission"
	"github.com/structuredstanza/norma/tool"
	"github.com/structuredstanza/norma/transcript"
)

func TestNativeCodexDiscoversToolAndUsesItsComputedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body nativeInferBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var input struct {
			Tools []struct {
				Type       string `json:"type"`
				Name       string `json:"name"`
				Parameters struct {
					Properties map[string]struct {
						Type string `json:"type"`
					} `json:"properties"`
				} `json:"parameters"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(body.Input, &input); err != nil || len(input.Tools) != 1 || input.Tools[0].Type != "function" || input.Tools[0].Parameters.Properties["id"].Type != "integer" {
			http.Error(w, "no discoverable integer tool", http.StatusBadRequest)
			return
		}
		var state json.RawMessage
		stop := "tool"
		if len(body.Replay) == 0 {
			name, _ := json.Marshal(input.Tools[0].Name)
			args, _ := json.Marshal(`{"id":9007199254740993}`)
			state = json.RawMessage(fmt.Sprintf(`{"id":"codex-tool","output":[{"type":"function_call","call_id":"number-call","name":%s,"arguments":%s}]}`, name, args))
		} else {
			if !bytes.Contains(body.Input, []byte(`"function_call_output"`)) || !bytes.Contains(body.Input, []byte(`9007199254740994`)) {
				http.Error(w, "computed tool result absent", http.StatusBadRequest)
				return
			}
			stop = "end"
			state = json.RawMessage(`{"id":"codex-done","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Exact successor verified"}]}]}`)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "done", "response": state, "state": state, "receipt": "local-fixture-receipt", "stop": stop, "usage": map[string]int{}})
	}))
	defer server.Close()
	proxy, err := nativeproxy.New(server.URL, "local-fixture-capability")
	if err != nil {
		t.Fatal(err)
	}
	provider := &nativeProvider{proxy: proxy, profileID: "7", provider: "codex", model: "fixture-model"}
	registry := tool.NewRegistry(tool.Build(tool.Spec{
		Name:   "capture_number",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}, "required": []any{"id"}},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				ID json.Number `json:"id"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Result{}, err
			}
			id, err := args.ID.Int64()
			if err != nil {
				return tool.Result{}, err
			}
			return tool.Result{Content: []llm.ContentBlock{llm.TextBlock(fmt.Sprint(id + 1))}}, nil
		},
	}))
	input := harness.QueryInput{Messages: []llm.Message{llm.UserText("Compute the exact integer successor")}, Tools: registry, NonStreaming: true, PermissionMode: permission.ModeBypass, WorkingDir: t.TempDir()}
	ctx := transcript.WithSessionID(context.Background(), "codex-tools")
	var result *harness.Terminal
	for event, err := range harness.Query(ctx, input, harness.QueryDeps{CallModelSync: provider.Complete}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == harness.KindResult {
			result = event.Terminal
		}
	}
	if result == nil || result.Reason != harness.ReasonCompleted || result.Text != "Exact successor verified" {
		t.Fatalf("native Codex did not execute the discovered tool: %+v", result)
	}
}

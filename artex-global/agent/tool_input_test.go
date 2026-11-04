package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// The exact payload that wedged a live task: a model that decided to call the same
// tool three times emitted three objects back to back in one arguments field. The
// first is kept, because it is the call the model started with.
func TestToolInputKeepsTheFirstOfSeveralConcatenatedObjects(t *testing.T) {
	raw := json.RawMessage(`{"dsl":"ip==10.0.0.1","limit":20}{"dsl":"ip==10.0.0.1","type":"app","limit":20}{"dsl":"ip==10.0.0.1","type":"service","limit":20}`)
	got := toolInput(raw)
	if !json.Valid(got) {
		t.Fatalf("still not valid JSON: %q", got)
	}
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	if v["dsl"] != "ip==10.0.0.1" || v["type"] != nil {
		t.Errorf("kept the wrong object: %v", v)
	}
	if v["limit"] != float64(20) {
		t.Errorf("lost a field of the first object: %v", v)
	}
}

// A valid input must pass through byte for byte, or every turn would rewrite the
// history it replays.
func TestToolInputLeavesValidInputAlone(t *testing.T) {
	for _, raw := range []string{
		`{"command":"id"}`,
		`{"a":{"b":[1,2,3]}}`,
		`[1,2]`,
		`"plain"`,
	} {
		got := toolInput(json.RawMessage(raw))
		if string(got) != raw {
			t.Errorf("rewrote valid input: %q -> %q", raw, got)
		}
	}
}

// Unparseable bytes cannot be salvaged, so the empty object is sent: a no-argument
// call is recoverable, an unparseable one wedges the task.
func TestToolInputFallsBackToAnObject(t *testing.T) {
	for _, raw := range []string{``, `null`, `{broken`, `{"a":`} {
		if got := toolInput(json.RawMessage(raw)); string(got) != "{}" {
			t.Errorf("toolInput(%q) = %q, want {}", raw, got)
		}
	}
}

// An empty input is the normal shape for a no-argument tool.
func TestToolInputEmptyBecomesAnObject(t *testing.T) {
	if got := toolInput(nil); string(got) != "{}" {
		t.Errorf("toolInput(nil) = %q", got)
	}
}

// The repair has to happen on the way out too: a history entry stored before this
// guard existed must still produce a request the upstream accepts.
func TestLocalEncodeInputRepairsAStoredToolCall(t *testing.T) {
	p := &nativeProvider{provider: "custom", model: "m"}
	req := llm.CompletionRequest{
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "go"}}},
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
				Type: llm.BlockToolUse, ID: "c1", Name: "list_assets",
				Input: json.RawMessage(`{"a":1}{"b":2}`),
			}}},
		},
	}
	raw, err := p.encodeInput(req)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range body.Messages {
		for _, c := range m.ToolCalls {
			found = true
			if !json.Valid([]byte(c.Function.Arguments)) {
				t.Errorf("invalid arguments reached the wire: %q", c.Function.Arguments)
			}
		}
	}
	if !found {
		t.Fatal("tool call missing from the encoded body")
	}
}

// A no-argument call must carry an object, not an empty string: the local server's
// chat template fails parsing it before the model runs.
func TestLocalEncodeInputGivesEmptyArgumentsAnObject(t *testing.T) {
	p := &nativeProvider{provider: "custom", model: "m"}
	req := llm.CompletionRequest{
		Messages: []llm.Message{
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
				Type: llm.BlockToolUse, ID: "c1", Name: "noargs",
			}}},
		},
	}
	raw, err := p.encodeInput(req)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	for _, m := range body.Messages {
		for _, c := range m.ToolCalls {
			if c.Function.Arguments != "{}" {
				t.Errorf("arguments = %q, want {}", c.Function.Arguments)
			}
		}
	}
}

// The reason a bad call vanished from disk: a message holding an invalid RawMessage
// cannot be marshaled, so the transcript write failed and nothing reported it. Once
// the call is repaired at ingest, the message persists.
func TestRepairedToolCallIsSerializable(t *testing.T) {
	unrepaired := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
		Type: llm.BlockToolUse, ID: "c1", Name: "x",
		Input: json.RawMessage(`{"a":1}{"b":2}`),
	}}}
	if _, err := json.Marshal(unrepaired); err == nil {
		t.Fatal("this test is pointless if invalid input marshals cleanly")
	}

	repaired := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
		Type: llm.BlockToolUse, ID: "c1", Name: "x",
		Input: toolInput(json.RawMessage(`{"a":1}{"b":2}`)),
	}}}
	if _, err := json.Marshal(repaired); err != nil {
		t.Fatalf("a repaired call still cannot be persisted: %v", err)
	}
}

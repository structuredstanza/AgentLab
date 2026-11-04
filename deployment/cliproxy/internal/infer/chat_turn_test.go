package infer

import (
	"encoding/json"
	"testing"
)

// A streaming server sends one tool call's id and name once, then its arguments as
// successive fragments under the same index. Folding each fragment into a new call
// would emit one call per character, and the upstream then rejects the malformed
// arguments on the next turn. This is that exact frame sequence.
func TestChatTurnMergesStreamedToolCallFragments(t *testing.T) {
	turn := newAccumulator("custom")
	frames := []map[string]any{
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{map[string]any{
				"index": json.Number("0"), "id": "call_1", "type": "function",
				"function": map[string]any{"name": "Bash", "arguments": ""},
			}},
		}}}},
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{map[string]any{
				"index":    json.Number("0"),
				"function": map[string]any{"arguments": `{"command":"`},
			}},
		}}}},
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{map[string]any{
				"index":    json.Number("0"),
				"function": map[string]any{"arguments": `id"}`},
			}},
		}}}},
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{},
			"finish_reason": "tool_calls"}}},
	}
	for _, f := range frames {
		if err := turn.feed(f); err != nil {
			t.Fatalf("feed: %v", err)
		}
	}
	result, ok, err := turn.result()
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	var msg struct {
		ToolCalls []struct {
			ID       string `json:"id"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(result.response, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("want 1 merged tool call, got %d", len(msg.ToolCalls))
	}
	call := msg.ToolCalls[0]
	if call.ID != "call_1" || call.Function.Name != "Bash" {
		t.Fatalf("identity lost: id=%q name=%q", call.ID, call.Function.Name)
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
		t.Fatalf("arguments are not valid JSON (%q): %v", call.Function.Arguments, err)
	}
	if args["command"] != "id" {
		t.Errorf("arguments = %v", args)
	}
	if result.stop != "tool" {
		t.Errorf("stop = %q, want tool", result.stop)
	}
}

// Two calls interleaved in one stream must stay separate and keep their own arguments.
func TestChatTurnKeepsDistinctToolCallsApart(t *testing.T) {
	turn := newAccumulator("custom")
	for _, f := range []map[string]any{
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{
				map[string]any{"index": json.Number("0"), "id": "a", "function": map[string]any{"name": "One", "arguments": `{"x":1}`}},
				map[string]any{"index": json.Number("1"), "id": "b", "function": map[string]any{"name": "Two", "arguments": `{"y":2}`}},
			},
		}}}},
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{}, "finish_reason": "tool_calls"}}},
	} {
		if err := turn.feed(f); err != nil {
			t.Fatal(err)
		}
	}
	result, ok, err := turn.result()
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	var msg struct {
		ToolCalls []struct {
			ID       string `json:"id"`
			Function struct {
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(result.response, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 2 {
		t.Fatalf("want 2 calls, got %d", len(msg.ToolCalls))
	}
	if msg.ToolCalls[0].ID != "a" || msg.ToolCalls[1].ID != "b" {
		t.Errorf("order or identity changed: %+v", msg.ToolCalls)
	}
}

// A no-argument tool must still carry a JSON object, or the server's template fails
// parsing it before the model runs.
func TestChatTurnGivesEmptyToolArgumentsAnObject(t *testing.T) {
	turn := newAccumulator("custom")
	if err := turn.feed(map[string]any{"choices": []any{map[string]any{
		"index": json.Number("0"),
		"message": map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"id": "c1", "function": map[string]any{"name": "NoArgs", "arguments": ""},
			}},
		},
		"finish_reason": "tool_calls",
	}}}); err != nil {
		t.Fatal(err)
	}
	result, ok, err := turn.result()
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	var msg struct {
		ToolCalls []struct {
			Function struct {
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(result.response, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].Function.Arguments != "{}" {
		t.Fatalf("empty arguments not normalized: %+v", msg.ToolCalls)
	}
}

// A complete non-streaming message carries whole arguments; they must not be lost.
func TestChatTurnReadsAWholeMessage(t *testing.T) {
	turn := newAccumulator("custom")
	if err := turn.feed(map[string]any{"choices": []any{map[string]any{
		"index": json.Number("0"),
		"message": map[string]any{
			"role": "assistant", "content": "done",
			"tool_calls": []any{map[string]any{
				"id": "c1", "function": map[string]any{"name": "Bash", "arguments": `{"command":"ls"}`},
			}},
		},
		"finish_reason": "stop",
	}}}); err != nil {
		t.Fatal(err)
	}
	result, ok, err := turn.result()
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	var msg struct {
		Content   string `json:"content"`
		ToolCalls []struct {
			Function struct {
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(result.response, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Content != "done" || len(msg.ToolCalls) != 1 {
		t.Fatalf("whole message not preserved: %+v", msg)
	}
	if msg.ToolCalls[0].Function.Arguments != `{"command":"ls"}` {
		t.Errorf("arguments = %q", msg.ToolCalls[0].Function.Arguments)
	}
	if result.stop != "end" {
		t.Errorf("stop = %q, want end", result.stop)
	}
}

// Some servers send each tool call in its own frame with no usable index, so every
// fragment arrives at position 0. Without splitting on a fresh id, the calls collapse
// into one whose arguments are several JSON objects concatenated, and the upstream
// rejects that on the following turn.
func TestChatTurnSplitsCallsThatShareAPosition(t *testing.T) {
	turn := newAccumulator("custom")
	for _, f := range []map[string]any{
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{map[string]any{
				"id": "a", "function": map[string]any{"name": "One", "arguments": `{"x":1}`},
			}},
		}}}},
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{map[string]any{
				"id": "b", "function": map[string]any{"name": "Two", "arguments": `{"y":2}`},
			}},
		}}}},
		{"choices": []any{map[string]any{"index": json.Number("0"), "delta": map[string]any{
			"tool_calls": []any{map[string]any{
				"id": "c", "function": map[string]any{"name": "Three", "arguments": `{"z":3}`},
			}},
		}}}},
	} {
		if err := turn.feed(f); err != nil {
			t.Fatal(err)
		}
	}
	result, ok, err := turn.result()
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	var msg struct {
		ToolCalls []struct {
			ID       string `json:"id"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(result.response, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 3 {
		t.Fatalf("want 3 separate calls, got %d", len(msg.ToolCalls))
	}
	for i, want := range []struct{ id, args string }{{"a", `{"x":1}`}, {"b", `{"y":2}`}, {"c", `{"z":3}`}} {
		if msg.ToolCalls[i].ID != want.id {
			t.Errorf("call %d id = %q, want %q", i, msg.ToolCalls[i].ID, want.id)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(msg.ToolCalls[i].Function.Arguments), &v); err != nil {
			t.Errorf("call %d arguments are not valid JSON: %q", i, msg.ToolCalls[i].Function.Arguments)
		}
	}
}

// The decoder reads numbers as json.Number, so a counter reported as a number would
// otherwise be dropped and every turn would report zero tokens.
func TestChatTurnReadsNumericUsage(t *testing.T) {
	turn := newAccumulator("custom")
	if err := turn.feed(map[string]any{
		"choices": []any{map[string]any{
			"index":         json.Number("0"),
			"delta":         map[string]any{"content": "hi"},
			"finish_reason": "stop",
		}},
		"timings": map[string]any{
			"cache_n":     json.Number("2534"),
			"prompt_n":    json.Number("4"),
			"predicted_n": json.Number("12"),
		},
	}); err != nil {
		t.Fatal(err)
	}
	result, ok, err := turn.result()
	if err != nil || !ok {
		t.Fatalf("result ok=%v err=%v", ok, err)
	}
	if result.usage.CacheReadTokens != 2534 {
		t.Errorf("cache_read = %d, want 2534", result.usage.CacheReadTokens)
	}
	if result.usage.InputTokens != 2538 {
		t.Errorf("input = %d, want 2538 (read + cached)", result.usage.InputTokens)
	}
	if result.usage.OutputTokens != 12 {
		t.Errorf("output = %d, want 12", result.usage.OutputTokens)
	}
}

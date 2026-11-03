package infer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/artex/cliproxyhost/internal/contract"
	"github.com/artex/cliproxyhost/internal/privacy"
)

func TestNativeClaudeToolNumbersSurviveSignedAccumulation(t *testing.T) {
	wire, err := os.ReadFile("../../../fixtures/claude_native_numbers_sse.txt")
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := privacy.NewReceipts(filepath.Join(t.TempDir(), "receipt.key"))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"capture the number"}],"max_tokens":256}`)
	service := &Service{d: Deps{Streamer: promptBlockStreamer{wire}, Receipts: receipts,
		Captured: func(context.Context) ([]byte, bool) { return input, true },
	}}
	binding := contract.Binding{Provider: contract.ProviderClaude, Model: "claude-sonnet-4-6", Profile: "7", SessionID: "number-session", CredentialID: "fixture-credential"}
	sink := &fixtureSink{}
	if err := service.stream(context.Background(), binding, input, binding.CredentialID, sink); err != nil {
		t.Fatal(err)
	}
	var done *Done
	for _, record := range sink.records {
		if value, ok := record.(Done); ok {
			done = &value
		}
	}
	if done == nil || done.Stop != StopTool || done.Usage.InputTokens != 11 || done.Usage.OutputTokens != 7 {
		t.Fatalf("missing tool turn or usage: %+v", done)
	}
	if err := receipts.Verify(done.Receipt, binding, done.State); err != nil {
		t.Fatal(err)
	}
	var state struct {
		Content []struct {
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(done.State, &state); err != nil {
		t.Fatal(err)
	}
	want := `{"id":9007199254740993,"nested":[-9007199254740993,1.234567890123456789,1e40]}`
	if len(state.Content) != 1 || string(state.Content[0].Input) != want {
		t.Fatalf("signed tool arguments lost exact numbers: %s", done.State)
	}
	edited := bytes.Replace(done.State, []byte("9007199254740993"), []byte("9007199254740992"), 1)
	if err := receipts.Verify(done.Receipt, binding, edited); err == nil {
		t.Fatal("receipt accepted a rounded tool argument")
	}
}

func TestNativeClaudeToolArgumentsRejectNullAndTrailingJSON(t *testing.T) {
	for name, raw := range map[string]string{"null object": "null", "trailing JSON": `{"id":1}{"id":2}`} {
		t.Run(name, func(t *testing.T) {
			acc := newAccumulator(contract.ProviderClaude)
			for _, event := range []map[string]any{
				{"type": "message_start", "message": map[string]any{"role": "assistant"}},
				{"type": "content_block_start", "content_block": map[string]any{"type": "tool_use", "id": "call", "name": "capture_number", "input": map[string]any{}}},
				{"type": "content_block_delta", "delta": map[string]any{"type": "input_json_delta", "partial_json": raw}},
			} {
				if err := acc.feed(event); err != nil {
					t.Fatal(err)
				}
			}
			if err := acc.feed(map[string]any{"type": "content_block_stop"}); err == nil {
				t.Fatal("invalid tool object was accepted")
			}
		})
	}
}

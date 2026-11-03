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
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type promptBlockStreamer struct{ wire []byte }

func (s promptBlockStreamer) ExecuteStream(context.Context, []string, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	ch := make(chan coreexecutor.StreamChunk, 1)
	ch <- coreexecutor.StreamChunk{Payload: s.wire}
	close(ch)
	return &coreexecutor.StreamResult{Chunks: ch}, nil
}

func TestAntigravityPromptRefusalIsSigned(t *testing.T) {
	fixture, err := os.ReadFile("../../../fixtures/gemini_native_safety_sse.txt")
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(fixture, []byte("data: ")), &wrapper); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"wrapped", fixture},
		{"unwrapped", append(append([]byte("data: "), wrapper.Response...), '\n', '\n')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipts, err := privacy.NewReceipts(filepath.Join(t.TempDir(), "receipt.key"))
			if err != nil {
				t.Fatal(err)
			}
			input := []byte(`{"contents":[{"role":"user","parts":[{"text":"fixture prompt"}]}]}`)
			service := &Service{d: Deps{
				Streamer: promptBlockStreamer{tc.wire}, Receipts: receipts,
				Captured: func(context.Context) ([]byte, bool) { return input, true },
			}}
			binding := contract.Binding{Provider: contract.ProviderAntigravity, Model: "model", Profile: "7", SessionID: "fixture-session", CredentialID: "fixture-credential"}
			sink := &fixtureSink{}
			if err := service.stream(context.Background(), binding, input, binding.CredentialID, sink); err != nil {
				t.Fatalf("prompt block failed as a transport/truncation error: %v", err)
			}
			var done *Done
			for _, record := range sink.records {
				if terminal, ok := record.(Done); ok {
					if done != nil {
						t.Fatal("prompt block emitted duplicate terminal records")
					}
					done = &terminal
				}
			}
			if done == nil || done.Stop != StopRefusal || done.Usage.InputTokens != 12 || done.Usage.OutputTokens != 0 {
				t.Fatalf("prompt block lost its refusal or usage: %+v", done)
			}
			if err := receipts.Verify(done.Receipt, binding, done.State); err != nil {
				t.Fatalf("prompt-block receipt is not valid: %v", err)
			}
			for _, raw := range []json.RawMessage{done.State, done.Response} {
				var body struct {
					Candidates     []json.RawMessage `json:"candidates"`
					PromptFeedback struct {
						BlockReason string `json:"blockReason"`
					} `json:"promptFeedback"`
				}
				if err := json.Unmarshal(raw, &body); err != nil || body.Candidates == nil || len(body.Candidates) != 0 || body.PromptFeedback.BlockReason != "SAFETY" {
					t.Fatalf("blocked prompt invented a candidate or lost feedback: %s (%v)", raw, err)
				}
			}
		})
	}
}

func TestAntigravityPromptFeedbackCannotManufactureCompletion(t *testing.T) {
	for name, raw := range map[string]string{
		"empty feedback":        `{"promptFeedback":{}}`,
		"empty reason":          `{"promptFeedback":{"blockReason":""}}`,
		"unspecified reason":    `{"promptFeedback":{"blockReason":"BLOCK_REASON_UNSPECIFIED"}}`,
		"non-string reason":     `{"promptFeedback":{"blockReason":true}}`,
		"non-object feedback":   `{"promptFeedback":[]}`,
		"whitespace reason":     `{"promptFeedback":{"blockReason":"   "}}`,
		"malformed candidates":  `{"candidates":"invalid","promptFeedback":{"blockReason":"SAFETY"}}`,
		"contradictory content": `{"candidates":[{"content":{"role":"model","parts":[{"text":"answer"}]},"finishReason":"STOP"}],"promptFeedback":{"blockReason":"SAFETY"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			acc := newAccumulator(contract.ProviderAntigravity)
			event, err := decodeObject([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := acc.feed(event); err == nil {
				if _, complete, err := acc.result(); err == nil && complete {
					t.Fatal("malformed or unblocked prompt became a completed refusal")
				}
			}
		})
	}
}

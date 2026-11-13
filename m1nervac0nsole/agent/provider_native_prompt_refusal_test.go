package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/llmrec"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

func TestNativeAntigravityPromptRefusalPreservesReceiptWithoutInventingHistory(t *testing.T) {
	state := `{"candidates":[],"promptFeedback":{"blockReason":"SAFETY"}}`
	terminal := `{"type":"done","response":` + state + `,"state":` + state + `,"receipt":"signed-fixture","usage":{"input_tokens":12},"stop":"refusal"}` + "\n"
	p, _ := nativeTestProvider(t, "antigravity", terminal)
	ctx := llmrec.WithRefusalSink(transcript.WithSessionID(context.Background(), "s"))
	msg, stop, usage, err := p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil || stop != "refusal" || !llmrec.RefusalObserved(ctx) || usage.InputTokens != 12 || msg.Text() != "" {
		t.Fatalf("prompt refusal lost: message=%+v stop=%q usage=%+v err=%v", msg, stop, usage, err)
	}
	for _, block := range msg.Content {
		if block.Type != nativeStateBlock {
			t.Fatalf("blocked prompt invented assistant content: %+v", block)
		}
	}
	body, replay, err := p.requestBody(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi"), msg, llm.UserText("continue")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(replay) != 1 || replay[0].Receipt != "signed-fixture" || string(replay[0].State) != state {
		t.Fatalf("blocked turn lost its receipt/state: %+v", replay)
	}
	var sent struct {
		Input struct {
			Contents []struct {
				Role  string `json:"role"`
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"contents"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatal(err)
	}
	var roles, texts []string
	for _, content := range sent.Input.Contents {
		roles = append(roles, content.Role)
		for _, part := range content.Parts {
			texts = append(texts, part.Text)
		}
	}
	if !reflect.DeepEqual(roles, []string{"user", "user"}) || !reflect.DeepEqual(texts, []string{"hi", "continue"}) {
		t.Fatalf("blocked turn invented replay content: roles=%v texts=%v", roles, texts)
	}
}

func TestNativeAntigravityEmptyCandidatesRequirePromptBlock(t *testing.T) {
	for name, state := range map[string]string{
		"absent candidates":     `{"promptFeedback":{"blockReason":"SAFETY"}}`,
		"null candidates":       `{"candidates":null,"promptFeedback":{"blockReason":"SAFETY"}}`,
		"absent feedback":       `{"candidates":[]}`,
		"empty feedback":        `{"candidates":[],"promptFeedback":{}}`,
		"unspecified reason":    `{"candidates":[],"promptFeedback":{"blockReason":"BLOCK_REASON_UNSPECIFIED"}}`,
		"non-string reason":     `{"candidates":[],"promptFeedback":{"blockReason":42}}`,
		"non-object feedback":   `{"candidates":[],"promptFeedback":[]}`,
		"contradictory content": `{"candidates":[{"content":{"role":"model","parts":[{"text":"answer"}]}}],"promptFeedback":{"blockReason":"SAFETY"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := projectNative("antigravity", json.RawMessage(state)); err == nil {
				t.Fatal("malformed prompt block accepted as a native terminal")
			}
		})
	}
}

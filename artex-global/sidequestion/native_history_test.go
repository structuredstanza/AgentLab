package sidequestion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func nativeMainSnapshot(t *testing.T, provider string) Snapshot {
	t.Helper()
	state, err := json.Marshal(map[string]any{
		"version": 2, "provider": provider, "profile_id": "7", "session_id": "main-session",
		"receipt": "PRIVATE_MAIN_RECEIPT", "state": map[string]string{
			"signature": "PRIVATE_MAIN_SIGNATURE", "encrypted_content": "PRIVATE_MAIN_ENCRYPTED_STATE", "data": "PRIVATE_MAIN_REDACTED_THINKING",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{Request: llm.CompletionRequest{Messages: []llm.Message{
		llm.UserText(strings.Repeat("Historical inspection context: inspect the prior evidence before answering. ", 400)),
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockThinking, Thinking: "PRIVATE_MAIN_THOUGHT", Signature: "PRIVATE_MAIN_SIGNATURE"},
			{Type: llm.BlockText, Text: "Inspecting the evidence."},
			{Type: llm.BlockToolUse, ID: "call-1", Name: "inspect", Input: json.RawMessage(`{"id":9007199254740993}`)},
			{Type: "provider_state", Input: state},
		}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "call-1", Content: []llm.ContentBlock{llm.TextBlock("evidence-42")}}}},
	}}, Model: Model{WindowTokens: 32000}}
}

func assertIndependentHistory(t *testing.T, request llm.CompletionRequest) {
	t.Helper()
	body := string(mustJSON(t, request))
	for _, secret := range []string{"PRIVATE_MAIN_RECEIPT", "PRIVATE_MAIN_SIGNATURE", "PRIVATE_MAIN_ENCRYPTED_STATE", "PRIVATE_MAIN_REDACTED_THINKING", "PRIVATE_MAIN_THOUGHT"} {
		if strings.Contains(body, secret) {
			t.Errorf("independent request disclosed %s", secret)
		}
	}
}

func TestNativeMainHistoryIsReadableBeforeSideBudgetAndCompaction(t *testing.T) {
	for _, provider := range []string{"claude", "codex", "antigravity"} {
		t.Run(provider, func(t *testing.T) {
			snapshot := nativeMainSnapshot(t, provider)
			original := string(mustJSON(t, snapshot))
			request, err := BuildRequest(snapshot, nil, "What did the inspection show?")
			if err != nil {
				t.Fatal(err)
			}
			assertIndependentHistory(t, request)
			body := string(mustJSON(t, request))
			for _, evidence := range []string{"inspect", "call-1", "9007199254740993", "evidence-42"} {
				if !strings.Contains(body, evidence) {
					t.Errorf("readable evidence lost: %s", evidence)
				}
			}
			answers, summaries := 0, 0
			service := SideQuestionService{fakeProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				assertIndependentHistory(t, req)
				if transcript.SessionIDFrom(ctx) != "side-session" {
					t.Error("main session replaced independent identity")
				}
				if len(req.System) > 0 && req.System[0] == summaryInstruction {
					summaries++
					return assistant("The earlier request asked to inspect the evidence."), "end_turn", llm.Usage{InputTokens: 3}, nil
				}
				answers++
				if answers == 1 {
					return llm.Message{}, "", llm.Usage{}, errors.New("maximum context length exceeded")
				}
				if !strings.Contains(string(mustJSON(t, req)), "evidence-42") {
					t.Error("compaction lost the retained tool result")
				}
				return assistant("The inspection showed evidence-42."), "end_turn", llm.Usage{InputTokens: 5}, nil
			}}}
			var memory Memory
			ctx := transcript.WithSessionID(t.Context(), "side-session")
			answer, _, err := service.Respond(ctx, snapshot, "What did the inspection show?", replayFixture(nil, &memory), ContextOptions{}, nil)
			if err != nil || answers != 2 || summaries != 1 || answer.Text != "The inspection showed evidence-42." || answer.Usage.InputTokens != 8 {
				t.Fatalf("independent compaction outcome: %+v answers=%d summaries=%d err=%v", answer, answers, summaries, err)
			}
			if string(mustJSON(t, snapshot)) != original {
				t.Error("main snapshot was mutated")
			}
			// Main thinking is private training data, not side-session input budget.
			snapshot.Request.Messages[1].Content[0].Thinking = strings.Repeat("private thinking ", 20000)
			request, err = BuildRequest(snapshot, nil, "What did the inspection show?")
			if err != nil {
				t.Fatalf("main reasoning consumed the side budget: %v", err)
			}
			assertIndependentHistory(t, request)
		})
	}
}

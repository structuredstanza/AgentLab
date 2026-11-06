package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type reviewCaptureProvider struct {
	request  llm.CompletionRequest
	sessions []string
	reply    *llm.Message
	stop     string
}

func (p *reviewCaptureProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("judge provider supports Complete only"))
	}
}

func (p *reviewCaptureProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.request = req
	p.sessions = append(p.sessions, transcript.SessionIDFrom(ctx))
	if p.reply != nil {
		return *p.reply, p.stop, llm.Usage{}, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(`{"decision":"ask","comment":"Action: delete file; Consequence: file will be lost, ownership unconfirmed; Matched rule: ASK (ownership unclear)"}`)}}, "end_turn", llm.Usage{}, nil
}

// Assert the actual model request, rather than merely the envelope helper.
func TestReviewCompletionSendsCurrentCallWithoutHistory(t *testing.T) {
	ctx := intercept.WithReviewContext(t.Context(), "/tmp/review-fixture", intercept.ReviewBackground{Source: intercept.BackgroundUserMessage, Text: "clean up this test's files"})
	ctx, trace := intercept.WithTrace(ctx, "GLOBAL_OVERVIEW_SENTINEL", []db.InterceptContextEntry{
		{Kind: "tool_use", Tool: "Write", ToolUseID: "created", Text: `{"path":"probe.txt"}`},
		{Kind: "tool_result", ToolUseID: "created", Text: "file created"},
		{Kind: "assistant", Text: "untrusted worker speculation"},
	})
	args := json.RawMessage(`{"command":"rm probe.txt","timeout":1000}`)
	trace.Start("current", "Bash", args)
	input, err := intercept.BuildReviewInput(intercept.WithCall(ctx, "Bash", args), "Bash", args)
	if err != nil {
		t.Fatal(err)
	}
	p := &reviewCaptureProvider{}
	prompt := intercept.EffectiveJudgePrompt(intercept.DefaultJudgePrompt)
	reply, err := reviewCompletion(ctx, p, prompt, input)
	if err != nil || intercept.ParseVerdict(reply).Action != "ask" {
		t.Fatalf("%s %v", reply, err)
	}
	if len(p.request.System) != 1 || p.request.System[0] != prompt || len(p.request.Messages) != 1 {
		t.Fatal("wrong review request roles")
	}
	if !strings.Contains(prompt, intercept.JudgeOutputContract) || p.request.MaxTokens < 1024 {
		t.Fatal("review request cannot return a complete explanation")
	}
	body := p.request.Messages[0].Content[0].Text
	var got intercept.ReviewInput
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 {
		t.Fatalf("unexpected envelope keys: %s", body)
	}
	for _, key := range []string{"version", "working_directory", "background", "tool_name", "arguments"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing %s", key)
		}
	}
	if strings.Contains(body, "file created") || strings.Contains(body, `"path"`) {
		t.Fatal("history leaked into actual model request")
	}
	if got.Version != 4 || got.Background == nil || got.Background.Source != intercept.BackgroundUserMessage || got.Background.Text != "clean up this test's files" || got.WorkingDir != "/tmp/review-fixture" || string(got.Arguments) != string(args) || strings.Contains(body, "worker speculation") || strings.Contains(body, "GLOBAL_OVERVIEW_SENTINEL") {
		t.Fatalf("wrong model input: %s", body)
	}
}

func TestJudgeCompletionUsesIndependentSessionsAndRejectsUnsafeAnswers(t *testing.T) {
	ctx := transcript.WithSessionID(t.Context(), "main-native-session")
	provider := &reviewCaptureProvider{}
	for range 2 {
		if _, err := judgeCompletion(ctx, provider, "review", "current call"); err != nil {
			t.Fatal(err)
		}
	}
	if provider.sessions[0] == "main-native-session" || provider.sessions[1] == provider.sessions[0] {
		t.Fatalf("judge reused a native reasoning session: %v", provider.sessions)
	}
	verdict := llm.TextBlock(`{"decision":"allow","comment":"Action: inspect file; Consequence: read only; Matched rule: ALLOW"}`)
	for _, test := range []struct {
		name, stop string
		role       llm.Role
		content    []llm.ContentBlock
		canceled   bool
	}{
		{"refused", "refusal", llm.RoleAssistant, []llm.ContentBlock{verdict}, false},
		{"truncated", "max_tokens", llm.RoleAssistant, []llm.ContentBlock{verdict}, false},
		{"missing stop", "", llm.RoleAssistant, []llm.ContentBlock{verdict}, false},
		{"wrong role", "end_turn", llm.RoleUser, []llm.ContentBlock{verdict}, false},
		{"tool with verdict", "end_turn", llm.RoleAssistant, []llm.ContentBlock{verdict, {Type: llm.BlockToolUse, ID: "unexpected", Name: "Bash", Input: json.RawMessage(`{}`)}}, false},
		{"canceled", "end_turn", llm.RoleAssistant, []llm.ContentBlock{verdict}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if test.canceled {
				cancel()
			}
			provider := &reviewCaptureProvider{reply: &llm.Message{Role: test.role, Content: test.content}, stop: test.stop}
			if text, err := judgeCompletion(ctx, provider, "review", "current call"); err == nil || text != "" {
				t.Fatalf("unsafe judge answer became a verdict: %q %v", text, err)
			}
		})
	}
}

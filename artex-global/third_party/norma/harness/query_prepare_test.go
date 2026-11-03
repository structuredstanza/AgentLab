package harness

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestModelRouteRenegotiationStopsAtOutputBoundary(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before output", true: "after output"}[committed], func(t *testing.T) {
			prepared, completed := 0, 0
			deps := QueryDeps{
				BeforeModel: func(ctx context.Context, _ llm.CompletionRequest) (context.Context, bool, error) {
					prepared++
					return ctx, prepared > 1, nil
				},
				CallModel: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
					return func(yield func(llm.StreamEvent, error) bool) {
						if committed && !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "already visible"}, nil) {
							return
						}
						yield(llm.StreamEvent{}, llm.ErrModelRouteChanged)
					}
				},
				CallModelSync: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
					completed++
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ready")}}, "end_turn", llm.Usage{}, nil
				},
			}
			var terminal *Terminal
			for event, _ := range Query(t.Context(), QueryInput{Messages: []llm.Message{llm.UserText("continue")}}, deps) {
				if event.Terminal != nil {
					terminal = event.Terminal
				}
			}
			if terminal == nil {
				t.Fatal("no terminal outcome")
			}
			if committed {
				if prepared != 1 || completed != 0 || terminal.Reason != ReasonModelError || !errors.Is(terminal.Err, llm.ErrModelRouteChanged) {
					t.Fatalf("visible output was retried: %+v prepare=%d complete=%d", terminal, prepared, completed)
				}
			} else if prepared != 2 || completed != 1 || terminal.Reason != ReasonCompleted || terminal.Text != "ready" {
				t.Fatalf("uncommitted route did not renegotiate: %+v prepare=%d complete=%d", terminal, prepared, completed)
			}
		})
	}
}

func TestModelPreparationFailureDoesNotDispatch(t *testing.T) {
	failure := errors.New("selection unavailable")
	called := false
	deps := QueryDeps{
		BeforeModel: func(ctx context.Context, _ llm.CompletionRequest) (context.Context, bool, error) {
			return ctx, false, failure
		},
		CallModel: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
			called = true
			return func(func(llm.StreamEvent, error) bool) {}
		},
	}
	var terminal *Terminal
	for event, _ := range Query(t.Context(), QueryInput{Messages: []llm.Message{llm.UserText("continue")}}, deps) {
		if event.Terminal != nil {
			terminal = event.Terminal
		}
	}
	if called || terminal == nil || terminal.Reason != ReasonModelError || !errors.Is(terminal.Err, failure) {
		t.Fatalf("failed preparation dispatched a call: terminal=%+v called=%v", terminal, called)
	}
}

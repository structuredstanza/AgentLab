package compaction

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type summaryCallKey struct{}
type preparedSummaryProvider struct{ streams, completes int }

func (p *preparedSummaryProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.streams++
		if ctx.Value(summaryCallKey{}) != 1 {
			yield(llm.StreamEvent{}, errors.New("wrong stream selection"))
			return
		}
		yield(llm.StreamEvent{}, errors.New("transient failure"))
	}
}
func (p *preparedSummaryProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.completes++
	if ctx.Value(summaryCallKey{}) != 2 {
		return llm.Message{}, "", llm.Usage{}, errors.New("wrong completion selection")
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("<summary>Recovered evidence</summary>")}}, "end_turn", llm.Usage{}, nil
}

func TestSummaryRetriesPrepareFreshContextsAndModes(t *testing.T) {
	provider := &preparedSummaryProvider{}
	prepared := 0
	before := func(ctx context.Context, _ llm.CompletionRequest) (context.Context, bool, error) {
		if ctx.Value(summaryCallKey{}) != nil {
			return ctx, false, errors.New("a previous selection leaked into retry preparation")
		}
		prepared++
		return context.WithValue(ctx, summaryCallKey{}, prepared), prepared > 1, nil
	}
	text, err := ProviderSummarizer(provider, 1024, false, before)(t.Context(), []llm.Message{llm.UserText("preserve the evidence")})
	if err != nil || !strings.Contains(text, "Recovered evidence") || prepared != 2 || provider.streams != 1 || provider.completes != 1 {
		t.Fatalf("summary retry: %q %v prepare=%d stream=%d complete=%d", text, err, prepared, provider.streams, provider.completes)
	}
}

func TestSummaryPreparationFailureDoesNotDispatch(t *testing.T) {
	failure := errors.New("profile unavailable")
	provider := &preparedSummaryProvider{}
	before := func(ctx context.Context, _ llm.CompletionRequest) (context.Context, bool, error) {
		return ctx, false, failure
	}
	_, err := ProviderSummarizer(provider, 1024, false, before)(t.Context(), []llm.Message{llm.UserText("summarize")})
	if !errors.Is(err, failure) || provider.streams != 0 || provider.completes != 0 {
		t.Fatalf("failed summary selection called a provider: %v %+v", err, provider)
	}
}

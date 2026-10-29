package llmpool

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// TestExhaustedErrorIdentity: callers branch on the ErrExhausted sentinel with
// errors.Is, so the chain-exhaustion error must keep wrapping it on both the
// Stream and Complete paths.
func TestExhaustedErrorIdentity(t *testing.T) {
	streamChain := New([]*Member{
		member(1, "a", 10, failProv("a", 402)),
		member(2, "b", 5, failProv("b", 402)),
	}, NewRegistry(nil, nil))
	_, serr := drain(streamChain.Stream(context.Background(), llm.CompletionRequest{}))
	if !errors.Is(serr, ErrExhausted) {
		t.Fatalf("Stream: surfaced error no longer wraps ErrExhausted: %v", serr)
	}

	completeChain := New([]*Member{
		member(1, "a", 10, failProv("a", 402)),
		member(2, "b", 5, failProv("b", 402)),
	}, NewRegistry(nil, nil))
	_, _, _, cerr := completeChain.Complete(context.Background(), llm.CompletionRequest{})
	if !errors.Is(cerr, ErrExhausted) {
		t.Fatalf("Complete: surfaced error no longer wraps ErrExhausted: %v", cerr)
	}
}

package llmrec

import (
	"context"
	"testing"
)

func TestEnsureRefusalSinkAttachesAndReuses(t *testing.T) {
	ctx := EnsureRefusalSink(context.Background())
	if RefusalObserved(ctx) {
		t.Fatal("fresh sink must not be observed")
	}
	MarkRefusal(ctx)
	if !RefusalObserved(ctx) {
		t.Fatal("refusal marked on the attached sink must be observed")
	}
	if again := EnsureRefusalSink(ctx); again != ctx {
		t.Fatal("an existing sink must be reused, not replaced")
	}
}

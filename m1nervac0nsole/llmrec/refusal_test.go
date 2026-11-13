package llmrec

import (
	"context"
	"errors"
	"testing"
)

func TestRefusalSink(t *testing.T) {
	ctx := WithRefusalSink(context.Background())
	if RefusalObserved(ctx) {
		t.Fatal("fresh sink is already set")
	}
	MarkRefusal(ctx)
	if !RefusalObserved(ctx) {
		t.Fatal("sink did not retain refusal")
	}
	if RefusalObserved(context.Background()) {
		t.Fatal("missing sink reports refusal")
	}
}

func TestCallStatus(t *testing.T) {
	sunk := WithRefusalSink(context.Background())
	MarkRefusal(sunk)
	bare := WithRefusalSink(context.Background())
	boom := errors.New("boom")
	cases := []struct {
		name       string
		ctx        context.Context
		stopReason string
		err        error
		want       string
	}{
		{"plain ok", bare, "end_turn", nil, "ok"},
		{"stop reason refusal", bare, "refusal", nil, "refused"},
		{"sink-only refusal", sunk, "end_turn", nil, "refused"},
		{"error wins over refusal", sunk, "refusal", boom, "error"},
		{"error", bare, "", boom, "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := callStatus(tc.ctx, tc.stopReason, tc.err); got != tc.want {
				t.Fatalf("callStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

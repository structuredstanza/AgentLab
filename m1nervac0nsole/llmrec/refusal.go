package llmrec

import (
	"context"
	"sync/atomic"
)

// The refusal sink is the per-call signal the HTTP transport (which sniffs wire
// bodies) sets and the Recorder reads to label the call "refused". It lives here
// because agent imports llmrec, not the other way round.

type refusalSinkKey struct{}
type refusalSink struct{ observed atomic.Bool }

// WithRefusalSink attaches a fresh refusal signal to ctx for one provider call.
func WithRefusalSink(ctx context.Context) context.Context {
	return context.WithValue(ctx, refusalSinkKey{}, &refusalSink{})
}

// EnsureRefusalSink reuses a sink the caller already attached (the task router
// attaches one per attempt) and otherwise attaches a fresh one, so every recorded
// call, including global and conversation calls, can observe refusal signals.
func EnsureRefusalSink(ctx context.Context) context.Context {
	if _, ok := ctx.Value(refusalSinkKey{}).(*refusalSink); ok {
		return ctx
	}
	return WithRefusalSink(ctx)
}

// MarkRefusal records a refusal in the call's sink, when present.
func MarkRefusal(ctx context.Context) {
	if sink, ok := ctx.Value(refusalSinkKey{}).(*refusalSink); ok {
		sink.observed.Store(true)
	}
}

// RefusalObserved reports whether the call observed a refusal signal.
func RefusalObserved(ctx context.Context) bool {
	sink, ok := ctx.Value(refusalSinkKey{}).(*refusalSink)
	return ok && sink.observed.Load()
}

// callStatus labels one finished provider call. A refusal is a distinct outcome,
// not an error: it must not be counted as an accepted training row.
func callStatus(ctx context.Context, stopReason string, err error) string {
	switch {
	case err != nil:
		return "error"
	case stopReason == "refusal" || RefusalObserved(ctx):
		return "refused"
	default:
		return "ok"
	}
}

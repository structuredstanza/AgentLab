package llm

import (
	"context"
	"errors"
)

// ErrModelRouteChanged requests preparation again before any output is emitted.
var ErrModelRouteChanged = errors.New("model route changed before output")

// ErrHistoryRejected is a deterministic input error, not an account failure.
var ErrHistoryRejected = errors.New("native history authorization failed")

// RequiresComplete reports whether streaming would lose provider-owned state.
func RequiresComplete(p Provider) bool {
	capability, ok := p.(interface{ RequiresComplete() bool })
	return ok && capability.RequiresComplete()
}

// PrepareModelCall binds one provider selection to the transport chosen for it.
// The returned context is for this call, not for tools or future calls.
func PrepareModelCall(ctx context.Context, p Provider, req CompletionRequest, nonStreaming bool) (context.Context, bool, error) {
	if preparer, ok := p.(interface {
		PrepareModelCall(context.Context, CompletionRequest, bool) (context.Context, bool, error)
	}); ok {
		return preparer.PrepareModelCall(ctx, req, nonStreaming)
	}
	return ctx, nonStreaming || RequiresComplete(p), nil
}

func (rp *rateLimitedProvider) RequiresComplete() bool { return RequiresComplete(rp.p) }

func (rp *rateLimitedProvider) PrepareModelCall(ctx context.Context, req CompletionRequest, nonStreaming bool) (context.Context, bool, error) {
	return PrepareModelCall(ctx, rp.p, req, nonStreaming)
}

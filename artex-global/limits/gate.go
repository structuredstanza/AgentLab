package limits

import (
	"context"
	"sync"
	"time"
)

// RateGate is the engagement's hard request ceiling, enforced on the proxy
// rather than on any tool's flag.
//
// A per-tool rate parameter only binds the tool that declares it, and a tool
// invoked through Bash declares nothing. The proxy sees every HTTP request that
// leaves the guest, so the cap belongs here.
//
// The rule the operator stated is "never exceed 100 requests a minute", which a
// token bucket cannot honour: a bucket of capacity 100 admits 100 requests in
// the first second, and a one-second burst of 100 is a breach however it is
// averaged. This is a sliding window instead, so no sixty-second span ever
// contains more than the limit.
type RateGate struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	perHost map[string]*window
}

// window holds the admission times still inside the trailing minute.
type window struct {
	times []time.Time
	// head is the index of the oldest live entry; the slice is used as a ring so
	// a long engagement does not allocate per request.
	head int
}

// NewPerHostRateGate returns a gate allowing limit requests per window to each
// host. A per-target window means a backlog of machines does not make each box
// wait behind the others.
func NewPerHostRateGate(limit int) *RateGate {
	if limit <= 0 {
		return nil
	}
	return &RateGate{limit: limit, window: time.Minute, perHost: map[string]*window{}}
}

// NewRateGate returns a gate allowing limit requests per window across every
// host.
func NewRateGate(limit int) *RateGate {
	g := NewPerHostRateGate(limit)
	if g == nil {
		return nil
	}
	return g
}

// Allow blocks until the request fits inside the window, then admits it. It
// refuses only when the context is cancelled while waiting.
func (g *RateGate) Allow(ctx context.Context, host, path string) (bool, string) {
	if g == nil {
		return true, ""
	}
	for {
		wait, ok := g.take(host)
		if ok {
			return true, ""
		}
		select {
		case <-ctx.Done():
			return false, "request budget wait cancelled"
		case <-time.After(wait):
		}
	}
}

// take admits one request or reports how long until the oldest one expires.
func (g *RateGate) take(host string) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()

	w := g.perHost[host]
	if w == nil {
		w = &window{}
		g.perHost[host] = w
	}

	// Drop entries that have left the window.
	for w.head < len(w.times) && now.Sub(w.times[w.head]) >= g.window {
		w.head++
	}
	// Compact once the dead prefix dominates, so the slice does not grow without
	// bound across a long engagement.
	if w.head > 0 && w.head == len(w.times) {
		w.times = w.times[:0]
		w.head = 0
	}

	if len(w.times)-w.head < g.limit {
		w.times = append(w.times, now)
		return 0, true
	}
	// Full: wait for the oldest admission to age out of the window.
	oldest := w.times[w.head]
	return g.window - now.Sub(oldest), false
}

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
	// lastSweep is when idle hosts were last dropped. The sweep is driven by
	// traffic rather than a timer, so a gate with no requests does no work, and
	// a gate with traffic pays one map scan per window.
	lastSweep time.Time
}

// window holds the admission times still inside the trailing minute.
type window struct {
	// times is append-ordered, oldest first. Entries before head have aged out
	// of the window and are dropped lazily, so the live admissions are
	// times[head:]; the prefix is compacted rather than the slice reallocated.
	times []time.Time
	// head is the index of the oldest live entry.
	head int
}

// NewPerHostRateGate returns a gate allowing limit requests per window to each
// host. A per-target window means a backlog of machines does not make each box
// wait behind the others.
func NewPerHostRateGate(limit int) *RateGate {
	if limit <= 0 {
		return nil
	}
	return &RateGate{limit: limit, window: time.Minute, perHost: map[string]*window{}, lastSweep: time.Now()}
}

// Allow blocks until the request fits inside the window, then admits it. It
// refuses only when the context is cancelled while waiting.
func (g *RateGate) Allow(ctx context.Context, host, path string) (bool, string) {
	if g == nil {
		return true, ""
	}
	// Collapse the spellings a scanner produces for one host — case, trailing
	// dot, scheme, port — before the loop, so every wait reuses one key and no
	// spelling can open a second budget.
	key := normalize(host)
	for {
		wait, ok := g.take(key)
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
// key is already normalized by Allow.
func (g *RateGate) take(key string) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()

	// Sweep before touching this host: a host that is never contacted again
	// must not keep its map entry forever, and only a later request can notice
	// that it has gone idle.
	g.sweepLocked(now)

	w := g.perHost[key]
	if w == nil {
		w = &window{}
		g.perHost[key] = w
	}

	// Drop entries that have left the window.
	for w.head < len(w.times) && now.Sub(w.times[w.head]) >= g.window {
		w.head++
	}
	// Compact the consumed prefix. Resetting only when the slice is fully empty
	// bounds nothing: under sustained traffic there is always one live entry, so
	// the backing array would grow by one allocation per request. Copying the
	// live entries to the front keeps len at most limit, and the window holds at
	// most limit live entries, so the slice stays within 2*limit.
	w.compact(g.limit)

	if len(w.times)-w.head < g.limit {
		w.times = append(w.times, now)
		return 0, true
	}
	// Full: wait for the oldest admission to age out of the window.
	oldest := w.times[w.head]
	return g.window - now.Sub(oldest), false
}

// sweepLocked drops the hosts whose every admission has aged out of the
// window. Such an entry carries no live timestamps, so deleting it cannot
// loosen a limit: the host starts again with a full window either way.
//
// It runs at most once per window, opportunistically on a request, so it needs
// no goroutine per host and its cost is one map scan amortized over a window of
// traffic.
func (g *RateGate) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < g.window {
		return
	}
	g.lastSweep = now
	for host, w := range g.perHost {
		// times is append-ordered, so its last element is the newest admission:
		// once that has aged out, every entry has.
		if len(w.times) == 0 || now.Sub(w.times[len(w.times)-1]) >= g.window {
			delete(g.perHost, host)
		}
	}
}

// compact copies the live tail to the front once the consumed prefix has grown
// to a full window's worth of admissions.
func (w *window) compact(limit int) {
	if w.head == 0 {
		return
	}
	if w.head == len(w.times) {
		w.times = w.times[:0]
		w.head = 0
		return
	}
	if w.head >= limit {
		n := copy(w.times, w.times[w.head:])
		w.times = w.times[:n]
		w.head = 0
	}
}

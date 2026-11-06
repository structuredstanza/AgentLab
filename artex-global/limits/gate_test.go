package limits

import (
	"context"
	"testing"
	"time"
)

// The same host written with different case, a trailing dot, a scheme or a port
// must spend one budget, not one per spelling.
func TestRateGateSharesCanonicalHostBucket(t *testing.T) {
	const limit = 2
	g := NewPerHostRateGate(limit)
	g.window = time.Hour
	ctx := context.Background()

	for _, host := range []string{"EXAMPLE.com", "example.com."} {
		if ok, why := g.Allow(ctx, host, "/"); !ok {
			t.Fatalf("Allow(%q) refused: %s", host, why)
		}
	}

	g.mu.Lock()
	buckets := len(g.perHost)
	w := g.perHost["example.com"]
	live := 0
	if w != nil {
		live = len(w.times) - w.head
	}
	g.mu.Unlock()
	if buckets != 1 || w == nil {
		t.Fatalf("spellings produced %d buckets, want one under example.com", buckets)
	}
	if live != limit {
		t.Fatalf("canonical bucket holds %d admissions, want %d", live, limit)
	}

	// A third spelling must find the bucket already full. The context is
	// cancelled up front so the check needs no wait: take runs first, so an
	// admission here would mean a separate budget had been opened, while a
	// refusal proves the canonical bucket was consulted.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, _ := g.Allow(cancelled, "http://example.com/x", "/"); ok {
		t.Fatal("a third spelling was admitted on a separate budget; the ceiling was multiplied")
	}
}

// A host that is never contacted again must still lose its map entry: a sweep
// driven by other hosts' traffic is the only thing that can notice it. No sleep
// is needed — the idle timestamp and lastSweep are seeded, and the next take for
// another host performs the sweep.
func TestRateGateEvictsAbandonedHost(t *testing.T) {
	const limit = 2
	g := NewPerHostRateGate(limit)
	g.window = time.Minute
	now := time.Now()

	// The abandoned host's only admission has aged out, and a full window has
	// passed since the last sweep, so the next request must sweep.
	g.mu.Lock()
	g.perHost["gone.example"] = &window{times: []time.Time{now.Add(-2 * g.window)}}
	g.lastSweep = now.Add(-2 * g.window)
	g.mu.Unlock()

	if _, ok := g.take("live.example"); !ok {
		t.Fatal("request to the live host was refused")
	}

	g.mu.Lock()
	_, gonePresent := g.perHost["gone.example"]
	_, livePresent := g.perHost["live.example"]
	buckets := len(g.perHost)
	g.mu.Unlock()

	if gonePresent {
		t.Fatal("the abandoned host kept its window after a full window of idleness")
	}
	if !livePresent || buckets != 1 {
		t.Fatalf("live host state missing or extra buckets left: buckets=%d live=%v", buckets, livePresent)
	}

	// Eviction drops dead timestamps only, so the returning host starts with a
	// full budget rather than inheriting the old one.
	for i := range limit {
		if _, ok := g.take("gone.example"); !ok {
			t.Fatalf("admission %d after eviction was refused; the old budget leaked back", i)
		}
	}
}

// A sweep must never drop a window that still has live admissions, or the
// eviction mechanism itself would hand out extra budget.
func TestRateGateSweepKeepsLiveBudget(t *testing.T) {
	const limit = 2
	g := NewPerHostRateGate(limit)
	g.window = time.Minute
	now := time.Now()

	g.mu.Lock()
	g.perHost["busy.example"] = &window{times: []time.Time{now.Add(-time.Second), now.Add(-time.Second)}}
	// Force the next take to sweep without letting the admissions age out.
	g.lastSweep = now.Add(-2 * g.window)
	g.mu.Unlock()

	if _, ok := g.take("other.example"); !ok {
		t.Fatal("request to the other host was refused")
	}

	g.mu.Lock()
	_, busyPresent := g.perHost["busy.example"]
	g.mu.Unlock()
	if !busyPresent {
		t.Fatal("a sweep dropped a window with live admissions")
	}
	if _, ok := g.take("busy.example"); ok {
		t.Fatal("a sweep reset a live budget; the limit was loosened")
	}
}

// Sustained rolling traffic must not grow the per-host timestamp slice without
// bound. The consumed prefix has to be compacted while entries are still live,
// not only once the window is fully empty.
func TestRateGateBoundsRetainedTimestamps(t *testing.T) {
	const (
		limit    = 8
		windows  = 40
		expiredN = windows * limit
		liveTail = limit - 1
	)
	g := NewPerHostRateGate(limit)
	g.window = time.Minute
	now := time.Now()

	// Seed what sustained traffic leaves behind: forty windows' worth of
	// admissions have already aged out at the head, while a live tail stays
	// inside the window — so the slice never becomes fully empty and the old
	// reset-on-empty compaction could never run.
	w := &window{}
	expired := now.Add(-2 * g.window)
	for i := range expiredN {
		w.times = append(w.times, expired.Add(time.Duration(i)*time.Millisecond))
	}
	for i := range liveTail {
		w.times = append(w.times, now.Add(-time.Duration(liveTail-i)*time.Millisecond))
	}
	g.mu.Lock()
	g.perHost["sustained.example"] = w
	g.mu.Unlock()

	if _, ok := g.take("sustained.example"); !ok {
		t.Fatal("the live tail was not admitted; the seeded window is malformed")
	}

	g.mu.Lock()
	length, live, head := len(w.times), len(w.times)-w.head, w.head
	g.mu.Unlock()
	if live > limit {
		t.Fatalf("%d live timestamps retained, over the %d limit", live, limit)
	}
	if length > 2*limit {
		t.Fatalf("%d timestamps retained (head %d), want at most %d: the consumed prefix was not compacted", length, head, 2*limit)
	}
}

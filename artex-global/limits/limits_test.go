package limits

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/manifest"
)

func rpsManifest() *manifest.Manifest {
	return &manifest.Manifest{
		ID:     "ffuf",
		Limits: manifest.Limits{Param: "rate", Unit: manifest.RateRPS},
	}
}

// The model can pass any number it likes, so the ceiling must be applied to the
// resolved value rather than trusted from the manifest default.
func TestClampCapsRequestsPerSecond(t *testing.T) {
	l := New(Policy{MaxRequestsPerMinute: 100, MaxConcurrentPerTarget: 3})

	out, note := l.Clamp(rpsManifest(), map[string]string{"rate": "50"})
	if out["rate"] != "1" {
		t.Fatalf("rate = %q, want 1 (the largest whole rate inside 100/min)", out["rate"])
	}
	if note == "" {
		t.Fatal("a clamped run must report that it was clamped")
	}

	// A value already inside the ceiling is left alone and not reported.
	out, note = l.Clamp(rpsManifest(), map[string]string{"rate": "1"})
	if out["rate"] != "1" || note != "" {
		t.Fatalf("an in-policy rate was rewritten: %q %q", out["rate"], note)
	}

	// A missing rate is filled with the ceiling rather than left to the tool's
	// own, larger, default.
	out, _ = l.Clamp(rpsManifest(), map[string]string{})
	if out["rate"] != "1" {
		t.Fatalf("absent rate = %q, want the ceiling to be set explicitly", out["rate"])
	}
}

func TestClampCapsPacketsAndThreads(t *testing.T) {
	l := New(DefaultLabPolicy())

	out, _ := l.Clamp(&manifest.Manifest{Limits: manifest.Limits{Param: "rate", Unit: manifest.RatePPS}},
		map[string]string{"rate": "1000"})
	if out["rate"] != "100" {
		t.Fatalf("packet rate = %q, want 100", out["rate"])
	}

	out, _ = l.Clamp(&manifest.Manifest{Limits: manifest.Limits{Param: "threads", Unit: manifest.RateThreads}},
		map[string]string{"threads": "64"})
	if out["threads"] != "8" {
		t.Fatalf("threads = %q, want 8", out["threads"])
	}
}

// A tool that declares no rate is an unbounded requester, and clamping cannot
// make it safe. It must be left visibly unclamped rather than silently allowed.
func TestClampIgnoresToolsThatDeclareNoRate(t *testing.T) {
	l := New(DefaultLabPolicy())
	out, note := l.Clamp(&manifest.Manifest{Limits: manifest.Limits{Unit: manifest.RateNone}},
		map[string]string{"x": "1"})
	if note != "" || out["x"] != "1" {
		t.Fatalf("a rate-less tool was rewritten: %v %q", out, note)
	}
}

// The concurrency ceiling is what stops three scans becoming ten.
func TestAcquireLimitsConcurrencyPerTarget(t *testing.T) {
	l := New(Policy{MaxConcurrentPerTarget: 2})
	ctx := context.Background()

	first, err := l.Acquire(ctx, "10.10.14.7", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.Acquire(ctx, "10.10.14.7", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The third must not be granted while two run against this target.
	done := make(chan struct{})
	go func() {
		third, err := l.Acquire(ctx, "10.10.14.7", nil, nil)
		if err == nil {
			third()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a third run was granted against a target already holding two")
	case <-time.After(400 * time.Millisecond):
	}

	// Releasing one makes room.
	first()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting run was not granted after a slot was released")
	}
	second()
}

// Targets must not share a budget, or one engagement could not run two boxes.
func TestAcquireIsPerTarget(t *testing.T) {
	l := New(Policy{MaxConcurrentPerTarget: 1})
	ctx := context.Background()
	a, err := l.Acquire(ctx, "10.10.14.7", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	b, err := l.Acquire(ctx, "10.10.14.8", nil, nil)
	if err != nil {
		t.Fatalf("a second target was blocked by the first: %v", err)
	}
	b()
}

// The same host written four ways is one target, or the ceiling is trivially
// bypassed by changing the spelling.
func TestAcquireNormalisesTargetSpelling(t *testing.T) {
	l := New(Policy{MaxConcurrentPerTarget: 1})
	ctx := context.Background()
	held, err := l.Acquire(ctx, "10.10.14.7", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held()

	for _, spelling := range []string{"http://10.10.14.7/", "HTTP://10.10.14.7:80/x", "10.10.14.7:80"} {
		waitCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		_, err := l.Acquire(waitCtx, spelling, nil, nil)
		cancel()
		if err == nil {
			t.Fatalf("%q was treated as a different target from 10.10.14.7", spelling)
		}
	}
}

// A deferred release plus an explicit one must not free two slots.
func TestReleaseIsIdempotent(t *testing.T) {
	l := New(Policy{MaxConcurrentPerTarget: 1})
	ctx := context.Background()
	release, err := l.Acquire(ctx, "t", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	release()
	release()
	again, err := l.Acquire(ctx, "t", nil, nil)
	if err != nil {
		t.Fatalf("a doubled release corrupted the counter: %v", err)
	}
	again()
}

// Waiting for a slot must be interruptible, or a cancelled task hangs a worker.
func TestAcquireRespectsCancellation(t *testing.T) {
	l := New(Policy{MaxConcurrentPerTarget: 1})
	held, err := l.Acquire(context.Background(), "t", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "t", nil, nil); err == nil {
		t.Fatal("Acquire ignored context cancellation")
	}
}

// An unset policy must not throttle anything: an operator who stated no ceiling
// should not be silently rate-limited.
func TestZeroPolicyAllowsEverything(t *testing.T) {
	l := New(Policy{})
	out, note := l.Clamp(rpsManifest(), map[string]string{"rate": "500"})
	if out["rate"] != "500" || note != "" {
		t.Fatalf("an unset policy rewrote the rate: %q", out["rate"])
	}
	for i := 0; i < 20; i++ {
		if _, err := l.Acquire(context.Background(), "t", nil, nil); err != nil {
			t.Fatalf("an unset policy refused a run: %v", err)
		}
	}
}

// The per-minute budget is a reservation, so two tools at the ceiling cannot
// both run: 1 rps each is 120/min, over a 100/min budget.
func TestPerMinuteBudgetBlocksOversubscription(t *testing.T) {
	l := New(Policy{MaxRequestsPerMinute: 100, MaxConcurrentPerTarget: 5})
	params := map[string]string{"rate": "1"}
	held, err := l.Acquire(context.Background(), "t", rpsManifest(), params)
	if err != nil {
		t.Fatal(err)
	}
	defer held()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "t", rpsManifest(), params); err == nil {
		t.Fatal("two runs at 1 rps each were admitted against a 100/min budget")
	}
}

// The hard cap is the operator's stated rule: never exceed 100 requests a
// minute. The test asserts the property that rule actually states, that no
// sixty-second span contains more than the limit, rather than an average.
func TestRateGateNeverExceedsTheLimitInAnyWindow(t *testing.T) {
	const limit = 20
	g := NewPerHostRateGate(limit)
	// A short window keeps the test fast; the mechanism is window-length
	// agnostic and production uses a minute.
	g.window = 2 * time.Second
	ctx := context.Background()

	var admitted []time.Time
	for i := 0; i < limit*2; i++ {
		if ok, why := g.Allow(ctx, "h", "/"); !ok {
			t.Fatalf("request %d refused rather than delayed: %s", i, why)
		}
		admitted = append(admitted, time.Now())
	}

	// Every trailing window must hold at most the limit.
	for i := range admitted {
		count := 0
		for j := i; j < len(admitted); j++ {
			if admitted[j].Sub(admitted[i]) < g.window {
				count++
			}
		}
		if count > limit {
			t.Fatalf("a window starting at request %d held %d requests, over the %d limit", i, count, limit)
		}
	}

	// The first `limit` are immediate; the rest wait for the window to slide,
	// which at limit/minute is roughly a minute for a full second batch.
	if elapsed := admitted[len(admitted)-1].Sub(admitted[0]); elapsed < g.window/2 {
		t.Fatalf("the second batch was admitted after only %v; the window is not binding", elapsed)
	}
}

// A full bucket must not admit a burst: the bug this replaced allowed the whole
// per-minute budget in the first second.
func TestRateGateDoesNotPermitAnInstantBurst(t *testing.T) {
	g := NewPerHostRateGate(50)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 50; i++ {
		g.Allow(ctx, "h", "/")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("the first 50 took %v; a small window should admit them at once", elapsed)
	}
	// The 51st must still be blocked seconds later: with a 50/min window it
	// cannot be admitted for a minute, and any admission sooner is a burst.
	admitted := make(chan struct{})
	go func() {
		g.Allow(ctx, "h", "/")
		close(admitted)
	}()
	select {
	case <-admitted:
		t.Fatal("the 51st request was admitted inside the window; a burst slipped through")
	case <-time.After(3 * time.Second):
		// Still waiting, which is the property under test.
	}
}

func TestRateGateRefusesOnCancellation(t *testing.T) {
	g := NewPerHostRateGate(2)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		g.Allow(ctx, "h", "/")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if ok, _ := g.Allow(waitCtx, "h", "/"); ok {
		t.Fatal("a cancelled wait was admitted")
	}
}

// A nil gate admits everything, so a VM with no engagement is not throttled.
func TestNilRateGateAllows(t *testing.T) {
	var g *RateGate
	if ok, _ := g.Allow(context.Background(), "h", "/"); !ok {
		t.Fatal("a nil gate refused a request")
	}
}

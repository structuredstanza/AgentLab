package limits

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGuidanceForProfiles(t *testing.T) {
	seen := map[string]bool{}
	for _, profile := range []string{"stealth", "careful", "standard", "unbound"} {
		g := GuidanceFor(profile)
		if seen[g] || !strings.Contains(g, "Operator instructions") || !strings.Contains(g, "not enforced limits") {
			t.Fatalf("profile %s has duplicate or misleading guidance: %s", profile, g)
		}
		seen[g] = true
	}
	for _, profile := range []string{"", "unknown"} {
		if GuidanceFor(profile) != GuidanceFor("standard") {
			t.Errorf("%q does not default to standard", profile)
		}
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
	for i := 0; i < 20; i++ {
		if _, err := l.Acquire(context.Background(), "t", nil, nil); err != nil {
			t.Fatalf("an unset policy refused a run: %v", err)
		}
	}
}

// A global cap is what stops a backlog of machines multiplying the load: three
// scans per target across ten targets is thirty scans, which is not what an
// operator asking for "three at a time" meant.
func TestGlobalScanLimitSpansTargets(t *testing.T) {
	l := New(Policy{MaxConcurrentTotal: 2, MaxConcurrentPerTarget: 5})
	ctx := context.Background()

	first, err := l.Acquire(ctx, "10.10.14.7", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.Acquire(ctx, "10.10.14.8", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A third scan, against a third target, must still wait: the cap is global.
	done := make(chan struct{})
	go func() {
		third, err := l.Acquire(ctx, "10.10.14.9", nil, nil)
		if err == nil {
			third()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a third scan started on a different target despite a global cap of 2")
	case <-time.After(400 * time.Millisecond):
	}

	first()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting scan was not admitted after a slot freed")
	}
	second()
}

// The per-target cap must still hold inside a larger global budget.
func TestPerTargetCapHoldsUnderGlobalBudget(t *testing.T) {
	l := New(Policy{MaxConcurrentTotal: 10, MaxConcurrentPerTarget: 1})
	ctx := context.Background()
	held, err := l.Acquire(ctx, "h", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held()

	waitCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(waitCtx, "h", nil, nil); err == nil {
		t.Fatal("a second scan on the same target was admitted despite a per-target cap of 1")
	}
}

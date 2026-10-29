package server

import (
	"testing"
	"time"
)

func TestUsageCacheFreshnessBackoffAndLastGood(t *testing.T) {
	c := newUsageCache()
	start := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	if _, fresh, backoff, good := c.get(2, start); fresh || backoff || good {
		t.Fatalf("empty cache must report nothing: fresh=%v backoff=%v good=%v", fresh, backoff, good)
	}

	c.set(2, nil, nil, nil, start)
	if _, fresh, _, good := c.get(2, start.Add(usageCacheTTL-time.Second)); !fresh || !good {
		t.Fatal("entry inside the TTL must be fresh")
	}
	if _, fresh, _, good := c.get(2, start.Add(usageCacheTTL)); fresh || !good {
		t.Fatal("entry at the TTL must be stale but still the last good value")
	}

	// A 429 suppresses the fresh hit (callers must not refetch) yet keeps the last good value for stale display.
	c.setRateLimited(2, start.Add(10*time.Second))
	if _, fresh, backoff, good := c.get(2, start.Add(20*time.Second)); fresh || !backoff || !good {
		t.Fatalf("rate-limited profile: fresh=%v backoff=%v good=%v", fresh, backoff, good)
	}
	if _, _, backoff, _ := c.get(2, start.Add(10*time.Second+usageRateLimitTTL)); backoff {
		t.Fatal("backoff must end after the rate-limit window")
	}

	// A successful fetch clears the backoff, and profiles are independent.
	c.setRateLimited(2, start)
	c.set(2, nil, nil, nil, start.Add(time.Second))
	if _, _, backoff, _ := c.get(2, start.Add(2*time.Second)); backoff {
		t.Fatal("a successful fetch must clear the backoff")
	}
	if _, _, backoff, good := c.get(3, start); backoff || good {
		t.Fatal("other profiles must be unaffected")
	}
}

package server

import (
	"sync"
	"time"

	"github.com/Autumn-27/artex/sdkbridge"
)

const (
	usageCacheTTL     = 120 * time.Second
	usageRateLimitTTL = 5 * time.Minute
)

type cachedUsage struct {
	plan      *string
	fetchedAt *time.Time
	windows   []sdkbridge.UsageWindow
	cachedAt  time.Time
}

type profileRateLimit struct {
	until time.Time
}

type usageCache struct {
	mu         sync.RWMutex
	entries    map[int64]cachedUsage
	rateLimits map[int64]profileRateLimit
}

func newUsageCache() *usageCache {
	return &usageCache{
		entries:    make(map[int64]cachedUsage),
		rateLimits: make(map[int64]profileRateLimit),
	}
}

// get returns cached usage and status:
// hitFresh is true if entry exists, < 120s old, and not rate limited.
// inBackoff is true if the profile is currently within the 5m 429 backoff window.
// hasLastGood is true if a valid prior response was ever cached.
func (c *usageCache) get(profileID int64, now time.Time) (entry cachedUsage, hitFresh bool, inBackoff bool, hasLastGood bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rl, ok := c.rateLimits[profileID]
	if ok && now.Before(rl.until) {
		inBackoff = true
	}

	e, has := c.entries[profileID]
	if has {
		hasLastGood = true
		entry = e
		if !inBackoff && now.Sub(e.cachedAt) < usageCacheTTL {
			hitFresh = true
		}
	}
	return
}

func (c *usageCache) set(profileID int64, plan *string, fetchedAt *time.Time, windows []sdkbridge.UsageWindow, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.rateLimits, profileID)
	c.entries[profileID] = cachedUsage{
		plan:      plan,
		fetchedAt: fetchedAt,
		windows:   windows,
		cachedAt:  now,
	}
}

func (c *usageCache) setRateLimited(profileID int64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rateLimits[profileID] = profileRateLimit{
		until: now.Add(usageRateLimitTTL),
	}
}

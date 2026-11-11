package egress

import (
	"sync"
	"time"
)

// HeaderEgress names the proxy as the origin of a failure. A response carrying
// it did not come from the target: the proxy could not dial the target or read
// its reply. Consumers must treat such a response as a failed probe rather than
// as the site's answer, which is why the header is part of the proxy's contract
// and not a debug aid.
const HeaderEgress = "X-Artex-Egress"

// Values of HeaderEgress.
const (
	// egressDialFailed means no TCP connection to the target was established.
	egressDialFailed = "dial-failed"
	// egressReadFailed means the target was dialled but no response head came
	// back.
	egressReadFailed = "read-failed"
)

const (
	// connectProbeTimeout bounds the TCP probe issued before a CONNECT is
	// answered. A reachable host completes the handshake in one round trip, so
	// this only has to cover a slow path; a host that cannot make it in this
	// window is reported down instead of letting the tool wait out its own
	// timeout against a dead target.
	connectProbeTimeout = 3 * time.Second

	// connectProbeTTL is how long a probe outcome is reused. A worker retries
	// the same host within seconds, so a retry storm costs one dial; two
	// minutes still lets a host that comes back be seen by the next planning
	// round, and bounds how stale a cached success can be (a host that dies
	// inside the window still gets a labelled 502 from the request's own dial).
	connectProbeTTL = 2 * time.Minute

	// connectProbeLimit bounds the cache. A scan touches tens of thousands of
	// hosts, so the map must not grow with every one of them; the bound matches
	// the minted-leaf cache in ca.go.
	connectProbeLimit = 4096
)

// reachEntry is one cached probe outcome and the moment it stops being reused.
type reachEntry struct {
	ok      bool
	expires time.Time
}

// reachCache remembers whether an authority accepted a TCP connection, so a
// retry loop against a dead host costs one dial instead of one per request.
// The bound and the insertion-order eviction follow the leaf cache in ca.go.
type reachCache struct {
	mu    sync.Mutex
	m     map[string]reachEntry
	fifo  []string // insertion order, for bounded FIFO eviction
	limit int
}

func newReachCache(limit int) *reachCache {
	return &reachCache{m: map[string]reachEntry{}, limit: limit}
}

// lookup returns a cached outcome. A miss and an expired entry are the same
// answer: dial again.
func (c *reachCache) lookup(host string) (ok, cached bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.m[host]
	if !found || time.Now().After(e.expires) {
		return false, false
	}
	return e.ok, true
}

// put records an outcome, evicting the oldest entry at the bound.
func (c *reachCache) put(host string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, found := c.m[host]; !found {
		if len(c.m) >= c.limit {
			for len(c.fifo) > 0 {
				oldest := c.fifo[0]
				c.fifo = c.fifo[1:]
				if _, live := c.m[oldest]; live {
					delete(c.m, oldest)
					break
				}
			}
		}
		c.fifo = append(c.fifo, host)
	}
	c.m[host] = reachEntry{ok: ok, expires: time.Now().Add(connectProbeTTL)}
}

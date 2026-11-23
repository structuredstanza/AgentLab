// Package limits bounds concurrent tool runs while leaving speed to operator guidance.
package limits

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
)

// Policy is one engagement's ceiling. The zero value enforces nothing, which is
// deliberate: an operator who has not stated a policy should not be silently
// throttled.
type Policy struct {
	// MaxConcurrentPerTarget bounds scans against one host.
	MaxConcurrentPerTarget int
	// MaxConcurrentTotal bounds scans across the whole engagement, so a backlog
	// of machines cannot multiply the load a single target would see.
	MaxConcurrentTotal int
}

// DefaultLabPolicy bounds resource use without limiting tool rates or threads.
func DefaultLabPolicy() Policy {
	return Policy{
		MaxConcurrentPerTarget: 16,
		MaxConcurrentTotal:     16,
	}
}

// Enabled reports whether this policy constrains anything.
func (p Policy) Enabled() bool {
	return p.MaxConcurrentPerTarget > 0 || p.MaxConcurrentTotal > 0
}

// Limiter enforces a Policy. One per server; safe for concurrent use.
type Limiter struct {
	policy Policy

	mu      sync.Mutex
	targets map[string]*targetState
	// total counts every run in flight across all targets.
	total int
}

type targetState struct {
	inflight int
}

// New returns a Limiter for the policy.
func New(p Policy) *Limiter {
	return &Limiter{policy: p, targets: map[string]*targetState{}}
}

// GuidanceFor carries the operator's intent without silently enforcing tool rates.
func GuidanceFor(profile string) string {
	const prefix = "Operator instructions (guidance, not enforced limits): "
	switch profile {
	case "stealth":
		return prefix + "Stealth: passive first; about 5 req/s, short targeted wordlists, nmap -sT -T2 on top ports; no brute force."
	case "careful":
		return prefix + "Careful: about 25 req/s, focused wordlists, nmap -T3 on the top 1000 ports then targeted scans; brute force only on explicit operator intent."
	case "unbound":
		return prefix + "Unbound: maximum speed, full port ranges, large wordlists, parallel scans."
	default:
		return prefix + "Standard: tool defaults, nmap -T4 full port sweep, normal wordlists."
	}
}

// Acquire blocks until the target has room for one more run, and returns the
// function that releases it. The release is idempotent, so a deferred call plus
// an explicit one cannot double-count.
func (l *Limiter) Acquire(ctx context.Context, target string, m *manifest.Manifest, params map[string]string) (func(), error) {
	if !l.policy.Enabled() {
		return func() {}, nil
	}
	key := normalize(target)

	// Poll rather than wake waiters: runs are minutes long and a scan starts at
	// most a few times a minute, so a short interval costs nothing and avoids a
	// condition-variable dance over a map that is rarely contended.
	for {
		l.mu.Lock()
		st := l.targets[key]
		if st == nil {
			st = &targetState{}
			l.targets[key] = st
		}
		fits := true
		if l.policy.MaxConcurrentPerTarget > 0 && st.inflight >= l.policy.MaxConcurrentPerTarget {
			fits = false
		}
		if l.policy.MaxConcurrentTotal > 0 && l.total >= l.policy.MaxConcurrentTotal {
			fits = false
		}
		if fits {
			st.inflight++
			l.total++
			l.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					defer l.mu.Unlock()
					st.inflight--
					l.total--
					if st.inflight <= 0 {
						// Drop an idle target so the map does not grow with every
						// host the engagement ever touched.
						delete(l.targets, key)
					}
				})
			}, nil
		}
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for a free slot against %s: %w", key, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// normalize keys a target so the same host is counted once whatever form the
// caller used.
//
// The three spellings a scanner can produce for one host — `EXAMPLE.com`,
// `example.com.`, `example.com` — must collapse to one key, or each gets its
// own concurrency budget. A bare IPv6 literal has several colons, so only a
// single-colon host:port pair has its port stripped; a bracketed literal keeps
// its address without the brackets.
func normalize(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if strings.HasPrefix(t, "[") {
		// [::1] / [::1]:8080 → ::1
		if end := strings.Index(t, "]"); end > 0 {
			return strings.TrimSuffix(t[1:end], ".")
		}
		return strings.Trim(t, "[]")
	}
	// One colon is a host:port pair; more is an IPv6 address.
	if strings.Count(t, ":") == 1 {
		if i := strings.LastIndex(t, ":"); i > 0 {
			if _, err := strconv.Atoi(t[i+1:]); err == nil {
				t = t[:i]
			}
		}
	}
	return strings.TrimSuffix(t, ".")
}

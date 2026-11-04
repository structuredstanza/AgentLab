// Package limits enforces an engagement's throughput ceiling.
//
// The ceiling exists because a scanning tool's own defaults are wrong for a
// shared lab: ffuf ships at 50 requests a second and masscan at 1000 packets a
// second, both of which read as abuse against a platform that forbids denial of
// service. Declaring a safer default is not enough, because a parameter is
// operator-settable and a model can pass any number it likes. So the policy is
// applied to the resolved value on the way in, and the model cannot exceed it.
//
// Two ceilings are enforced together, per target:
//
//   - at most MaxConcurrentPerTarget runs in flight, whatever their kind;
//   - the sum of the request rates those runs reserved stays within
//     MaxRequestsPerMinute.
//
// The second is a reservation rather than a measurement. A tool does not report
// its requests back, so the limiter charges each run the rate it declared for
// the whole time it runs. That is conservative: a run that finishes early has
// over-reserved. Being conservative is the correct direction for a rule whose
// purpose is to avoid looking like an attack.
package limits

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/manifest"
)

// Policy is one engagement's ceiling. The zero value enforces nothing, which is
// deliberate: an operator who has not stated a policy should not be silently
// throttled.
type Policy struct {
	MaxRequestsPerMinute   int
	MaxConcurrentPerTarget int
	MaxPacketsPerSecond    int
	MaxThreads             int
}

// DefaultLabPolicy is the ceiling for a shared, multi-tenant lab: 100 HTTP
// requests a minute, three scans at once against one target, and rates low
// enough that a port scan cannot be mistaken for a flood.
func DefaultLabPolicy() Policy {
	return Policy{
		MaxRequestsPerMinute:   100,
		MaxConcurrentPerTarget: 3,
		MaxPacketsPerSecond:    100,
		MaxThreads:             8,
	}
}

// Enabled reports whether this policy constrains anything.
func (p Policy) Enabled() bool { return p.MaxConcurrentPerTarget > 0 || p.MaxRequestsPerMinute > 0 }

// Limiter enforces a Policy. One per server; safe for concurrent use.
type Limiter struct {
	policy Policy

	mu      sync.Mutex
	targets map[string]*targetState
}

type targetState struct {
	inflight int
	// reservedPerMin is the request rate the running tools declared, held for
	// as long as they run.
	reservedPerMin int
}

// New returns a Limiter for the policy.
func New(p Policy) *Limiter {
	return &Limiter{policy: p, targets: map[string]*targetState{}}
}

// Policy returns the ceiling this limiter enforces, for reporting.
func (l *Limiter) Policy() Policy { return l.policy }

// Clamp rewrites the throughput parameter to the policy's ceiling.
//
// It returns the effective parameters and a note describing any change, so the
// run result can say the rate was lowered rather than pretending the request
// was honoured.
func (l *Limiter) Clamp(m *manifest.Manifest, params map[string]string) (map[string]string, string) {
	if !l.policy.Enabled() || m == nil || m.Limits.Unit == manifest.RateNone {
		return params, ""
	}
	out := make(map[string]string, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	ceiling, why := l.ceiling(m.Limits.Unit)
	if ceiling <= 0 || m.Limits.Param == "" {
		return out, ""
	}
	current := 0
	if raw, ok := out[m.Limits.Param]; ok {
		// A value the tool would reject anyway is left alone: clamping it would
		// hide the operator's mistake behind a working run.
		parsed, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return out, ""
		}
		current = parsed
	}
	if current > 0 && current <= ceiling {
		return out, ""
	}
	out[m.Limits.Param] = strconv.Itoa(ceiling)
	note := fmt.Sprintf("%s clamped from %d to %d (%s)", m.Limits.Param, current, ceiling, why)
	return out, note
}

// ceiling is the largest value the policy allows for this unit.
func (l *Limiter) ceiling(unit manifest.RateUnit) (int, string) {
	switch unit {
	case manifest.RateRPS:
		// Tools take whole requests per second, so the honest ceiling is the
		// largest integer rate whose per-minute cost stays within budget. At 100
		// a minute that is 1, which is 60 a minute: the cap is never reachable
		// exactly, and erring low is the point.
		perSecond := l.policy.MaxRequestsPerMinute / 60
		if perSecond < 1 {
			perSecond = 1
		}
		return perSecond, fmt.Sprintf("%d/min budget", l.policy.MaxRequestsPerMinute)
	case manifest.RatePPS:
		return l.policy.MaxPacketsPerSecond, "packets per second ceiling"
	case manifest.RateThreads:
		return l.policy.MaxThreads, "worker ceiling"
	}
	return 0, ""
}

// reservePerMin is the request budget a run of this manifest costs while it runs.
func (l *Limiter) reservePerMin(m *manifest.Manifest, params map[string]string) int {
	if m == nil || m.Limits.Unit != manifest.RateRPS {
		return 0
	}
	rate, err := strconv.Atoi(strings.TrimSpace(params[m.Limits.Param]))
	if err != nil || rate <= 0 {
		return 0
	}
	return rate * 60
}

// Acquire blocks until the target has room for one more run, and returns the
// function that releases it. The release is idempotent, so a deferred call plus
// an explicit one cannot double-count.
func (l *Limiter) Acquire(ctx context.Context, target string, m *manifest.Manifest, params map[string]string) (func(), error) {
	if !l.policy.Enabled() {
		return func() {}, nil
	}
	key := normalize(target)
	reserve := l.reservePerMin(m, params)

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
		if l.policy.MaxRequestsPerMinute > 0 && reserve > 0 &&
			st.reservedPerMin+reserve > l.policy.MaxRequestsPerMinute {
			fits = false
		}
		if fits {
			st.inflight++
			st.reservedPerMin += reserve
			l.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					defer l.mu.Unlock()
					st.inflight--
					st.reservedPerMin -= reserve
					if st.inflight <= 0 && st.reservedPerMin <= 0 {
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
func normalize(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, ":"); i > 0 && !strings.Contains(t[i+1:], "]") {
		t = t[:i]
	}
	return strings.Trim(t, "[]")
}

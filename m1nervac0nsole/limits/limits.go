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
	"math"
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
	MaxRequestsPerMinute int
	// MaxConcurrentPerTarget bounds scans against one host.
	MaxConcurrentPerTarget int
	// MaxConcurrentTotal bounds scans across the whole engagement, so a backlog
	// of machines cannot multiply the load a single target would see.
	MaxConcurrentTotal int
}

// DefaultLabPolicy is the ceiling for a shared, multi-tenant lab: 100 HTTP
// requests a minute, three scans at once against one target and three across
// the engagement.
//
// The request ceiling is the hard rule and is enforced on the proxy, because a
// tool run through Bash declares nothing. The per-tool values below are only
// defaults: an operator may raise them, and the guidance in the tool description
// asks for a sensible choice rather than pinning one.
func DefaultLabPolicy() Policy {
	return Policy{
		MaxRequestsPerMinute:   100,
		MaxConcurrentPerTarget: 3,
		MaxConcurrentTotal:     3,
	}
}

// Enabled reports whether this policy constrains anything.
func (p Policy) Enabled() bool {
	return p.MaxConcurrentPerTarget > 0 || p.MaxConcurrentTotal > 0 || p.MaxRequestsPerMinute > 0
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
	// reservedPerMin is the request rate the running tools declared, held for
	// as long as they run.
	reservedPerMin int
}

// New returns a Limiter for the policy.
func New(p Policy) *Limiter {
	return &Limiter{policy: p, targets: map[string]*targetState{}}
}

// Guidance is the text a tool description carries, so the agent chooses a
// sensible rate instead of being pinned to one.
//
// The ceiling is enforced on the proxy regardless; this is about the agent
// picking a rate that finishes in reasonable time rather than one that would be
// throttled for hours.
func (l *Limiter) Guidance() string {
	if !l.policy.Enabled() {
		return ""
	}
	return fmt.Sprintf(
		"Choose rates a person running this by hand would choose: "+
			"under %d requests a minute against one target, at most %d scans at once "+
			"in total and %d against the same host. Prefer a targeted run "+
			"(a template subset, a short wordlist) over a full pass, and say why you picked the rate.",
		l.policy.MaxRequestsPerMinute, l.policy.MaxConcurrentTotal, l.policy.MaxConcurrentPerTarget)
}

// reservePerMin is the request budget a run of this manifest costs while it runs.
//
// The rate is parsed as a float: tools accept fractional rates (ffuf -rate 1.5)
// and an integer parse would fail on them, returning 0 and silently disabling
// the ceiling for exactly the runs that declared one.
func (l *Limiter) reservePerMin(m *manifest.Manifest, params map[string]string) int {
	if m == nil || m.Limits.Unit != manifest.RateRPS {
		return 0
	}
	raw := strings.TrimSpace(params[m.Limits.Param])
	if raw == "" {
		return 0
	}
	rate, err := strconv.ParseFloat(raw, 64)
	if err != nil || rate <= 0 {
		return 0
	}
	perMin := int(math.Ceil(rate * 60))
	if perMin <= 0 {
		return 0
	}
	return perMin
}

// ClampThreads caps a manifest's declared thread count at the per-target
// concurrency ceiling, in place, and reports the value it replaced.
//
// Threads are not concurrency units. A 50-thread scan under a cap of three is
// one run holding 50 workers, so counting threads as slots would make the run
// wait for 47 slots that cannot exist, and not counting them lets one scan
// exceed the operator's per-target ceiling by 47. Clamping the parameter makes
// the run honour the intent instead: at most three workers against one host.
func (l *Limiter) ClampThreads(m *manifest.Manifest, params map[string]string) (from, to int, clamped bool) {
	if m == nil || m.Limits.Unit != manifest.RateThreads || params == nil {
		return 0, 0, false
	}
	limit := l.policy.MaxConcurrentPerTarget
	if limit <= 0 {
		return 0, 0, false
	}
	declared, err := strconv.Atoi(strings.TrimSpace(params[m.Limits.Param]))
	if err != nil || declared <= limit {
		return 0, 0, false
	}
	params[m.Limits.Param] = strconv.Itoa(limit)
	return declared, limit, true
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
	// A declared rate above the ceiling is not a reason to refuse the scan
	// forever. Clamp the reservation to the ceiling so the run is admitted at
	// the operator's hard cap instead of waiting for a slot that cannot exist:
	// the shipped tool defaults (ffuf 50 rps, nuclei 150 rps) are 3000-9000
	// requests a minute against a 100 ceiling, and without this clamp Acquire
	// would poll until the agent run was cancelled.
	if max := l.policy.MaxRequestsPerMinute; max > 0 && reserve > max {
		reserve = max
	}

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
		if l.policy.MaxRequestsPerMinute > 0 && reserve > 0 &&
			st.reservedPerMin+reserve > l.policy.MaxRequestsPerMinute {
			fits = false
		}
		if fits {
			st.inflight++
			st.reservedPerMin += reserve
			l.total++
			l.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					defer l.mu.Unlock()
					st.inflight--
					st.reservedPerMin -= reserve
					l.total--
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
//
// The three spellings a scanner can produce for one host — `EXAMPLE.com`,
// `example.com.`, `example.com` — must collapse to one key, or each gets its
// own request budget. A bare IPv6 literal has several colons, so only a
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

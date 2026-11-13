// Package plan validates operator-drafted engagement plans before anything is
// written to the graph.
//
// A drafting assistant proposes goals, seed intents, hints and scope rules; the
// operator reviews the proposal and applies it in one transaction. Nothing here
// writes: Validate is a pure function so the model can be handed every error at
// once and retry, and the apply path can trust the stored proposal.
//
// The proposal maps one-to-one onto the node payloads the planner and workers
// already write (see agent/tools.go): a goal carries `text`, an intent carries
// `summary` + `asset_ids`, a hint carries `text`. Keeping the same keys means
// the apply step is a translation, not a second vocabulary.
//
// Scope: an exclusion only narrows the engagement and is applied directly. An
// inclusion widens it, so the apply endpoint requires an explicit allow-include
// flag; the validator accepts both and leaves that decision to the caller.
package plan

import (
	"fmt"
	"strings"
)

// Proposal is one drafted plan.
type Proposal struct {
	Summary string   `json:"summary"`
	Goals   []Goal   `json:"goals"`
	Intents []Intent `json:"intents"`
	Hints   []Hint   `json:"hints"`
	Scope   []Scope  `json:"scope"`
}

// Goal is a verifiable end state.
type Goal struct {
	Ref       string `json:"ref"`
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// Intent is a seed exploration direction. DependsOn names other intents of the
// same proposal, so the operator can see the order the model intends.
type Intent struct {
	Ref       string   `json:"ref"`
	Summary   string   `json:"summary"`
	Goal      string   `json:"goal"`
	AssetIDs  []int64  `json:"asset_ids,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
}

// Hint is a standing instruction. Rule marks a constraint the planner must not
// contradict rather than a suggestion.
type Hint struct {
	Text     string  `json:"text"`
	AssetIDs []int64 `json:"asset_ids,omitempty"`
	Rule     bool    `json:"rule,omitempty"`
}

// Scope is one boundary rule. Kind and Value match task_scope.
type Scope struct {
	Effect string `json:"effect"`
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Note   string `json:"note,omitempty"`
}

// Limits bounds what one draft may create, so a model cannot flood a task.
type Limits struct {
	Goals   int
	Intents int
	Hints   int
	Scope   int
}

// DefaultLimits is what the drafting tool advertises and enforces.
var DefaultLimits = Limits{Goals: 8, Intents: 24, Hints: 16, Scope: 32}

// Context is what the validator may assume about the task.
type Context struct {
	Limits   Limits
	AssetIDs map[int64]bool // nil: do not check that asset ids exist
}

const (
	maxText    = 2000
	maxRef     = 64
	scopeKinds = "company root_domain subdomain ip cidr icp keyword"
)

// Validate returns every problem it finds, in a stable order, so the drafting
// model can correct them in one retry.
func Validate(p Proposal, ctx Context) []error {
	limits := ctx.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits
	}
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if strings.TrimSpace(p.Summary) == "" {
		add("summary is empty: say in one sentence what this plan does")
	} else if len(p.Summary) > maxText {
		add("summary is %d characters, the limit is %d", len(p.Summary), maxText)
	}
	if len(p.Goals) > limits.Goals {
		add("%d goals, the limit is %d", len(p.Goals), limits.Goals)
	}
	if len(p.Intents) > limits.Intents {
		add("%d intents, the limit is %d", len(p.Intents), limits.Intents)
	}
	if len(p.Hints) > limits.Hints {
		add("%d hints, the limit is %d", len(p.Hints), limits.Hints)
	}
	if len(p.Scope) > limits.Scope {
		add("%d scope rules, the limit is %d", len(p.Scope), limits.Scope)
	}
	if len(p.Goals)+len(p.Intents)+len(p.Hints)+len(p.Scope) == 0 {
		add("the proposal is empty: it would create nothing")
	}

	// Refs share one namespace: an intent's goal and depends_on both name refs,
	// and a goal ref that also names an intent would be ambiguous.
	refs := map[string]string{} // ref -> "goal" | "intent"
	for i, g := range p.Goals {
		where := fmt.Sprintf("goals[%d]", i)
		checkRef(refs, g.Ref, "goal", where, add)
		if strings.TrimSpace(g.Text) == "" {
			add("%s.text is empty", where)
		} else if len(g.Text) > maxText {
			add("%s.text is %d characters, the limit is %d", where, len(g.Text), maxText)
		}
	}
	for i, it := range p.Intents {
		where := fmt.Sprintf("intents[%d]", i)
		checkRef(refs, it.Ref, "intent", where, add)
		if strings.TrimSpace(it.Summary) == "" {
			add("%s.summary is empty", where)
		} else if len(it.Summary) > maxText {
			add("%s.summary is %d characters, the limit is %d", where, len(it.Summary), maxText)
		}
		if it.Goal == "" {
			add("%s.goal is empty: every intent belongs to a goal", where)
		}
		checkAssets(it.AssetIDs, where, ctx, add)
	}

	// Goal and dependency references need the full ref table, so they are
	// checked after every ref has been registered.
	for i, it := range p.Intents {
		where := fmt.Sprintf("intents[%d]", i)
		if it.Goal != "" && refs[it.Goal] != "goal" {
			add("%s.goal %q is not a goal of this proposal", where, it.Goal)
		}
		for _, dep := range it.DependsOn {
			if dep == it.Ref {
				add("%s.depends_on names itself", where)
				continue
			}
			if refs[dep] != "intent" {
				add("%s.depends_on %q is not an intent of this proposal", where, dep)
			}
		}
	}
	if cycle := findCycle(p.Intents); cycle != "" {
		add("depends_on has a cycle: %s", cycle)
	}

	for i, h := range p.Hints {
		where := fmt.Sprintf("hints[%d]", i)
		if strings.TrimSpace(h.Text) == "" {
			add("%s.text is empty", where)
		} else if len(h.Text) > maxText {
			add("%s.text is %d characters, the limit is %d", where, len(h.Text), maxText)
		}
		checkAssets(h.AssetIDs, where, ctx, add)
	}

	for i, s := range p.Scope {
		where := fmt.Sprintf("scope[%d]", i)
		if s.Effect != "include" && s.Effect != "exclude" {
			add("%s.effect is %q, want include or exclude", where, s.Effect)
		}
		if !containsWord(scopeKinds, s.Kind) {
			add("%s.kind is %q, want one of %s", where, s.Kind, scopeKinds)
		}
		if strings.TrimSpace(s.Value) == "" {
			add("%s.value is empty", where)
		}
	}
	return errs
}

// HasInclude reports whether the proposal would widen the task's scope.
func HasInclude(p Proposal) bool {
	for _, s := range p.Scope {
		if s.Effect == "include" {
			return true
		}
	}
	return false
}

func checkRef(refs map[string]string, ref, kind, where string, add func(string, ...any)) {
	if strings.TrimSpace(ref) == "" {
		add("%s.ref is empty", where)
		return
	}
	if len(ref) > maxRef {
		add("%s.ref is %d characters, the limit is %d", where, len(ref), maxRef)
		return
	}
	if prev, ok := refs[ref]; ok {
		add("%s.ref %q is already used by a %s", where, ref, prev)
		return
	}
	refs[ref] = kind
}

func checkAssets(ids []int64, where string, ctx Context, add func(string, ...any)) {
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			add("%s.asset_ids repeats %d", where, id)
			continue
		}
		seen[id] = true
		if ctx.AssetIDs != nil && !ctx.AssetIDs[id] {
			add("%s.asset_ids has %d, which is not an asset of this task", where, id)
		}
	}
}

// findCycle returns a readable cycle path, or "" when the graph is acyclic.
func findCycle(intents []Intent) string {
	deps := map[string][]string{}
	for _, it := range intents {
		deps[it.Ref] = it.DependsOn
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := map[string]int{}
	var path []string
	var walk func(string) string
	walk = func(ref string) string {
		switch state[ref] {
		case grey:
			return strings.Join(append(path, ref), " -> ")
		case black:
			return ""
		}
		state[ref] = grey
		path = append(path, ref)
		for _, dep := range deps[ref] {
			if _, ok := deps[dep]; !ok {
				continue // already reported as an unknown ref
			}
			if c := walk(dep); c != "" {
				return c
			}
		}
		path = path[:len(path)-1]
		state[ref] = black
		return ""
	}
	for _, it := range intents {
		if c := walk(it.Ref); c != "" {
			return c
		}
	}
	return ""
}

func containsWord(list, want string) bool {
	for _, w := range strings.Fields(list) {
		if w == want {
			return true
		}
	}
	return false
}

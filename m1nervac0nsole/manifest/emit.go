package manifest

import (
	"fmt"
	"strings"
)

// Target is an asset a record produced, ready to be upserted.
type Target struct {
	Kind     Kind
	Value    string
	ParentOf string // "input" when the asset hangs under the run's input target
}

// Fact is an observation attached to the run's input asset.
type Fact struct {
	Kind KindOrFact
	Data map[string]string
}

// EmitResult is everything one tool run contributed.
type EmitResult struct {
	Targets []Target
	Facts   []Fact
	// Skipped counts emit rules whose template could not resolve. It is reported
	// rather than raised: a partial row is normal, and an operator seeing a
	// non-zero count knows the manifest may need widening.
	Skipped int
}

// Apply turns records into targets and facts using the manifest's emit rules.
//
// A rule whose value (or any fact field) fails to resolve is skipped, not
// fatal. This is the one behavioural decision worth stating twice: tools emit
// partial rows constantly — a subfinder row with no host, a nuclei row with no
// severity — and discarding a whole scan because one row is thin would be worse
// than losing that row.
func (m *Manifest) Apply(records []Record) EmitResult {
	var out EmitResult
	for _, rec := range records {
		for _, rule := range m.Emit.Targets {
			value, ok := Interpolate(rule.Value, rec)
			if !ok || value == "" {
				out.Skipped++
				continue
			}
			out.Targets = append(out.Targets, Target{
				Kind:     rule.Kind,
				Value:    value,
				ParentOf: rule.Parent,
			})
		}
		for _, rule := range m.Emit.Facts {
			data := make(map[string]string, len(rule.Data))
			missing := false
			for key, tmpl := range rule.Data {
				resolved, ok := Interpolate(tmpl, rec)
				if !ok {
					if isOptional(tmpl) {
						data[key] = ""
						continue
					}
					missing = true
					break
				}
				data[key] = resolved
			}
			if missing {
				out.Skipped++
				continue
			}
			out.Facts = append(out.Facts, Fact{Kind: rule.Kind, Data: data})
		}
	}
	return out
}

// Run parses a tool's output and applies its emit rules in one step, which is
// what a caller almost always wants.
func (m *Manifest) Run(output string) (EmitResult, error) {
	records, err := m.Parse(output)
	if err != nil {
		return EmitResult{}, err
	}
	return m.Apply(records), nil
}

// ValidateEmit checks that every emit template names a field the parser can
// produce. It cannot prove the field will be present at run time — that is what
// a golden fixture is for — but it catches a typo in a template, which is the
// common failure and otherwise shows up as an empty scan.
func (m *Manifest) ValidateEmit() error {
	for _, rule := range m.Emit.Targets {
		if err := m.checkTemplate(rule.Value); err != nil {
			return fmt.Errorf("%s: target value %q: %w", m.ID, rule.Value, err)
		}
	}
	for _, rule := range m.Emit.Facts {
		for key, tmpl := range rule.Data {
			if err := m.checkTemplate(tmpl); err != nil {
				return fmt.Errorf("%s: fact field %q: %w", m.ID, key, err)
			}
		}
	}
	return nil
}

// isOptional reports whether a template marks its field optional with a
// trailing `?` inside the placeholder.
func isOptional(tmpl string) bool {
	inner := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(tmpl), "{{"), "}}")
	return strings.HasSuffix(strings.TrimSpace(inner), "?")
}

func (m *Manifest) checkTemplate(tmpl string) error {
	if !strings.Contains(tmpl, "{{") {
		return nil
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(tmpl), "{{"), "}}"))
	if _, ok := strings.CutPrefix(inner, "record."); !ok {
		return fmt.Errorf("expected a {{ record.<field> }} placeholder, got %q", tmpl)
	}
	return nil
}

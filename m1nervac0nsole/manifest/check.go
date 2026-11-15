package manifest

import (
	"fmt"
	"regexp"
	"strings"
)

// idPattern keeps an id usable as a URL path segment and a run_tool argument.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Check is the gate for a manifest saved at run time. Parse only guarantees the
// file is well formed; a template that is going to be offered to the planner
// must also be complete (an agent picks a tool from its description, accepts and
// requires) and its default command must actually render, because a template
// that fails only when first run costs a worker turn.
//
// Required parameters are not enforced here: they have no default by design, so
// the render check substitutes each parameter's declared default (possibly empty).
func Check(text string) (*Manifest, error) {
	m, err := Parse(text)
	if err != nil {
		return nil, err
	}
	if !idPattern.MatchString(m.ID) {
		return nil, fmt.Errorf("%s: id must be lowercase letters, digits, '-' or '_'", m.ID)
	}
	if err := m.ValidateEmit(); err != nil {
		return nil, err
	}
	switch {
	case strings.TrimSpace(m.Description) == "":
		return nil, fmt.Errorf("%s: description is required", m.ID)
	case len(m.Accepts) == 0:
		return nil, fmt.Errorf("%s: accepts is required", m.ID)
	case len(m.Requires) == 0:
		return nil, fmt.Errorf("%s: requires is required, so a missing binary can be reported", m.ID)
	case m.Command.TimeoutSeconds <= 0:
		return nil, fmt.Errorf("%s: command.timeout_seconds must be positive", m.ID)
	}
	defaults := make(map[string]string, len(m.Params))
	for name, p := range m.Params {
		defaults[name] = p.Default
	}
	// The proxy placeholder is rendered with a stand-in: a template that renders
	// only when a proxy exists would otherwise pass validation and then drop a
	// flag mid-run.
	if _, err := m.Resolve("example.com", defaults, "http://proxy.example:8080"); err != nil {
		return nil, fmt.Errorf("default command does not render: %w", err)
	}
	return m, nil
}

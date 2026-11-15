package manifest

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
)

// Resolve renders a manifest's command into a concrete argv. proxy is the
// gateway URL the run's tool environment carries, credential included; it is
// what `{{ proxy }}` and `{{ proxyhost }}` render, and empty renders nothing
// rather than an invented address.
//
// The template language is intentionally tiny: `{{ target.value }}`,
// `{{ params.name }}`, and the two argument forms `{{ params.name | -flag }}`
// (emit `-flag` and `value` as two arguments, or nothing when the value is
// empty; a bool parameter emits the bare `-flag` when true and nothing when
// false) and `{{ params.name? }}` (emit the value alone, or nothing). That is
// every shape the tool manifests need, and a larger language would be a
// scripting surface pretending to be configuration.
//
// Values are never shell-quoted here because the argv is executed without a
// shell. A parameter that contains a space therefore stays one argument, which
// is the behaviour an operator expects and the behaviour a shell would break.
// For the same reason a flag and its value are separate arguments: one
// "-sV true" element is a single unknown option to the tool, not a flag.
func (m *Manifest) Resolve(targetValue string, values map[string]string, proxy string) ([]string, error) {
	bools := make(map[string]bool)
	for name, p := range m.Params {
		bools[name] = p.Type == ParamBool
	}
	proxy = strings.TrimSpace(proxy)
	args := make([]string, 0, len(m.Command.Args))
	for _, tmpl := range m.Command.Args {
		rendered, err := renderArg(tmpl, targetValue, values, bools, proxy)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		for _, a := range rendered {
			if a != "" {
				args = append(args, a)
			}
		}
	}
	return args, nil
}

// Effective returns the parameter values with defaults applied, so a caller
// sees exactly what would be sent. Required parameters left empty are an error:
// running the tool without them produces output that looks valid and is not.
func (m *Manifest) Effective(values map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(m.Params))
	for name, p := range m.Params {
		v, ok := values[name]
		if !ok || strings.TrimSpace(v) == "" {
			v = p.Default
		}
		if p.Required && strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("%s: parameter %q is required", m.ID, name)
		}
		if p.Type == ParamEnum && v != "" && !contains(p.Options, v) {
			return nil, fmt.Errorf("%s: parameter %q must be one of %s, got %q",
				m.ID, name, strings.Join(p.Options, ", "), v)
		}
		out[name] = v
	}
	return out, nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// renderArg expands one argv template element into zero or more arguments.
//
// Two shapes are supported, and the distinction matters:
//
//   - the whole element is one placeholder (`{{ params.rate }}`, `{{ x | -flag }}`,
//     `{{ x? }}`): the flag forms apply, and a `| -flag` yields the flag and the
//     value as two arguments (the flag alone for a true bool parameter);
//   - the placeholder sits inside surrounding text (`-{{ params.timing }}`,
//     `{{ target.value }}/FUZZ`): only bare placeholders may appear, each is
//     substituted in place, and if any resolves empty the whole element is
//     dropped — `-{{ x }}` with an empty x must not become a bare "-", which
//     several tools read as a real flag.
func renderArg(tmpl, targetValue string, values map[string]string, bools map[string]bool, proxy string) ([]string, error) {
	if !strings.Contains(tmpl, "{{") {
		return []string{tmpl}, nil
	}

	// Whole-element placeholder: the flag forms are available.
	if strings.HasPrefix(tmpl, "{{") && strings.HasSuffix(tmpl, "}}") &&
		strings.Count(tmpl, "{{") == 1 {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(tmpl, "{{"), "}}"))

		// `name?` renders the value alone and vanishes when empty.
		if strings.HasSuffix(inner, "?") {
			expr := strings.TrimSpace(strings.TrimSuffix(inner, "?"))
			v, err := lookup(expr, targetValue, values, proxy)
			return []string{v}, err
		}

		// `name | -flag` renders "-flag" "value", or nothing when the value is empty.
		if idx := strings.Index(inner, "|"); idx >= 0 {
			expr := strings.TrimSpace(inner[:idx])
			flag := strings.TrimSpace(inner[idx+1:])
			v, err := lookup(expr, targetValue, values, proxy)
			if err != nil {
				return nil, err
			}
			if v == "" {
				return nil, nil
			}
			if flag == "" {
				return []string{v}, nil
			}
			if name, ok := strings.CutPrefix(expr, "params."); ok && bools[name] {
				on, err := strconv.ParseBool(v)
				if err != nil {
					return nil, fmt.Errorf("parameter %q must be true or false, got %q", name, v)
				}
				if !on {
					return nil, nil
				}
				return []string{flag}, nil
			}
			return []string{flag, v}, nil
		}

		v, err := lookup(inner, targetValue, values, proxy)
		return []string{v}, err
	}

	// Embedded placeholders: substitute in place, drop the element if one is empty.
	var b strings.Builder
	rest := tmpl
	for {
		start := strings.Index(rest, "{{")
		if start < 0 {
			b.WriteString(rest)
			break
		}
		end := strings.Index(rest[start:], "}}")
		if end < 0 {
			return nil, fmt.Errorf("unterminated placeholder in %q", tmpl)
		}
		end += start
		b.WriteString(rest[:start])
		expr := strings.TrimSpace(rest[start+2 : end])
		v, err := lookup(expr, targetValue, values, proxy)
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, nil
		}
		b.WriteString(v)
		rest = rest[end+2:]
	}
	return []string{b.String()}, nil
}

// lookup resolves `target.value`, `proxy`, `proxyhost`, `useragent` or
// `params.name`.
func lookup(expr, targetValue string, values map[string]string, proxy string) (string, error) {
	switch expr {
	case "target.value":
		return targetValue, nil
	case "proxy":
		// The engagement's outbound proxy. A tool that ignores the proxy
		// environment variables still needs it passed as a flag, or its traffic
		// leaves with the tool's own TLS fingerprint.
		return proxy, nil
	case "proxyhost":
		// Same proxy without the scheme, for tools that take host[:port] only.
		// Any scheme is stripped, not just http(s): a socks5 exit is configured
		// with one too, and leaving it in would hand the tool a URL as a host.
		if _, rest, ok := strings.Cut(proxy, "://"); ok {
			return rest, nil
		}
		return proxy, nil
	case "useragent":
		// The engagement's outbound identity. A tool with its own User-Agent flag
		// is given the same string the proxy would have set, so a run that
		// bypasses the proxy still does not announce itself.
		return useragent.Get(), nil
	case "":
		return "", fmt.Errorf("empty placeholder")
	}
	if name, ok := strings.CutPrefix(expr, "params."); ok {
		v, present := values[name]
		if !present {
			// An unknown parameter is a manifest bug, not an operator error, so it
			// fails loudly instead of rendering an empty string into the argv.
			return "", fmt.Errorf("unknown parameter %q", name)
		}
		return v, nil
	}
	return "", fmt.Errorf("unknown placeholder %q (expected target.value, useragent, proxy, or params.<name>)", expr)
}

// gatewayProxy is gone: the address a manifest tool is given is the run's own
// proxy URL, passed to Resolve. A process-wide one cannot carry the per-session
// credential the gateway requires, and a manifest run with no session renders no
// proxy rather than a bare address the gateway would refuse.

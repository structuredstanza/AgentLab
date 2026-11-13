package manifest_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
)

// Every shipped manifest must load and validate. A manifest that parses but
// names an unknown emit field would produce an empty scan at run time, which
// looks like a clean target rather than a broken tool, so this gate is the
// cheap half of the golden tests.
func TestShippedManifestsLoad(t *testing.T) {
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("no manifests loaded")
	}
	for _, m := range set.All() {
		if err := m.ValidateEmit(); err != nil {
			t.Errorf("emit: %v", err)
		}
		if len(m.Accepts) == 0 {
			t.Errorf("%s: declares no accepted target kinds", m.ID)
		}
		if m.Command.TimeoutSeconds <= 0 {
			t.Errorf("%s: needs a positive timeout_seconds", m.ID)
		}
		if m.Description == "" {
			t.Errorf("%s: needs a description", m.ID)
		}
	}
	t.Logf("loaded %d manifests", set.Len())
}

// A manifest whose binary is not in the image is still valid, but the set of
// required binaries is what the image must provide. This test records that list
// so a missing tool shows up as a diff rather than as a silent gap.
func TestRequiredBinariesAreDeclared(t *testing.T) {
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, m := range set.All() {
		if len(m.Requires) == 0 {
			t.Errorf("%s: declares no requires, so a missing binary cannot be reported", m.ID)
			continue
		}
		for _, bin := range m.Requires {
			if _, err := os.Stat("/usr/bin/" + bin); err != nil {
				if _, err := os.Stat("/usr/local/bin/" + bin); err != nil {
					missing = append(missing, m.ID+":"+bin)
				}
			}
		}
	}
	if len(missing) > 0 {
		t.Logf("binaries not on this host (expected outside the guest image): %s",
			strings.Join(missing, ", "))
	}
}

// Templates must only reference declared parameters. A typo renders an empty
// argument, which most tools treat as a positional and then misbehave on.
func TestCommandTemplatesReferenceDeclaredParams(t *testing.T) {
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range set.All() {
		if _, err := m.Resolve("example.test", defaultsFor(m)); err != nil {
			t.Errorf("%s: resolve with defaults: %v", m.ID, err)
		}
	}
}

func defaultsFor(m *manifest.Manifest) map[string]string {
	out := make(map[string]string, len(m.Params))
	for name, p := range m.Params {
		out[name] = p.Default
		if out[name] == "" {
			out[name] = "x"
			if p.Type == manifest.ParamBool {
				out[name] = "true"
			}
		}
	}
	return out
}

// The command runs without a shell, so "-sV true" as one argument is a single
// unknown option, not a flag and its value. Every `| -flag` manifest shipped
// that way, and nmap printed usage text instead of XML. Check every manifest,
// not one, because the defect lived in the shared renderer.
func TestFlagAndValueAreSeparateArguments(t *testing.T) {
	flagWithValue := regexp.MustCompile(`^--?[A-Za-z][\w-]* \S`)
	for _, m := range manifest.LoadBuiltin().All() {
		args, err := m.Resolve("example.test", defaultsFor(m))
		if err != nil {
			t.Fatalf("%s: %v", m.ID, err)
		}
		for _, a := range args {
			if flagWithValue.MatchString(a) {
				t.Errorf("%s: %q is one argument; a flag and its value must be two", m.ID, a)
			}
		}
	}
}

// A bool parameter is a switch: bare flag when true, absent when false.
func TestBoolParameterIsABareSwitch(t *testing.T) {
	m := manifest.LoadBuiltin().Get("nmap")
	for value, want := range map[string]bool{"true": true, "false": false} {
		params, err := m.Effective(map[string]string{"service": value, "scripts": "default"})
		if err != nil {
			t.Fatal(err)
		}
		args, err := m.Resolve("10.129.14.7", params)
		if err != nil {
			t.Fatal(err)
		}
		has := false
		for _, a := range args {
			if a == "-sV" {
				has = true
			}
			if a == "true" || a == "false" {
				t.Errorf("service=%s leaked %q into argv: %v", value, a, args)
			}
		}
		if has != want {
			t.Errorf("service=%s: -sV present = %v, want %v (%v)", value, has, want, args)
		}
	}
	params, _ := m.Effective(map[string]string{"service": "maybe"})
	if _, err := m.Resolve("10.129.14.7", params); err == nil {
		t.Error("a non-boolean value for a bool parameter must be an error")
	}
}

// A [limits] block naming a parameter that does not exist would silently cap
// nothing, leaving the tool at its own default rate.
func TestLimitsNameAnExistingParameter(t *testing.T) {
	set := manifest.LoadBuiltin()
	declared := 0
	for _, m := range set.All() {
		if m.Limits.Unit == manifest.RateNone {
			continue
		}
		declared++
		if m.Limits.Param == "" {
			t.Errorf("%s declares unit %q with no param", m.ID, m.Limits.Unit)
			continue
		}
		if _, ok := m.Params[m.Limits.Param]; !ok {
			t.Errorf("%s limits.param %q is not one of its parameters", m.ID, m.Limits.Param)
		}
	}
	if declared == 0 {
		t.Fatal("no manifest declares a rate; the policy would cap nothing")
	}
}

// Every HTTP tool the policy cannot clamp must still be capped by the proxy, so
// the set of unclamped HTTP tools is a deliberate list, not an accident.
func TestHTTPToolsWithoutLimitsAreKnown(t *testing.T) {
	unclamped := map[string]bool{}
	for _, m := range manifest.LoadBuiltin().All() {
		if m.Category == manifest.CategoryWeb && m.Limits.Unit == manifest.RateNone {
			unclamped[m.ID] = true
		}
	}
	want := []string{"dalfox", "gowitness", "sqlmap", "whatweb", "wpscan"}
	for _, id := range want {
		if !unclamped[id] {
			t.Errorf("%s no longer needs the proxy ceiling, so remove it from this list", id)
		}
		delete(unclamped, id)
	}
	for id := range unclamped {
		t.Errorf("%s is a web tool with no rate limit; add [limits] or accept the proxy ceiling deliberately", id)
	}
}

// A tool with a native User-Agent flag must be given the engagement identity,
// or a run that bypasses the proxy announces the tool instead.
func TestUserAgentFlagCarriesTheEngagementIdentity(t *testing.T) {
	t.Setenv("M1NERVAC0NSOLE_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) EngagementIdentity/9.9")
	useragent.Set("Mozilla/5.0 (X11; Linux x86_64) EngagementIdentity/9.9")

	set := manifest.LoadBuiltin()
	checked := 0
	for _, id := range []string{"whatweb", "gobuster", "wpscan", "sqlmap", "dalfox"} {
		m := set.Get(id)
		if m == nil {
			t.Fatalf("%s manifest missing", id)
		}
		params, err := m.Effective(nil)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		args, err := m.Resolve("10.129.14.7", params)
		if err != nil {
			t.Fatalf("%s resolve: %v", id, err)
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "EngagementIdentity/9.9") {
			t.Errorf("%s does not pass the engagement identity: %s", id, joined)
		}
		checked++
	}
	if checked != 5 {
		t.Fatalf("checked %d manifests, want 5", checked)
	}
}

// Every tool that speaks HTTP must present the engagement identity. A tool left
// without it is not a style problem: it names itself to the target, and the
// whole point of the identity is that a target sees one coherent visitor.
//
// Tools that do not speak HTTP (dig, whois, masscan, hydra, ...) are exempt,
// and a new tool in a web category fails here until it is declared.
func TestEveryHTTPToolCarriesTheIdentity(t *testing.T) {
	nonHTTP := map[string]bool{
		"dig": true, "whois": true, "mtr": true, "traceroute": true,
		"masscan": true, "naabu": true, "rustscan": true, "nbtscan": true,
		"hydra": true, "searchsploit": true, "sslscan": true, "testssl": true,
		"enum4linux": true, "enum4linux-ng": true, "netexec": true,
		"subfinder": true, "gau": true, "amass": true, "dnsx": true,
		// nmap is a port scanner: it has no user-agent option, and its NSE
		// http-* scripts would need --script-args handling of their own. A scan
		// through nmap is a scan, not a browsing session.
		"nmap": true,
	}
	for _, m := range manifest.LoadBuiltin().All() {
		if nonHTTP[m.ID] {
			continue
		}
		// Either an explicit user-agent, or the proxy, which rewrites the header
		// on the way out. A tool with neither sends its own identity.
		joined := strings.Join(m.Command.Args, " ")
		if !strings.Contains(joined, "useragent") && !strings.Contains(joined, "{{ proxy }}") {
			t.Errorf("%s speaks HTTP but passes neither an identity nor the proxy", m.ID)
		}
	}
}

// A tool that ignores the proxy environment variables must be given the proxy
// as a flag, or its traffic leaves with the tool's own TLS fingerprint.
func TestProxyBypassingToolsPassTheProxyExplicitly(t *testing.T) {
	// Measured: these ignore http_proxy and connect directly.
	needsFlag := []string{"katana", "dalfox"}
	set := manifest.LoadBuiltin()
	for _, id := range needsFlag {
		m := set.Get(id)
		if m == nil {
			t.Fatalf("%s missing", id)
		}
		if !strings.Contains(strings.Join(m.Command.Args, " "), "{{ proxy }}") {
			t.Errorf("%s ignores http_proxy; it must be given --proxy", id)
		}
	}
}

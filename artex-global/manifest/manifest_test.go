package manifest_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/manifest"
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
		}
	}
	return out
}

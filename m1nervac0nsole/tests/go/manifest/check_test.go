package manifest_test

import (
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
)

const miniManifest = `id = "mini"
name = "Mini"
description = "A minimal template"
category = "recon"
accepts = ["domain"]
requires = ["echo"]

[params]
word = { type = "string", label = "Word", default = "hi" }

[command]
program = "echo"
args = ["{{ params.word }}", "{{ target.value }}"]
timeout_seconds = 5

[emit]
parser = "lines"
fields = ["value"]
`

// A built-in must pass the runtime gate as shipped: "reset to built-in" and
// "edit then save unchanged" both depend on it.
func TestCheckAcceptsEveryBuiltinSource(t *testing.T) {
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range set.IDs() {
		src, ok := manifest.BuiltinSource(id)
		if !ok {
			t.Errorf("%s: no built-in source", id)
			continue
		}
		if _, err := manifest.Check(src); err != nil {
			t.Errorf("%s: Check rejected the shipped source: %v", id, err)
		}
	}
	if _, ok := manifest.BuiltinSource("no-such-tool"); ok {
		t.Error("BuiltinSource answered for an unknown id")
	}
}

func TestCheckRejects(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"unknown key", "bogus = 1\n" + miniManifest, "unknown keys"},
		{"empty requires", strings.Replace(miniManifest, `requires = ["echo"]`, `requires = []`, 1), "requires"},
		{"undeclared param", strings.Replace(miniManifest, `"{{ params.word }}"`, `"{{ params.ghost }}"`, 1), "ghost"},
		{"no description", strings.Replace(miniManifest, `description = "A minimal template"`, `description = " "`, 1), "description"},
		{"zero timeout", strings.Replace(miniManifest, "timeout_seconds = 5", "timeout_seconds = 0", 1), "timeout"},
		{"unsafe id", strings.Replace(miniManifest, `id = "mini"`, `id = "../mini"`, 1), "id"},
	}
	for _, c := range cases {
		_, err := manifest.Check(c.text)
		if err == nil {
			t.Errorf("%s: Check accepted it", c.name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
	if _, err := manifest.Check(miniManifest); err != nil {
		t.Fatalf("the baseline template should pass: %v", err)
	}
}

func TestInstallTableRoundTrips(t *testing.T) {
	m, err := manifest.Parse(miniManifest + "\n[install]\nscript = \"apt-get install -y echo\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if m.Install.Script != "apt-get install -y echo" || m.Install.TimeoutSeconds != 600 {
		t.Fatalf("install = %+v, want the script and the 600s default", m.Install)
	}
	m, err = manifest.Parse(miniManifest + "\n[install]\nscript = \"true\"\ntimeout_seconds = 30\n")
	if err != nil || m.Install.TimeoutSeconds != 30 {
		t.Fatalf("explicit timeout = %+v, %v", m.Install, err)
	}
	if m, err = manifest.Parse(miniManifest); err != nil || m.Install.Script != "" {
		t.Fatalf("a manifest without [install] must parse as not installable: %+v, %v", m.Install, err)
	}
}

// The overlay replaces a built-in by id, adds a new id, and leaves the base set
// untouched so a live set can be swapped atomically.
func TestOverlayReplacesAndAdds(t *testing.T) {
	base, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	dig, err := manifest.Parse(strings.Replace(mustSource(t, "dig"), "Direct DNS query", "Edited DNS query", 1))
	if err != nil {
		t.Fatal(err)
	}
	mini, err := manifest.Parse(miniManifest)
	if err != nil {
		t.Fatal(err)
	}
	set := base.Overlay([]*manifest.Manifest{dig, mini})
	if set.Len() != base.Len()+1 {
		t.Fatalf("overlay has %d manifests, want %d", set.Len(), base.Len()+1)
	}
	if !strings.HasPrefix(set.Get("dig").Description, "Edited") || strings.HasPrefix(base.Get("dig").Description, "Edited") {
		t.Fatal("overlay did not replace dig, or it modified the base set")
	}
	if set.Get("mini") == nil {
		t.Fatal("overlay lost the custom template")
	}
}

func mustSource(t *testing.T, id string) string {
	t.Helper()
	src, ok := manifest.BuiltinSource(id)
	if !ok {
		t.Fatalf("no built-in %q", id)
	}
	return src
}

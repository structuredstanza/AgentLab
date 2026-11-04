package manifest_test

import (
	"os/exec"
	"testing"

	"github.com/Autumn-27/artex/manifest"
)

// Runs a real tool against the loopback and parses its real output through the
// embedded manifest. This is the only test that proves the manifest matches what
// the installed binary actually prints; the golden cases prove the parser, not
// the command line.
func TestLiveDigAgainstLoopback(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Skip("dig not installed")
	}
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	m := set.Get("dig")
	params, err := m.Effective(map[string]string{"record_type": "A"})
	if err != nil {
		t.Fatal(err)
	}
	args, err := m.Resolve("localhost", params)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(m.Command.Program, args...).Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	result, err := m.Run(string(out))
	if err != nil {
		t.Fatalf("parse %q: %v", string(out), err)
	}
	if len(result.Facts) == 0 {
		t.Fatalf("dig against localhost produced no facts from %q", string(out))
	}
	t.Logf("facts: %v", result.Facts)
}

// nmap's XML parser is the only one with a hand-written decoder, so it gets the
// same real-binary check: a closed loopback port still proves the shape.
func TestLiveNmapAgainstLoopback(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed")
	}
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	m := set.Get("nmap")
	params, err := m.Effective(map[string]string{"ports": "22", "service": "false", "timing": "T4"})
	if err != nil {
		t.Fatal(err)
	}
	args, err := m.Resolve("127.0.0.1", params)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(m.Command.Program, args...).Output()
	if err != nil {
		// A SYN scan needs root; retry as a TCP connect scan so the test proves
		// the XML shape rather than the caller's privileges.
		args = append(args[:len(args)-1], "-sT", args[len(args)-1])
		out, err = exec.Command(m.Command.Program, args...).Output()
		if err != nil {
			t.Skipf("nmap cannot scan here: %v", err)
		}
	}
	result, err := m.Run(string(out))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(result.Targets) == 0 {
		t.Fatalf("nmap produced no targets from %d bytes", len(out))
	}
	t.Logf("targets: %v facts: %d", result.Targets, len(result.Facts))
}

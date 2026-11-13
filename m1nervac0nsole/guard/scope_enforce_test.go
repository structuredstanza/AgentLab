package guard

import (
	"context"
	"encoding/json"
	"testing"
)

type fakeScope struct{ excluded map[string]string }

func (f fakeScope) Judge(asset string) (bool, string) {
	if r, ok := f.excluded[asset]; ok {
		return true, r
	}
	return false, ""
}

// The boundary must refuse a call that names an excluded host, and must let
// everything else through: an engagement whose rules are still empty reports
// every asset unknown, and treating unknown as out would refuse all work.
func TestGuardRefusesExcludedHost(t *testing.T) {
	sc := fakeScope{excluded: map[string]string{
		"out-of-scope.test": "explicitly excluded by the program",
	}}
	g := New().WithScope(sc)

	block := func(cmd string) (bool, string) {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b, msg
	}

	cases := []struct {
		name    string
		cmd     string
		blocked bool
	}{
		{"excluded host in a command", "nmap -p 80 out-of-scope.test", true},
		{"excluded host in a url", "curl https://out-of-scope.test/admin", true},
		{"in-scope host", "nmap -p 80 in-scope.test", false},
		{"unrelated command", "ls -la /tmp", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, msg := block(c.cmd)
			if got != c.blocked {
				t.Fatalf("blocked=%v, want %v (message: %s)", got, c.blocked, msg)
			}
			if c.blocked && msg == "" {
				t.Fatal("a block must explain itself")
			}
		})
	}
}

// Without a checker the guard behaves exactly as before, so this change cannot
// affect a code path that has not opted in.
func TestGuardWithoutScopeAllows(t *testing.T) {
	g := New()
	input, _ := json.Marshal(map[string]string{"command": "nmap out-of-scope.test"})
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
	if blocked {
		t.Fatalf("a guard with no scope checker must not block: %s", msg)
	}
}

// Every asset shape the extractor sees must be judged, including one that only
// appears inside a URL, or a path-level exclusion is bypassed by the host rule.
func TestAssetsInExtractsEveryShape(t *testing.T) {
	input := json.RawMessage(`{"command":"nuclei -u https://api.target.test/v1 -target 10.0.0.5 -l hosts.txt"}`)
	assets := assetsIn(input)
	want := map[string]bool{
		"https://api.target.test/v1": false,
		"10.0.0.5":                   false,
	}
	for _, a := range assets {
		if _, ok := want[a]; ok {
			want[a] = true
		}
	}
	for a, found := range want {
		if !found {
			t.Errorf("asset %q not extracted from %v", a, assets)
		}
	}
}

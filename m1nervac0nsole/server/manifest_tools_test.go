package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
)

func listToolsText(t *testing.T, in string) string {
	t.Helper()
	res, err := (&Server{}).toolListManifests().Call(context.Background(), json.RawMessage(in), nil)
	if err != nil {
		t.Fatalf("list_tools: %v", err)
	}
	return res.Flatten()
}

// The catalog is long enough that a model asking for one tool should get one
// tool, and an empty result must say so rather than look like a broken catalog.
func TestListToolsFiltersByQuery(t *testing.T) {
	all := listToolsText(t, `{}`)
	if !strings.Contains(all, "nmap") || !strings.Contains(all, "ffuf") {
		t.Fatalf("the unfiltered catalog is missing tools:\n%s", all[:min(len(all), 400)])
	}

	narrowed := listToolsText(t, `{"query":"nmap"}`)
	if !strings.Contains(narrowed, "- nmap") {
		t.Fatalf("query nmap did not return nmap:\n%s", narrowed)
	}
	if strings.Contains(narrowed, "- ffuf") {
		t.Fatalf("query nmap returned unrelated tools:\n%s", narrowed)
	}
	if !strings.Contains(narrowed, "of") || !strings.Contains(narrowed, "match") {
		t.Fatalf("the narrowed header does not report the count:\n%s", narrowed)
	}

	empty := listToolsText(t, `{"query":"zzz-no-such-tool"}`)
	if !strings.Contains(empty, "no tool matches") {
		t.Fatalf("an empty result is not explained:\n%s", empty)
	}
}

// publishedArtifact describes the file the supervisor published, and reports
// nothing at all for a manifest that was never installed: a row with no install
// must not claim a path, a size or a digest.
func TestPublishedArtifact(t *testing.T) {
	root := t.TempDir()
	t.Setenv(execbox.ToolboxEnv, root)

	if got := publishedArtifact("never-installed"); got != nil {
		t.Fatalf("publishedArtifact for an absent tool = %+v, want nil", got)
	}
	if got := publishedArtifact("/usr/bin/absolute"); got != nil {
		t.Fatalf("publishedArtifact for an absolute program = %+v, want nil", got)
	}

	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\necho fixture\n")
	path := filepath.Join(bin, "fixture")
	if err := os.WriteFile(path, body, 0o755); err != nil {
		t.Fatal(err)
	}

	got := publishedArtifact("fixture")
	if got == nil {
		t.Fatal("publishedArtifact for a published tool = nil")
	}
	want := fmt.Sprintf("%x", sha256.Sum256(body))
	if got.Path != path || got.Size != int64(len(body)) || got.SHA256 != want || got.InstalledAt == "" {
		t.Fatalf("publishedArtifact = %+v, want path %s size %d sha %s and a time", got, path, len(body), want)
	}

	// A replaced binary must be re-digested rather than reported from the cache.
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho replaced\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if replaced := publishedArtifact("fixture"); replaced.SHA256 == got.SHA256 {
		t.Fatalf("publishedArtifact kept the stale digest %s after the file changed", replaced.SHA256)
	}
}

// An nmap run that sees nothing from the sandbox must say why; a run that
// found something must not carry the warning.
func TestSandboxBlindNote(t *testing.T) {
	nmap := builtinManifests.Get("nmap")
	if nmap == nil {
		t.Fatal("builtin nmap manifest missing")
	}
	if got := sandboxBlindNote(nmap, 0, 0); !strings.Contains(got, "Use port_scan") {
		t.Fatalf("empty nmap run has no note: %q", got)
	}
	if got := sandboxBlindNote(nmap, 1, 0); got != "" {
		t.Fatalf("nmap run with an asset got a note: %q", got)
	}
	if ffuf := builtinManifests.Get("ffuf"); ffuf != nil {
		if got := sandboxBlindNote(ffuf, 0, 0); got != "" {
			t.Fatalf("non-scanner got the note: %q", got)
		}
	}
}

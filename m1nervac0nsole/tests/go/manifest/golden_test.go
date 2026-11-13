package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
)

// A golden case pins one tool's parsing: a captured output file and the records
// that output must yield. It exists because a manifest is data, and data that
// nobody tests drifts — a tool adds a field, an emit rule keeps naming the old
// one, and the scan silently returns nothing.
//
// Every manifest must have a case. A manifest without one is listed by
// TestEveryManifestHasAGoldenCase and fails, so adding a tool means adding its
// fixture in the same change.
type goldenCase struct {
	Manifest string           `json:"manifest"`
	Fixture  string           `json:"fixture"`
	Records  []map[string]any `json:"records"`
	Targets  []map[string]any `json:"targets"`
	Facts    []map[string]any `json:"facts"`
}

func TestGoldenCases(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read golden dir: %v", err)
	}

	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}

	var ran int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".case.json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".case.json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var c goldenCase
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("case json: %v", err)
			}
			m := set.Get(c.Manifest)
			if m == nil {
				t.Fatalf("manifest %q not found", c.Manifest)
			}
			fixture, err := os.ReadFile(filepath.Join(dir, c.Fixture))
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}

			records, err := m.Parse(string(fixture))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			// A case may check a prefix of the records: a fixture with three
			// lines and two asserted rows still proves the parser handled all
			// three, without restating every field of the third.
			if len(records) < len(c.Records) {
				t.Fatalf("record count = %d, want at least %d\nrecords: %v",
					len(records), len(c.Records), records)
			}
			for i, want := range c.Records {
				for field, wantValue := range want {
					got, ok := records[i][field]
					if !ok {
						t.Errorf("record %d: field %q missing (have %v)", i, field, records[i].FieldNames())
						continue
					}
					if gotString := manifest.Scalar(got); gotString != manifest.Scalar(wantValue) {
						t.Errorf("record %d field %q = %q, want %q", i, field, gotString, manifest.Scalar(wantValue))
					}
				}
			}

			if c.Targets != nil || c.Facts != nil {
				result := m.Apply(records)
				if len(result.Targets) < len(c.Targets) {
					t.Errorf("targets = %d, want at least %d (%v)", len(result.Targets), len(c.Targets), result.Targets)
				}
				for i := range c.Targets {
					if i >= len(result.Targets) {
						break
					}
					if got, want := result.Targets[i].Value, c.Targets[i]["value"]; got != want {
						t.Errorf("target %d value = %q, want %q", i, got, want)
					}
					if got, want := string(result.Targets[i].Kind), c.Targets[i]["kind"]; got != want {
						t.Errorf("target %d kind = %q, want %q", i, got, want)
					}
				}
				if len(result.Facts) < len(c.Facts) {
					t.Errorf("facts = %d, want at least %d", len(result.Facts), len(c.Facts))
				}
				for i := range c.Facts {
					if i >= len(result.Facts) {
						break
					}
					for field, want := range c.Facts[i] {
						if field == "kind" {
							if string(result.Facts[i].Kind) != manifest.Scalar(want) {
								t.Errorf("fact %d kind = %q, want %q", i, result.Facts[i].Kind, manifest.Scalar(want))
							}
							continue
						}
						if got := result.Facts[i].Data[field]; got != manifest.Scalar(want) {
							t.Errorf("fact %d field %q = %q, want %q", i, field, got, manifest.Scalar(want))
						}
					}
				}
			}
		})
		ran++
	}
	if ran == 0 {
		t.Fatal("no golden cases found")
	}
}

// Every shipped manifest must be covered by a golden case, so a new tool cannot
// ship without its parsing pinned.
func TestEveryManifestHasAGoldenCase(t *testing.T) {
	set, err := manifest.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	entries, err := os.ReadDir(filepath.Join("testdata", "golden"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".case.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("testdata", "golden", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var c goldenCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		covered[c.Manifest] = true
	}

	var missing []string
	for _, id := range set.IDs() {
		if !covered[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("manifests with no golden case: %s", strings.Join(missing, ", "))
	}
}

package report

import (
	"strings"
	"testing"
	"time"
)

// A report that lists only findings implies the untested remainder of the scope
// was clean. The coverage section must name it.
func TestMarkdownNamesUncoveredAssets(t *testing.T) {
	md := Markdown(Input{
		Title:       "engagement",
		Goal:        "read the flags",
		GeneratedAt: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
		Uncovered: []UncoveredAsset{
			{Kind: "ip", Label: "10.129.176.81"},
			{Kind: "endpoint", Label: "http://10.129.175.35/admin"},
		},
	})
	for _, want := range []string{
		"## Coverage",
		"2 in-scope asset(s) had no recorded exploration activity",
		"`ip` 10.129.176.81",
		"`endpoint` http://10.129.175.35/admin",
		"treat them as untested, not as clean",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q\n%s", want, md)
		}
	}
}

// With a KNOWN-empty result the section still renders, so its absence never
// reads as an unreported failure. A nil slice is "could not be determined" and
// must not reach this wording (see TestMarkdownReportsUnknownCoverage).
func TestMarkdownReportsFullCoverage(t *testing.T) {
	md := Markdown(Input{Title: "engagement", GeneratedAt: time.Now(), Uncovered: []UncoveredAsset{}})
	if !strings.Contains(md, "## Coverage") {
		t.Fatalf("coverage section missing:\n%s", md)
	}
	if !strings.Contains(md, "Every in-scope asset had recorded exploration activity") {
		t.Fatalf("full-coverage wording missing:\n%s", md)
	}
	if strings.Contains(md, "no recorded exploration activity.**") {
		t.Fatalf("gap wording leaked into a fully covered report:\n%s", md)
	}
}

// A failed coverage computation must never read as full coverage.
func TestMarkdownReportsUnknownCoverage(t *testing.T) {
	md := Markdown(Input{Title: "engagement", GeneratedAt: time.Now()})
	if !strings.Contains(md, "## Coverage") {
		t.Fatalf("coverage section missing:\n%s", md)
	}
	if !strings.Contains(md, "could not be determined") {
		t.Fatalf("unknown-coverage wording missing:\n%s", md)
	}
	if strings.Contains(md, "Every in-scope asset had recorded exploration activity") {
		t.Fatalf("unknown coverage claims full coverage:\n%s", md)
	}
	if strings.Contains(md, "had no recorded exploration activity.**") {
		t.Fatalf("unknown coverage claims a gap list:\n%s", md)
	}
}

package evidence

import (
	"context"
	"strings"
	"testing"
)

// The spill decision lives in Record, so this is the test that proves the wiring
// rather than the helper: a large body must land on disk with the row carrying a
// path, and a small body must stay inline so existing readers are unaffected.
func TestRecordSpillsLargeEvidenceAndKeepsSmallInline(t *testing.T) {
	store, in, _ := evidenceFixture(t)

	small := in
	small.Name = "small evidence"
	small.Evidence = "tiny body"
	out, err := store.Record(context.Background(), small, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.DB.GetFinding(out.FindingID)
	if err != nil || got == nil {
		t.Fatalf("GetFinding: %v %v", got, err)
	}
	if got.Evidence != "tiny body" || got.EvidencePath != "" {
		t.Fatalf("small evidence should stay inline: evidence=%q path=%q", got.Evidence, got.EvidencePath)
	}

	large := in
	large.Name = "large evidence"
	large.Evidence = strings.Repeat("B", InlineEvidenceLimit+1024)
	out, err = store.Record(context.Background(), large, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = store.DB.GetFinding(out.FindingID)
	if err != nil || got == nil {
		t.Fatalf("GetFinding: %v %v", got, err)
	}
	if got.EvidencePath == "" {
		t.Fatalf("large evidence was not spilled: evidence has %d bytes inline", len(got.Evidence))
	}
	if got.Evidence != "" {
		t.Fatalf("spilled evidence must not also be stored inline (%d bytes)", len(got.Evidence))
	}
	body, err := store.ReadFindingEvidence(got.EvidencePath)
	if err != nil {
		t.Fatalf("read spilled evidence: %v", err)
	}
	if len(body) != len(large.Evidence) {
		t.Fatalf("spilled body is %d bytes, wrote %d", len(body), len(large.Evidence))
	}
}

package evidence

import (
	"strings"
	"testing"
)

// Content addressing is the property that makes a spilled finding cheap to
// record twice (a retest, a re-import) and gives the filename a second job as
// an integrity check.
func TestWriteFindingEvidenceIsContentAddressed(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	body := strings.Repeat("A", InlineEvidenceLimit*2)

	first, err := store.WriteFindingEvidence(7, body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.WriteFindingEvidence(7, body)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("identical evidence wrote two paths: %q and %q", first, second)
	}
	// The digest is the name, so the path is verifiable without the row.
	if len(first) == 0 || !strings.HasPrefix(first, "findings/7/") {
		t.Fatalf("path %q is not under the task's findings directory", first)
	}

	got, err := store.ReadFindingEvidence(first)
	if err != nil {
		t.Fatal(err)
	}
	if got != body {
		t.Fatalf("read back %d bytes, wrote %d", len(got), len(body))
	}

	// Different content under the same task must not collide.
	other, err := store.WriteFindingEvidence(7, body+"x")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("different content produced the same path")
	}
}

// A path from a tampered row must not read outside the store.
func TestReadFindingEvidenceRejectsEscapes(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	for _, bad := range []string{"../secrets", "../../etc/passwd", "/etc/passwd"} {
		if _, err := store.ReadFindingEvidence(bad); err == nil {
			t.Errorf("ReadFindingEvidence(%q) = nil error, want a rejection", bad)
		}
	}
	if got, err := store.ReadFindingEvidence(""); err != nil || got != "" {
		t.Errorf("empty path should read as empty: %q %v", got, err)
	}
}

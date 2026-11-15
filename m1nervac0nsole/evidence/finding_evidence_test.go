package evidence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// A task's spilled evidence must travel with the task: an archive package keeps
// the proof its findings rows point at, a restore puts it back, and neither
// touches another task's directory.
func TestFindingEvidenceTravelsWithTheTask(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	body := strings.Repeat("B", InlineEvidenceLimit+128)
	rel, err := store.WriteFindingEvidence(11, body)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.WriteFindingEvidence(12, "another task's proof")
	if err != nil {
		t.Fatal(err)
	}

	payload := t.TempDir()
	if err := store.CopyFindingEvidence(11, payload); err != nil {
		t.Fatal(err)
	}
	archived, err := os.ReadFile(filepath.Join(payload, filepath.FromSlash(rel)))
	if err != nil || string(archived) != body {
		t.Fatalf("archive copy: %v (%d bytes)", err, len(archived))
	}
	if _, err := os.Stat(filepath.Join(payload, filepath.FromSlash(other))); !os.IsNotExist(err) {
		t.Fatalf("archive copied another task's evidence: %v", err)
	}

	restored := &Store{Dir: t.TempDir()}
	if err := restored.InstallFindingEvidence(11, payload); err != nil {
		t.Fatal(err)
	}
	if got, err := restored.ReadFindingEvidence(rel); err != nil || got != body {
		t.Fatalf("restored evidence: %v (%d bytes)", err, len(got))
	}
}

// A finding's spilled evidence is referenced from its row, so deleting the row
// (a task delete, or a write whose commit failed) leaves the file behind. GC
// reaps it after the grace period and keeps the evidence of a live finding.
func TestEvidenceGCReapsOrphanedFindingEvidence(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	ctx := context.Background()
	live := in
	live.Name = "kept finding"
	live.Evidence = strings.Repeat("K", InlineEvidenceLimit+64)
	kept, err := s.Record(ctx, live, nil)
	if err != nil {
		t.Fatal(err)
	}
	gone := in
	gone.Name = "deleted finding"
	gone.Evidence = strings.Repeat("G", InlineEvidenceLimit+64)
	dropped, err := s.Record(ctx, gone, nil)
	if err != nil {
		t.Fatal(err)
	}
	droppedRow, err := s.DB.GetFinding(dropped.FindingID)
	if err != nil || droppedRow == nil || droppedRow.EvidencePath == "" {
		t.Fatalf("fixture did not spill: %v %v", droppedRow, err)
	}
	if _, err = s.DB.DeleteFinding(dropped.FindingID); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(s.Dir, filepath.FromSlash(droppedRow.EvidencePath))
	now := time.Now()
	for _, at := range []time.Time{now, now.Add(23 * time.Hour)} {
		if err = s.Collect(ctx, at); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(orphan); err != nil {
			t.Fatalf("GC grace ignored: %v", err)
		}
	}
	if err = s.Collect(ctx, now.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphaned evidence was not collected: %v", err)
	}
	keptRow, err := s.DB.GetFinding(kept.FindingID)
	if err != nil || keptRow == nil {
		t.Fatalf("live finding: %v %v", keptRow, err)
	}
	if got, err := s.ReadFindingEvidence(keptRow.EvidencePath); err != nil || got != live.Evidence {
		t.Fatalf("GC removed referenced evidence: %v (%d bytes)", err, len(got))
	}
}

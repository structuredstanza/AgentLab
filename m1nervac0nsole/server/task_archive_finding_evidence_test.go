package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// A task archive must carry the spilled finding evidence its rows point at. The
// archive deletes the hot row, so the hot file becomes unreferenced and GC reaps
// it; only the package's copy can put the body back on restore.
func TestTaskArchiveCarriesSpilledFindingEvidence(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	s.ctx = ctx
	row, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || row == nil || row.TaskID == nil {
		t.Fatalf("fixture finding: %v %v", row, err)
	}
	task, err := s.m.pg.GetTask(*row.TaskID)
	if err != nil || task == nil {
		t.Fatalf("fixture task: %v %v", task, err)
	}
	body := strings.Repeat("archive me\n", 2000) // above the 8 KiB inline limit
	// Re-recording the same name folds into the row that already carries the
	// bound proof, so the archive's evidence gate still passes.
	if _, err = s.evidenceStore().Record(ctx, db.RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, Worker: "test", VulnClass: "TEST",
		Name: "Evidence API", Severity: "low", Summary: "large proof", Evidence: body,
	}, nil); err != nil {
		t.Fatal(err)
	}
	spilled, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || spilled == nil || spilled.EvidencePath == "" {
		t.Fatalf("fixture did not spill: %v %v", spilled, err)
	}
	if err = s.m.SetTaskPaused(strconv.FormatInt(*row.TaskID, 10), true); err != nil {
		t.Fatal(err)
	}
	job, err := s.m.pg.QueueTaskArchive(*row.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.m.pg.GetFinding(f.FindingID); got != nil {
		t.Fatal("archive retained the hot finding")
	}
	if err = s.evidenceStore().Collect(ctx, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	restored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || restored == nil {
		t.Fatalf("restored finding: %v %v", restored, err)
	}
	if restored.EvidencePath == "" {
		t.Fatal("restored row lost its evidence path")
	}
	got, err := s.evidenceStore().ReadFindingEvidence(restored.EvidencePath)
	if err != nil || got != body {
		t.Fatalf("restored evidence: %v (%d bytes)", err, len(got))
	}
}

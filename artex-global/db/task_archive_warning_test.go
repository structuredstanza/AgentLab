package db

import (
	"encoding/json"
	"testing"
)

// A warning appended while an archive runs must survive completion. The
// completion update used to set warnings='[]', so the growth-guard notice that
// "hot-store compaction was skipped" was written and then silently erased.
func TestArchiveWarningSurvivesCompletion(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { d.Close() })

	var expID, taskID int64
	if err := d.QueryRow(`INSERT INTO explorations (description, goal) VALUES ('p','p') RETURNING id`).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO tasks (name, description, goal, exploration_id) VALUES ('w','','',$1) RETURNING id`, expID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	// CompleteTaskArchive deletes from llm_records, which is created lazily by
	// whoever needs it. Declare the precondition here rather than relying on an
	// earlier test in the package having created the table.
	for _, ensure := range []func() error{d.EnsureLLMRecordsTable, d.EnsureLLMUsageTable} {
		if err := ensure(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`UPDATE tasks SET status='done' WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	job, err := d.QueueTaskArchive(taskID)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_archives WHERE id=$1`, job.ID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	})

	// a claimed job is in the archiving state
	if _, err := d.Exec(`UPDATE task_archives SET state=$2 WHERE id=$1`, job.ID, Archiving); err != nil {
		t.Fatal(err)
	}

	const warning = "traffic captured after the archive snapshot; hot-store compaction skipped"
	if err := d.AppendTaskArchiveWarning(job.ID, warning); err != nil {
		t.Fatal(err)
	}
	snapshot := &TaskArchiveSnapshot{FormatVersion: TaskArchiveFormatVersion, TaskID: taskID, ExplorationID: expID}
	if err := d.CompleteTaskArchive(job.ID, snapshot, "/tmp/x.tar.zst", "sha", 1, 1); err != nil {
		t.Fatalf("complete: %v", err)
	}

	got, err := d.GetTaskArchive(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	var warnings []string
	if err := json.Unmarshal(got.Warnings, &warnings); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0] != warning {
		t.Fatalf("warnings after completion = %v, want the appended warning preserved", warnings)
	}
}

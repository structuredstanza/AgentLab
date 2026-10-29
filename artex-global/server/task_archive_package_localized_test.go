package server

import (
	"os"
	"path/filepath"
	"testing"
)

// task_archive_package.go: Verify the error path returned when the original and the delete-staging temporary file coexist.
//
// Call graph determination (see the errArchiveStagedAndOriginalCoexist constant comment): this error is raised in the background
// archive worker runOneTaskArchiveJob (task_archives.go:102) calls FailTaskArchiveJob with it.
// Stored in the task_archives.error column, and TaskArchivesPanel in tasks/page.tsx displays {archive.error}
// Used only for direct display on screen as user-facing output (actool·planner feedback 0). Along the same propagation path
// (archiveTask·validateArchivePath) are already in Korean, so this translation is consistent with them.
//
// stageTaskArchivePackageDelete is a pure file function that does not touch the DB, so on this host without a DB
// it can create both the original file and the delete temp file (.deleting-N) at once to actually drive the real contradictory branch.
func TestTaskArchiveStagedAndOriginalCoexistError(t *testing.T) {
	dataDir := t.TempDir()
	archivePath := taskArchivePath(dataDir, 21, "42")
	if err := os.MkdirAll(filepath.Dir(archivePath), archiveDirMode); err != nil {
		t.Fatal(err)
	}
	// Creates the contradictory state where both the original archive package and the delete temp file exist.
	if err := os.WriteFile(archivePath, []byte("original"), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	staged := archivePath + ".deleting-21"
	if err := os.WriteFile(staged, []byte("archive"), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	_, moved, err := stageTaskArchivePackageDelete(archivePath, 21)
	if err == nil {
		t.Fatalf("an error must be returned when the original and the staged delete file coexist (moved=%v)", moved)
	}
	if moved {
		t.Fatal("moved must not be true in the coexisting contradiction state")
	}
}

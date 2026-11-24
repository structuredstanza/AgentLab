package server

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTaskArchiveStagedAndOriginalCoexistError exercises the conflicting file
// state directly, without running the archive worker or accessing the database.
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

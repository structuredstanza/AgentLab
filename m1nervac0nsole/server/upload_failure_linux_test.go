package server

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestChatUploadCopyFailureRemovesOnlyItsReservation(t *testing.T) {
	const childEnv = "M1NERVAC0NSOLE_TEST_UPLOAD_FILE_LIMIT"
	if os.Getenv(childEnv) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestChatUploadCopyFailureRemovesOnlyItsReservation$")
		// No database is used here; do not contend for the parent suite's advisory lock.
		cmd.Env = append(os.Environ(), childEnv+"=1", "M1NERVAC0NSOLE_PG_DSN=host="+filepath.Join(t.TempDir(), "no-postgres")+" dbname=unused sslmode=disable")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated filesystem-failure scenario: %v\n%s", err, out)
		}
		return
	}

	work := t.TempDir()
	dir := filepath.Join(work, "sessions", "s1", "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(original, []byte("original attachment"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := workspaceUploadRequest(t, "/?scope=session&id=s1", "sample.txt", "replacement payload")
	s := &Server{m: &Manager{dir: work}}

	// Limit only this child: a real short write must not publish attachment metadata.
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 1, Max: 1}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.chatUpload(response, request)
	if response.Code != 500 {
		t.Fatalf("failed copy was reported as successful: %d %s", response.Code, response.Body.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "sample.txt" {
		t.Fatalf("failed reservation remained or replaced an existing file: %v", entries)
	}
	data, err := os.ReadFile(original)
	if err != nil || string(data) != "original attachment" {
		t.Fatalf("existing attachment changed: %q %v", data, err)
	}
}

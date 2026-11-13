package server

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReserveUploadReturnsNonCollisionErrors(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	result := make(chan error, 1)
	go func() {
		file, _, err := reserveUpload(root, "missing-parent", "file.txt")
		if file != nil {
			_ = file.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing parent did not return its filesystem error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reservation kept retrying a non-collision error")
	}
}

type uploadCloseAtEOF struct {
	io.Reader
	file *os.File
}

func (reader uploadCloseAtEOF) Read(buf []byte) (int, error) {
	n, err := reader.Reader.Read(buf)
	if err == io.EOF {
		_ = reader.file.Close()
	}
	return n, err
}

func TestSaveUploadReturnsDestinationCloseFailure(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "close-error.txt"))
	if err != nil {
		t.Fatal(err)
	}
	src := io.NopCloser(uploadCloseAtEOF{Reader: strings.NewReader("payload"), file: file})
	if err := saveUpload(src, file, 7); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("destination close failure was ignored: %v", err)
	}
}

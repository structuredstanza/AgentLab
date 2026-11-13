package mcp

import (
	"context"
	"strings"
	"testing"
)

// A server that dies during the handshake must say why: the parent only sees
// "connection closed", so the child's stderr is the whole diagnosis.
func TestStdioClientReportsChildStderr(t *testing.T) {
	_, err := NewStdioClient(context.Background(), "boom", "sh", nil,
		"-c", "echo 'Error: Cannot find module @playwright/mcp' >&2; exit 3")
	if err == nil {
		t.Fatal("expected a handshake error")
	}
	if !strings.Contains(err.Error(), "Cannot find module") {
		t.Fatalf("error %q does not carry the child's stderr", err)
	}
}

func TestTailBufferKeepsTheTail(t *testing.T) {
	var b tailBuffer
	for i := 0; i < 1000; i++ {
		b.Write([]byte("0123456789"))
	}
	got := b.String()
	if len(got) > maxTail {
		t.Fatalf("buffer kept %d bytes, want at most %d", len(got), maxTail)
	}
	if !strings.HasSuffix(got, "0123456789") {
		t.Fatalf("buffer lost the tail: %q", got[len(got)-20:])
	}
}

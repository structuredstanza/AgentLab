package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/privacy"
)

func captureSegments(t *testing.T, root string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "captures", "native-sse-*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func captureText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Bounded, immutable segments are what let an export copy the stream whole and
// `lab prune` delete what it captured: the active file must never grow past one
// segment, and a restart must not append to a segment an export already copied.
func TestCaptureStoreRotatesIntoImmutableSegments(t *testing.T) {
	root := t.TempDir()
	captures, err := newCaptureStore(root)
	if err != nil {
		t.Fatal(err)
	}
	captures.limit = 1
	record := func(store *captureStore, model string) {
		t.Helper()
		if err := store.Record(privacy.Record{
			Direction: privacy.DirectionRequest, Provider: contract.ProviderClaude,
			Model: model, Profile: "1", SessionID: "session", Body: []byte(model),
		}); err != nil {
			t.Fatal(err)
		}
	}
	record(captures, "first")
	record(captures, "second")
	active := filepath.Join(root, "captures", "native-sse.ndjson")
	if got := captureText(t, active); strings.Contains(got, "first") || !strings.Contains(got, "second") {
		t.Fatalf("active stream = %q; a full segment was not rotated away", got)
	}
	segments := captureSegments(t, root)
	if len(segments) != 1 {
		t.Fatalf("segments = %v; want exactly one", segments)
	}
	if got := captureText(t, segments[0]); !strings.Contains(got, "first") || strings.Contains(got, "second") {
		t.Fatalf("segment = %q; it must hold only the rotated records", got)
	}
	if err := captures.file.Close(); err != nil {
		t.Fatal(err)
	}
	// A restart rotates the previous run's stream instead of appending to it.
	restarted, err := newCaptureStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.file.Close() })
	if got := captureText(t, active); got != "" {
		t.Fatalf("active stream after restart = %q; want a fresh segment", got)
	}
	after := captureSegments(t, root)
	if len(after) != 2 {
		t.Fatalf("segments after restart = %v; want two", after)
	}
	rotated := captureText(t, after[0]) + captureText(t, after[1])
	if !strings.Contains(rotated, "first") || !strings.Contains(rotated, "second") {
		t.Fatalf("segments after restart = %q; the previous run's records were lost", rotated)
	}
	record(restarted, "third")
	if got := captureText(t, active); !strings.Contains(got, "third") || strings.Contains(got, "second") {
		t.Fatalf("active stream = %q; a restart appended to an exported segment", got)
	}
	if got := captureSegments(t, root); len(got) != 2 {
		t.Fatalf("segments = %v; rotation must not rewrite closed segments", got)
	}
	for _, segment := range after {
		if got := captureText(t, segment); strings.Contains(got, "third") {
			t.Fatalf("segment %s = %q; a closed segment was appended to", segment, got)
		}
	}
}

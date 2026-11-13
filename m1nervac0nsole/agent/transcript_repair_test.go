package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/norma/transcript"
)

// A crash can leave the last transcript record half-written. Resume rejects the
// whole file, and the session id is deterministic per intent, so without repair
// the intent can never run again.
func TestRepairTranscriptDropsOnlyThePartialTail(t *testing.T) {
	dir := t.TempDir()
	store := transcript.NewStore(dir)
	const sid = "intent-1"
	path := store.MainPath(sid)

	good := `{"a":1}` + "\n" + `{"a":2}` + "\n"
	if err := os.WriteFile(path, []byte(good+`{"a":3,"trunc`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := repairTranscript(store, sid); err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != good {
		t.Fatalf("after repair: %q, want the complete records only: %q", got, good)
	}

	// A second pass must be a no-op rather than an error: the file now ends on
	// a record boundary, and repair is only called after a failed Resume.
	if err := repairTranscript(store, sid); err == nil {
		t.Fatal("a clean transcript should report that there is nothing to drop")
	}
}

// A file whose damage is not a trailing fragment is moved aside, not deleted:
// it is the only record of what the intent already did.
func TestQuarantineTranscriptKeepsTheOriginal(t *testing.T) {
	dir := t.TempDir()
	store := transcript.NewStore(dir)
	const sid = "intent-2"
	path := store.MainPath(sid)
	content := `{"broken":` + "\n" + "not-json\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := quarantineTranscript(store, sid); err != nil {
		t.Fatalf("quarantine failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the transcript is still in place (stat err=%v)", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var kept string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), sid+".jsonl.corrupt-") {
			kept = filepath.Join(dir, e.Name())
		}
	}
	if kept == "" {
		t.Fatalf("no quarantined copy was kept: %v", entries)
	}
	got, err := os.ReadFile(kept)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("quarantined copy = %q, want the original bytes %q", got, content)
	}

	// A missing transcript is not an error: nothing to move aside.
	if err := quarantineTranscript(store, "absent"); err != nil {
		t.Fatalf("quarantining a missing transcript failed: %v", err)
	}
}

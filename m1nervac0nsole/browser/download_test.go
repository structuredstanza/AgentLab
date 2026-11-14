package browser

import (
	"path/filepath"
	"testing"
)

// A finished download is reported once, with the path the agent can read.
func TestDownloadsReportCompletedOnce(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	dir := t.TempDir()
	d.mu.Lock()
	d.downloadDir = dir
	d.mu.Unlock()

	f.emit("Browser.downloadWillBegin", map[string]any{
		"guid":              "d1",
		"suggestedFilename": "export.csv",
		"url":               "https://target.test/export.csv",
	})
	f.emit("Browser.downloadProgress", map[string]any{
		"guid":  "d1",
		"state": "completed",
	})

	got := d.Downloads()
	want := filepath.Join(dir, "export.csv")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("downloads = %v, want [%s]", got, want)
	}
	if again := d.Downloads(); len(again) != 0 {
		t.Fatalf("second drain = %v, want empty", again)
	}
}

// A cancelled download leaves no file and no report.
func TestDownloadsIgnoreCancelled(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.downloadDir = t.TempDir()
	d.mu.Unlock()

	f.emit("Browser.downloadWillBegin", map[string]any{
		"guid":              "d1",
		"suggestedFilename": "export.csv",
	})
	f.emit("Browser.downloadProgress", map[string]any{
		"guid":  "d1",
		"state": "canceled",
	})
	if got := d.Downloads(); len(got) != 0 {
		t.Fatalf("downloads = %v, want none", got)
	}
}

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestReportFindingScreenshots covers the screenshot_paths contract: a valid
// browser_screenshot path is stored and returned, and every bad path refuses the
// whole report (naming the path) instead of writing a row.
func TestReportFindingScreenshots(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("screenshot evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	other, err := d.CreateTask("other task", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(other.ID)

	dir := t.TempDir()
	taskID := strconv.FormatInt(task.ID, 10)
	shots := filepath.Join(dir, "tasks", taskID, "screenshots")
	if err := os.MkdirAll(filepath.Join(shots, "dir.png"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shots, "shot.png"), []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	big, err := os.Create(filepath.Join(shots, "big.png"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(maxFindingScreenshotBytes + 1); err != nil {
		t.Fatal(err)
	}
	big.Close()

	ts := NewToolSet(nil, "fixture")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.SetWorkDir(dir)

	prefix := "tasks/" + taskID + "/screenshots/"
	good := prefix + "shot.png"
	report := func(paths []string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"vulnclass": "TEST", "severity": "low", "summary": "screenshot fixture", "screenshot_paths": paths,
		})
		res, err := ts.addFinding().Call(t.Context(), body, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	count := func() int {
		t.Helper()
		_, total, err := d.ListFindingsPage(db.FindingFilter{TaskID: taskID}, 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		return total
	}

	for _, tc := range []struct{ name, path string }{
		{"parent traversal", prefix + "../shot.png"},
		{"absolute", "/etc/passwd"},
		{"missing", prefix + "missing.png"},
		{"directory", prefix + "dir.png"},
		{"other task", "tasks/" + strconv.FormatInt(other.ID, 10) + "/screenshots/shot.png"},
		{"oversized", prefix + "big.png"},
	} {
		out := report([]string{good, tc.path})
		if strings.HasPrefix(out, "finding recorded: ") {
			t.Fatalf("%s: accepted %q: %s", tc.name, tc.path, out)
		}
		if !strings.Contains(out, tc.path) {
			t.Fatalf("%s: refusal does not name %q: %s", tc.name, tc.path, out)
		}
		if n := count(); n != 0 {
			t.Fatalf("%s: refusal wrote %d finding(s)", tc.name, n)
		}
	}

	eleven := make([]string, maxFindingScreenshots+1)
	for i := range eleven {
		eleven[i] = good
	}
	if out := report(eleven); strings.HasPrefix(out, "finding recorded: ") {
		t.Fatalf("accepted %d paths: %s", len(eleven), out)
	}

	out := report([]string{good})
	if !strings.HasPrefix(out, "finding recorded: ") {
		t.Fatalf("valid screenshot refused: %s", out)
	}
	var recorded db.RecordedFinding
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[1]), &recorded); err != nil {
		t.Fatal(err)
	}
	f, err := d.GetFinding(recorded.FindingID)
	if err != nil || f == nil {
		t.Fatalf("finding missing: %v", err)
	}
	if len(f.Screenshots) != 1 || f.Screenshots[0] != good {
		t.Fatalf("screenshots = %v, want [%s]", f.Screenshots, good)
	}
}

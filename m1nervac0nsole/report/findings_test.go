package report

import (
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// A finding recorded with screenshots names them under the same Evidence
// section, and a text-only finding keeps its previous rendering.
func TestSingleFindingMarkdownNamesScreenshots(t *testing.T) {
	withShot := SingleFindingMarkdown(&db.DBFinding{
		Severity: "high", Name: "Stored XSS", Summary: "payload persisted",
		Evidence:    "POST /comment returned 200",
		Screenshots: []string{"tasks/7/screenshots/shot.png"},
	}, time.Unix(0, 0))
	if !strings.Contains(withShot, "## Evidence") || !strings.Contains(withShot, "tasks/7/screenshots/shot.png") {
		t.Fatalf("screenshot missing:\n%s", withShot)
	}

	plain := SingleFindingMarkdown(&db.DBFinding{
		Severity: "high", Name: "Stored XSS", Evidence: "POST /comment returned 200",
	}, time.Unix(0, 0))
	if strings.Count(plain, "## Evidence") != 1 || strings.Contains(plain, "Screenshot:") {
		t.Fatalf("text-only evidence changed:\n%s", plain)
	}
}

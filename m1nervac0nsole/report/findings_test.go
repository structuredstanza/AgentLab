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

// The CSV is opened in a spreadsheet, and every string cell can come from an
// agent or a target: a leading formula character must be neutralised, and an
// ordinary cell must be left alone.
func TestFindingsCSVNeutralisesFormulaCells(t *testing.T) {
	out := string(FindingsCSV([]*db.DBFinding{{
		ID: 7, Name: "=cmd|'/c calc'!A1", VulnClass: "+SUM(1)", Severity: "high",
		Status: "confirmed", TaskDescription: "@import", Summary: "-2+3",
	}}))
	for _, want := range []string{"'=cmd", "'+SUM(1)", "'@import", "'-2+3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("cell %q was not neutralised:\n%s", want, out)
		}
	}
	if strings.Contains(out, "'high") || strings.Contains(out, "'7") {
		t.Fatalf("a plain cell was prefixed:\n%s", out)
	}
}

// A severity stored in mixed case must not take the zero value of a missing map
// key: "High" is not "critical", and the summary counts it as high.
func TestFindingsMarkdownSortsSeverityCaseInsensitively(t *testing.T) {
	md := FindingsMarkdown([]*db.DBFinding{
		{ID: 1, Name: "mixed case high", Severity: "High", CreatedAt: time.Unix(200, 0)},
		{ID: 2, Name: "critical finding", Severity: "critical", CreatedAt: time.Unix(100, 0)},
	}, time.Unix(300, 0))
	critical, high := strings.Index(md, "### 1. [CRITICAL] critical finding"), strings.Index(md, "### 2. [HIGH] mixed case high")
	if critical < 0 || high < 0 || critical > high {
		t.Fatalf("mixed-case severity sorted as critical:\n%s", md)
	}
	if !strings.Contains(md, "| High | 1 |") {
		t.Fatalf("mixed-case severity was not counted:\n%s", md)
	}
}

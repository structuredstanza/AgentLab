package db

import (
	"context"
	"testing"
)

// A finding recorded twice is one row, not two: the planner and the workers
// converge on the same vulnerability from different intents, and a second row
// inflates the report and splits the evidence between them.
func TestRecordFindingFoldsARepeat(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task := memoryTask(t, d)
	expID := task.ExplorationID
	es := d.Exploration(expID)

	first, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "sqli", Name: "Login form SQL injection",
		Severity: SeverityHigh, Summary: "the login form is injectable", Evidence: "poc one", Worker: "worker-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created {
		t.Fatal("the first record did not report itself as created")
	}

	// The same finding, different case and different proof.
	second, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "sqli", Name: "login form sql injection",
		Severity: SeverityCritical, Summary: "confirmed with a UNION payload", Evidence: "poc two", Worker: "worker-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Created {
		t.Fatal("the repeat reported itself as a new finding")
	}
	if second.FindingID != first.FindingID {
		t.Fatalf("repeat created finding %d, want %d", second.FindingID, first.FindingID)
	}

	var n int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND lower(name)='login form sql injection'`, task.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d rows for one finding", n)
	}

	// The row carries the newest observation, but the evidence version stays 0:
	// it counts bound traffic, and a text change is not proof.
	var severity, summary, evidence string
	var version int
	if err := d.QueryRow(`SELECT severity, summary, evidence, evidence_version FROM findings WHERE id=$1`, first.FindingID).
		Scan(&severity, &summary, &evidence, &version); err != nil {
		t.Fatal(err)
	}
	if severity != SeverityCritical || summary != "confirmed with a UNION payload" || evidence != "poc two" {
		t.Fatalf("row not refreshed: severity=%q summary=%q evidence=%q", severity, summary, evidence)
	}
	if version != 0 {
		t.Fatalf("evidence_version = %d after a text-only refresh, want 0 (the archive gate reads 0 as no bound proof)", version)
	}

	// A repeat never moves it either.
	if _, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "sqli", Name: "Login form SQL injection",
		Severity: SeverityCritical, Summary: "same proof again", Evidence: "poc two", Worker: "worker-c",
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1`, first.FindingID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("evidence_version = %d after an identical repeat, want 0", version)
	}
}

// A human's disposition outlives a re-observation: folding must never reopen a
// finding someone marked false positive or resolved.
func TestRecordFindingKeepsTheHumanStatus(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task := memoryTask(t, d)
	expID := task.ExplorationID
	es := d.Exploration(expID)

	first, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "xss", Name: "Stored XSS in the profile",
		Severity: SeverityHigh, Summary: "s", Evidence: "e", Worker: "w",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE findings SET status='false_positive' WHERE id=$1`, first.FindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "xss", Name: "stored xss in the profile",
		Severity: SeverityHigh, Summary: "s2", Evidence: "e2", Worker: "w2",
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := d.QueryRow(`SELECT status FROM findings WHERE id=$1`, first.FindingID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "false_positive" {
		t.Fatalf("status = %q after a repeat, want false_positive", status)
	}
}

// An unnamed finding is not an identity: two findings without a name must stay
// two rows, or every unnamed record would collapse into the first.
func TestRecordFindingDoesNotFoldUnnamedFindings(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task := memoryTask(t, d)
	expID := task.ExplorationID
	es := d.Exploration(expID)

	a, err := es.RecordFinding(context.Background(), RecordFindingInput{TaskID: task.ID, ExplorationID: expID, VulnClass: "info", Severity: SeverityLow, Summary: "one"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := es.RecordFinding(context.Background(), RecordFindingInput{TaskID: task.ID, ExplorationID: expID, VulnClass: "info", Severity: SeverityLow, Summary: "two"})
	if err != nil {
		t.Fatal(err)
	}
	if a.FindingID == b.FindingID {
		t.Fatal("two unnamed findings collapsed into one row")
	}
}

// The asset set is part of a finding's identity: the same vulnerability on two
// hosts is two findings, and folding them would merge the evidence of one host
// into the other.
func TestRecordFindingKeepsTheSameNameOnDifferentAssets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task := memoryTask(t, d)
	expID := task.ExplorationID
	es := d.Exploration(expID)

	a := seedTreeAsset(t, d, "ip", map[string]any{"ip": "10.0.0.1"})
	b := seedTreeAsset(t, d, "ip", map[string]any{"ip": "10.0.0.2"})
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, a, b) })

	first, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "xss", Name: "Reflected XSS",
		Severity: SeverityHigh, Summary: "on the first host", Evidence: "e1", Worker: "w", AssetIDs: []int64{a},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "xss", Name: "Reflected XSS",
		Severity: SeverityHigh, Summary: "on the second host", Evidence: "e2", Worker: "w", AssetIDs: []int64{b},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.FindingID == second.FindingID {
		t.Fatal("the same name on two assets folded into one finding")
	}

	// The order of the asset list must not change the identity.
	both, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "xss", Name: "Reflected XSS",
		Severity: SeverityCritical, Summary: "on both hosts", Evidence: "e3", Worker: "w", AssetIDs: []int64{a, b},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !both.Created {
		t.Fatal("the first record of the pair was not created")
	}
	again, err := es.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: expID, VulnClass: "xss", Name: "Reflected XSS",
		Severity: SeverityCritical, Summary: "on both hosts, reordered", Evidence: "e4", Worker: "w", AssetIDs: []int64{b, a},
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.FindingID != both.FindingID {
		t.Fatalf("the asset order changed the identity: created=%v id=%d want %d", again.Created, again.FindingID, both.FindingID)
	}
}

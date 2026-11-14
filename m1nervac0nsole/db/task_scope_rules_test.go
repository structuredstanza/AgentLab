package db

import (
	"fmt"
	"testing"
)

// A rule is the operator's explicit layer: it decides for the hosts it matches,
// and the accumulated task_scope rows decide only when no rule matches.
func TestTaskScopeRulesTakePrecedenceOverRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rules", "operator rules outrank accumulated rows", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	apex := fmt.Sprintf("rules-%d.invalid", task.ID)
	host := "api." + apex

	// A broad row excludes the whole root domain.
	if _, err := assets.AddAgentScope(task.ID, "root_domain", apex, "vendor", "manual", "exclude"); err != nil {
		t.Fatal(err)
	}
	checker := NewTaskScopeChecker(assets, task.ID)
	if out, _ := checker.Judge(host); !out {
		t.Fatal("the row's exclusion did not refuse the host")
	}

	// The operator then writes a rule that includes one host inside it.
	if _, err := assets.AddTaskScopeRule(task.ID, "include", host, "this one is ours"); err != nil {
		t.Fatal(err)
	}
	if out, reason := checker.Judge(host); out {
		t.Fatalf("the rule did not outrank the row: %s", reason)
	}
	// The rest of the root domain is still excluded by the row.
	if out, _ := checker.Judge("other." + apex); !out {
		t.Fatal("the row stopped applying to hosts no rule names")
	}
}

// Within the rule layer the scope package's semantics hold, so a rule cannot
// rescue a host another rule excludes.
func TestTaskScopeRuleExclusionBeatsRuleInclude(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rules conflict", "an excluding rule wins", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	host := fmt.Sprintf("both-%d.invalid", task.ID)
	if _, err := assets.AddTaskScopeRule(task.ID, "include", host, "in"); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.AddTaskScopeRule(task.ID, "exclude", host, "out"); err != nil {
		t.Fatal(err)
	}
	checker := NewTaskScopeChecker(assets, task.ID)
	if out, reason := checker.Judge(host); !out {
		t.Fatalf("an include rescued a host another rule excludes: %s", reason)
	}
}

// A task with no rules keeps the old behaviour exactly: rows decide, and an
// empty boundary blocks nothing.
func TestTaskScopeRulesAbsentKeepsRowBehaviour(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rules empty", "no rules means rows decide", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	checker := NewTaskScopeChecker(assets, task.ID)
	if out, _ := checker.Judge("anything.invalid"); out {
		t.Fatal("an empty boundary blocked a host")
	}
	if _, err := assets.AddTaskScopeRule(task.ID, "exclude", "blocked.invalid", "no"); err != nil {
		t.Fatal(err)
	}
	if out, _ := checker.Judge("blocked.invalid"); !out {
		t.Fatal("the rule did not block its host")
	}
	if out, _ := checker.Judge("allowed.invalid"); out {
		t.Fatal("a non-matching host was blocked")
	}
}

func TestTaskScopeRuleValidation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rule validation", "reject bad rules", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	assets := d.Assets()

	if _, err := assets.AddTaskScopeRule(task.ID, "maybe", "x.invalid", ""); err == nil {
		t.Fatal("an unknown effect was accepted")
	}
	if _, err := assets.AddTaskScopeRule(task.ID, "include", "", ""); err == nil {
		t.Fatal("an empty pattern was accepted")
	}
	id, err := assets.AddTaskScopeRule(task.ID, "exclude", "gone.invalid", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.DeleteTaskScopeRule(task.ID, id); err != nil {
		t.Fatal(err)
	}
	if err := assets.DeleteTaskScopeRule(task.ID, id); err == nil {
		t.Fatal("deleting a missing rule succeeded")
	}
}

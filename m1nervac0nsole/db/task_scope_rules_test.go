package db

import (
	"fmt"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
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

// A rule written on a parent engagement binds the child it spawned, exactly as
// an inherited scope row does: otherwise a worker on the child can reach a host
// the parent explicitly ruled out.
func TestTaskScopeRulesAreInheritedFromSourceTasks(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	parent, err := d.CreateTask("scope rules parent", "parent engagement", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(parent.ID) })
	child, err := d.CreateTask("scope rules child", "child engagement", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(child.ID) })
	if _, err := d.Exec(`INSERT INTO task_relations(task_id, source_task_id) VALUES ($1,$2)`, child.ID, parent.ID); err != nil {
		t.Fatal(err)
	}

	assets := d.Assets()
	if _, err := assets.AddTaskScopeRule(parent.ID, "exclude", "parent-blocked.invalid", "parent ruled it out"); err != nil {
		t.Fatal(err)
	}
	checker := NewTaskScopeChecker(assets, child.ID)
	if out, _ := checker.Judge("parent-blocked.invalid"); !out {
		t.Fatal("the child did not inherit the parent's rule")
	}
	if out, _ := checker.Judge("unrelated.invalid"); out {
		t.Fatal("an unrelated host was blocked")
	}
}

// The scope-rule list is the operator's view of the rows the gateway judges, so
// it carries the fields that decide a grant: the protocol, the ports (always an
// array, never null), and whether the row is authorized.
func TestTaskScopeRuleRowsCarryAuthorization(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rule rows", "list the policy fields", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	id, err := assets.AddTaskScopeRule(task.ID, "include", "api.example.com", "ours")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := assets.ListTaskScopeRuleRows(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one", rows)
	}
	r := rows[0]
	if r.Authorized {
		t.Fatal("a written rule is a grant before the operator approves it")
	}
	if r.Protocol != "any" {
		t.Fatalf("protocol = %q, want any", r.Protocol)
	}
	if r.Ports == nil || len(r.Ports) != 0 {
		t.Fatalf("ports = %v, want an empty array", r.Ports)
	}

	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, id, true, OperatorActor); err != nil {
		t.Fatal(err)
	}
	rows, err = assets.ListTaskScopeRuleRows(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].Authorized {
		t.Fatalf("rows = %+v, want the approved rule authorized", rows)
	}
}

// An approval names one boundary line. Editing the effect or the pattern makes
// it a different line, so the rule drops back to unauthorized and the gateway
// stops honoring it until the operator approves it again.
func TestTaskScopeRuleUpdateResetsAuthorization(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rule reset", "an edited grant is not a grant", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	id, err := assets.AddTaskScopeRule(task.ID, "include", "api.example.com", "ours")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, id, true, OperatorActor); err != nil {
		t.Fatal(err)
	}
	s := netpolicy.Session{ID: "scope-rule-reset", TaskID: task.ID, Purpose: netpolicy.PurposeTesting}
	dest := netpolicy.Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"}
	decide := func() (netpolicy.Decision, netpolicy.State) {
		t.Helper()
		st, err := d.PolicyState(t.Context(), s)
		if err != nil {
			t.Fatal(err)
		}
		return netpolicy.Decide(s.Purpose, st, dest, nil), st
	}

	if dec, _ := decide(); !dec.Allow {
		t.Fatalf("the approved rule denied the destination: %s", dec.Reason)
	}

	// A note-only edit keeps the approval: the line an operator approved is the
	// same line.
	if err := assets.UpdateTaskScopeRule(task.ID, id, "include", "api.example.com", "still ours"); err != nil {
		t.Fatal(err)
	}
	if dec, _ := decide(); !dec.Allow {
		t.Fatalf("a note-only edit dropped the approval: %s", dec.Reason)
	}

	// A new pattern drops it.
	if err := assets.UpdateTaskScopeRule(task.ID, id, "include", "api.other.example", "moved"); err != nil {
		t.Fatal(err)
	}
	dec, st := decide()
	if len(st.Rules) != 1 || st.Rules[0].Authorized {
		t.Fatalf("rules = %+v, want the edited rule unauthorized", st.Rules)
	}
	if dec.Allow {
		t.Fatalf("the edited rule still allowed the old destination: %s", dec.Reason)
	}

	// A new effect drops it too.
	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, id, true, OperatorActor); err != nil {
		t.Fatal(err)
	}
	if err := assets.UpdateTaskScopeRule(task.ID, id, "exclude", "api.other.example", "moved"); err != nil {
		t.Fatal(err)
	}
	_, st = decide()
	if len(st.Rules) != 1 || st.Rules[0].Authorized {
		t.Fatalf("rules = %+v, want the effect edit unauthorized", st.Rules)
	}
}

// Every write through the console's scope-rule routes records the same audit row
// the policy accessors write and moves the task's policy revision, so the trail
// and the invalidation cannot tell the two writers apart.
func TestTaskScopeRuleWritesPolicyAudit(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope rule audit", "one writer, one audit trail", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	rev := policyRevision(t, d, task.ID)
	step := func(name string) {
		t.Helper()
		got := policyRevision(t, d, task.ID)
		if got != rev+1 {
			t.Fatalf("%s: revision = %d, want %d", name, got, rev+1)
		}
		rev = got
	}

	id, err := assets.AddTaskScopeRule(task.ID, "exclude", "blocked.invalid", "vendor")
	if err != nil {
		t.Fatal(err)
	}
	step("add scope rule")

	if err := assets.UpdateTaskScopeRule(task.ID, id, "exclude", "blocked.invalid", "vendor, narrowed"); err != nil {
		t.Fatal(err)
	}
	step("update scope rule")

	if err := assets.DeleteTaskScopeRule(task.ID, id); err != nil {
		t.Fatal(err)
	}
	step("delete scope rule")

	want := []string{"rule.add", "rule.update", "rule.delete"}
	actions := policyAuditActions(t, d, task.ID)
	if len(actions) != len(want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("audit actions = %v, want %v", actions, want)
		}
	}
}

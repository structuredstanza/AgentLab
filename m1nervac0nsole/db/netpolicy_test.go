package db

import (
	"errors"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// openPolicyDB opens the configured database (skipping when none is reachable).
func openPolicyDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func policyRevision(t *testing.T, d *DB, taskID int64) int64 {
	t.Helper()
	var rev int64
	if err := d.QueryRow(`SELECT policy_revision FROM tasks WHERE id=$1`, taskID).Scan(&rev); err != nil {
		t.Fatalf("read policy revision: %v", err)
	}
	return rev
}

// policyAuditActions lists the audit rows written for one task, in order.
func policyAuditActions(t *testing.T, d *DB, taskID int64) []string {
	t.Helper()
	rows, err := d.Query(`SELECT action FROM policy_audit WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		t.Fatalf("read policy audit: %v", err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatalf("scan policy audit: %v", err)
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read policy audit: %v", err)
	}
	return actions
}

// The migration is additive and idempotent: a second pass changes nothing, and a
// row written before it keeps its meaning and stays non-authorizing.
func TestPolicySchemaMigrationIsIdempotent(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("policy migration", "prove the migration is additive", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	// A rule written the way the pre-migration code wrote it: no policy columns.
	var ruleID int64
	if err := d.QueryRow(`INSERT INTO task_scope_rules(task_id, effect, pattern, note)
VALUES ($1,'include','legacy.example','written before the migration') RETURNING id`, task.ID).Scan(&ruleID); err != nil {
		t.Fatal(err)
	}

	conn, err := d.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for pass := 1; pass <= 2; pass++ {
		if err := applySchemaWithRetry(t.Context(), conn, func(time.Duration) {}); err != nil {
			t.Fatalf("schema pass %d: %v", pass, err)
		}
	}

	var (
		authorized bool
		protocol   string
		ports      string
		note       string
	)
	if err := d.QueryRow(`SELECT authorized, protocol, COALESCE(array_to_json(ports)::text,'[]'), note
FROM task_scope_rules WHERE id=$1`, ruleID).Scan(&authorized, &protocol, &ports, &note); err != nil {
		t.Fatalf("the legacy rule did not survive the migration: %v", err)
	}
	if authorized {
		t.Fatal("a pre-migration rule must not become authorization")
	}
	if protocol != "any" || ports != "[]" || note != "written before the migration" {
		t.Fatalf("legacy rule = authorized=%v protocol=%q ports=%s note=%q", authorized, protocol, ports, note)
	}

	var columns int
	if err := d.QueryRow(`SELECT count(*) FROM information_schema.columns
WHERE table_name='task_scope_rules'
  AND column_name IN ('protocol','ports','authorized','approved_by','approved_at')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 5 {
		t.Fatalf("task_scope_rules has %d of the 5 policy columns", columns)
	}
	var tables int
	if err := d.QueryRow(`SELECT count(*) FROM information_schema.tables
WHERE table_name IN ('cert_exceptions','policy_audit')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 2 {
		t.Fatalf("found %d of the 2 policy tables", tables)
	}
	var triggers int
	if err := d.QueryRow(`SELECT count(*) FROM pg_trigger
WHERE tgname IN ('trg_task_scope_rules_policy','trg_cert_exceptions_policy','trg_task_scope_policy')`).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != 3 {
		t.Fatalf("found %d of the 3 revision triggers", triggers)
	}
	if rev := policyRevision(t, d, task.ID); rev <= 0 {
		t.Fatalf("policy_revision = %d after the rule insert, want it bumped", rev)
	}
}

// Every change to what a task may reach moves its revision exactly once, so a
// cached verdict or a pooled connection issued under the old revision is never
// trusted again.
func TestPolicyRevisionBumpsOnEveryChange(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("policy revision", "prove the revision moves", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	rev := policyRevision(t, d, task.ID)

	step := func(name string) {
		t.Helper()
		got := policyRevision(t, d, task.ID)
		if got != rev+1 {
			t.Fatalf("%s: revision = %d, want %d", name, got, rev+1)
		}
		rev = got
	}

	ruleID, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: "api.example.com", Protocol: "http", Ports: []int{443},
	}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	step("add rule")

	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, ruleID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	step("authorize rule")

	if err := d.AddCertException(t.Context(), task.ID, "self-signed.example:443", "lab target", nil, "operator"); err != nil {
		t.Fatal(err)
	}
	step("add cert exception")

	var scopeID int64
	if err := d.QueryRow(`INSERT INTO task_scope(task_id, kind, domain, source, effect)
VALUES ($1,'subdomain','scoped.example','manual','include') RETURNING id`, task.ID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	step("insert task scope row")

	if _, err := d.Exec(`DELETE FROM task_scope WHERE id=$1`, scopeID); err != nil {
		t.Fatal(err)
	}
	step("delete task scope row")

	want := []string{"rule.add", "rule.authorize", "cert.exception"}
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

// A task whose rules are only written, never approved, is denied: the migration
// does not promote anything, and neither does writing a rule.
func TestPolicyStateFailClosedWithoutAuthorizedRules(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("policy fail closed", "prove an unauthorized rule denies", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	s := netpolicy.Session{ID: "policy-test", TaskID: task.ID, Purpose: netpolicy.PurposeTesting}
	dest := netpolicy.Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"}

	// A fresh task has no rules at all, and that is already a refusal.
	st, err := d.PolicyState(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Rules) != 0 {
		t.Fatalf("a fresh task has %d rules", len(st.Rules))
	}
	if dec := netpolicy.Decide(s.Purpose, st, dest, nil); dec.Allow {
		t.Fatalf("a task with no rules allowed the destination: %s", dec.Reason)
	}

	ruleID, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: "api.example.com", Note: "written by the hunt",
	}, "agent")
	if err != nil {
		t.Fatal(err)
	}

	st, err = d.PolicyState(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Rules) != 1 || st.Rules[0].Authorized {
		t.Fatalf("state rules = %+v, want one unauthorized rule", st.Rules)
	}
	if dec := netpolicy.Decide(s.Purpose, st, dest, nil); dec.Allow {
		t.Fatalf("an unauthorized rule allowed the destination: %s", dec.Reason)
	}

	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, ruleID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	st, err = d.PolicyState(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if dec := netpolicy.Decide(s.Purpose, st, dest, nil); !dec.Allow {
		t.Fatalf("the approved rule did not allow the destination: %s", dec.Reason)
	}

	// Revoking closes it again.
	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, ruleID, false, "operator"); err != nil {
		t.Fatal(err)
	}
	st, err = d.PolicyState(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if dec := netpolicy.Decide(s.Purpose, st, dest, nil); dec.Allow {
		t.Fatalf("a revoked rule still allowed the destination: %s", dec.Reason)
	}
}

func TestPolicyStateMissingTask(t *testing.T) {
	d := openPolicyDB(t)
	_, err := d.PolicyState(t.Context(), netpolicy.Session{TaskID: 1 << 60, Purpose: netpolicy.PurposeTesting})
	if !errors.Is(err, netpolicy.ErrNoTask) {
		t.Fatalf("PolicyState() = %v, want ErrNoTask", err)
	}
}

// Research reads the authorized includes of every live task, and stops reading a
// pattern as soon as it is revoked.
func TestPolicyStateResearchTargets(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("policy targets", "prove research sees live targets", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	pattern := "targets-" + time.Now().Format("150405.000000") + ".example"
	ruleID, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: pattern, Authorized: true,
	}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	research := netpolicy.Session{ID: "research", Purpose: netpolicy.PurposeResearch}
	st, err := d.PolicyState(t.Context(), research)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(st.Targets, pattern) {
		t.Fatalf("research targets = %v, want %q", st.Targets, pattern)
	}

	// A testing session does not load them.
	testingSt, err := d.PolicyState(t.Context(), netpolicy.Session{ID: "testing", TaskID: task.ID, Purpose: netpolicy.PurposeTesting})
	if err != nil {
		t.Fatal(err)
	}
	if len(testingSt.Targets) != 0 {
		t.Fatalf("a testing session loaded %d research targets", len(testingSt.Targets))
	}

	// An install session is judged by the same public-destination rule, so it
	// must see the live targets too: an install may download from the public web
	// and must not reach an engagement target.
	installSt, err := d.PolicyState(t.Context(), netpolicy.Session{ID: "install", Purpose: netpolicy.PurposeInstall})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(installSt.Targets, pattern) {
		t.Fatalf("install targets = %v, want %q", installSt.Targets, pattern)
	}
	if len(installSt.Rules) != 0 {
		t.Fatalf("an unbound install session loaded task rules: %v", installSt.Rules)
	}

	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, ruleID, false, "operator"); err != nil {
		t.Fatal(err)
	}
	st, err = d.PolicyState(t.Context(), research)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(st.Targets, pattern) {
		t.Fatalf("a revoked rule is still a research target: %v", st.Targets)
	}
}

func TestCertExceptions(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("cert exceptions", "prove exceptions are bound and expiring", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	if err := d.AddCertException(t.Context(), task.ID, "Self-Signed.Example:443", "lab target", nil, "operator"); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := d.AddCertException(t.Context(), task.ID, "expired.example", "stale", &past, "operator"); err != nil {
		t.Fatal(err)
	}

	list, err := d.ListCertExceptions(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Authority != "self-signed.example:443" {
		t.Fatalf("exceptions = %+v, want only the unexpired normalized one", list)
	}

	// Re-approving the same authority replaces it rather than stacking rows.
	if err := d.AddCertException(t.Context(), task.ID, "self-signed.example:443", "still the lab target", nil, "operator"); err != nil {
		t.Fatal(err)
	}
	list, err = d.ListCertExceptions(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Reason != "still the lab target" {
		t.Fatalf("exceptions = %+v, want one updated row", list)
	}

	// A delete removes exactly the named row, and a second delete of the same id
	// reports the missing row rather than succeeding silently.
	if err := d.DeleteCertException(t.Context(), task.ID, list[0].ID, "operator"); err != nil {
		t.Fatalf("DeleteCertException: %v", err)
	}
	list, err = d.ListCertExceptions(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("exceptions = %+v, want none after the delete", list)
	}
}

func TestDeleteCertExceptionReportsMissingRow(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("cert delete", "prove a missing exception is a 404", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	if err := d.AddCertException(t.Context(), task.ID, "gone.example", "to be removed", nil, "operator"); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListCertExceptions(t.Context(), task.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("exceptions = %+v, err = %v", list, err)
	}
	if err := d.DeleteCertException(t.Context(), task.ID, list[0].ID, "operator"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := d.DeleteCertException(t.Context(), task.ID, list[0].ID, "operator"); !errors.Is(err, ErrCertExceptionNotFound) {
		t.Fatalf("second delete = %v, want ErrCertExceptionNotFound", err)
	}
	// A row belonging to another task is not this task's to delete.
	other, err := d.CreateTask("cert delete other", "own the row", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(other.ID) })
	if err := d.AddCertException(t.Context(), other.ID, "other.example", "not ours", nil, "operator"); err != nil {
		t.Fatal(err)
	}
	otherList, err := d.ListCertExceptions(t.Context(), other.ID)
	if err != nil || len(otherList) != 1 {
		t.Fatalf("other exceptions = %+v, err = %v", otherList, err)
	}
	if err := d.DeleteCertException(t.Context(), task.ID, otherList[0].ID, "operator"); !errors.Is(err, ErrCertExceptionNotFound) {
		t.Fatalf("cross-task delete = %v, want ErrCertExceptionNotFound", err)
	}
	var audits int
	if err := d.QueryRow(`SELECT count(*) FROM policy_audit WHERE task_id=$1 AND action='cert.exception.delete'`, task.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("policy_audit has %d delete rows, want 1 (the refused ones must not audit)", audits)
	}
}

func TestPolicyRuleValidationAndUnknownRule(t *testing.T) {
	d := openPolicyDB(t)
	task, err := d.CreateTask("policy validation", "prove bad grants are refused", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	for _, r := range []netpolicy.Rule{
		{Effect: "allow", Pattern: "api.example.com"},
		{Effect: "include", Pattern: "https://api.example.com/admin"},
		{Effect: "include", Pattern: "api.example.com", Protocol: "https"},
	} {
		if _, err := d.AddPolicyRule(t.Context(), task.ID, r, "operator"); err == nil {
			t.Fatalf("AddPolicyRule(%+v) = nil error, want a refusal", r)
		}
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM task_scope_rules WHERE task_id=$1`, task.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("%d refused rules were stored", count)
	}

	if err := d.SetPolicyRuleAuthorized(t.Context(), task.ID, 1<<60, true, "operator"); !errors.Is(err, ErrPolicyRuleNotFound) {
		t.Fatalf("SetPolicyRuleAuthorized() = %v, want ErrPolicyRuleNotFound", err)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

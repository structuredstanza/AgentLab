package db

import (
	"fmt"
	"testing"
)

// An operator-declared exclusion must actually block a call.
//
// Before this, the `effect` column had no writer: AddAgentScope did not accept
// it, the INSERT omitted it, and no API or tool could set it. The guard only
// enforces rows with effect='exclude', so the exclusion list the schema and the
// changelog advertise could be armed by hand-written SQL alone — and even then a
// root_domain row matched only the bare apex.
//
// This walks the whole path: write an exclusion, read it back through the
// checker the guard uses, and confirm a covered host is refused.
func TestTaskScopeExclusionBlocksCoveredHosts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope exclusion", "verify exclusions are enforced", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	apex := fmt.Sprintf("excluded-%d.invalid", task.ID)
	excludedNet := "203.0.113.0/24"

	// 1. The exclusion is persisted with effect='exclude'.
	ts, err := assets.AddAgentScope(task.ID, "root_domain", apex, "operator excluded it", "manual", "exclude")
	if err != nil {
		t.Fatalf("could not record an exclusion: %v", err)
	}
	if ts.Effect != "exclude" {
		t.Fatalf("effect not persisted: got %q, want exclude", ts.Effect)
	}
	if _, err := assets.AddAgentScope(task.ID, "cidr", excludedNet, "network excluded", "manual", "exclude"); err != nil {
		t.Fatalf("could not record a network exclusion: %v", err)
	}
	// An include stays an include.
	inc, err := assets.AddAgentScope(task.ID, "subdomain", "allowed-"+apex, "in scope", "manual", "")
	if err != nil {
		t.Fatalf("could not record an include: %v", err)
	}
	if inc.Effect != "include" {
		t.Errorf("default effect should be include, got %q", inc.Effect)
	}

	// 2. The checker the guard uses reports them as out.
	checker := NewTaskScopeChecker(assets, task.ID)
	if checker == nil {
		t.Fatal("no scope checker for a real task")
	}
	for _, host := range []string{apex, "api." + apex, "https://deep.api." + apex + "/admin"} {
		if out, reason := checker.Judge(host); !out {
			t.Errorf("%q is covered by the root_domain exclusion but was allowed", host)
		} else if reason == "" {
			t.Errorf("%q was refused with no reason", host)
		}
	}
	if out, _ := checker.Judge("203.0.113.7"); !out {
		t.Error("an address inside the excluded CIDR was allowed")
	}

	// 3. Hosts outside the boundary are untouched — an exclusion must not become
	// a blanket refusal.
	for _, host := range []string{"other-" + apex, "203.0.114.7"} {
		if out, reason := checker.Judge(host); out {
			t.Errorf("%q is outside the exclusions but was refused (%s)", host, reason)
		}
	}

	// 4. An exclusion that can never match is rejected instead of stored.
	if _, err := assets.AddAgentScope(task.ID, "keyword", "acme", "policy text", "manual", "exclude"); err == nil {
		t.Error("a keyword row was accepted as an exclusion, but the guard cannot enforce that kind")
	}
}

// Excluding a host the task already has as an include must still take effect.
//
// This is the ordinary case, not an edge one: auto-scope records every
// discovered root_domain/subdomain/ip as an include, so an operator excluding a
// host they are already scoped to is the normal action. The dedup index used to
// key on (task, kind, domain, net, company, value) without `effect`, and the
// insert was ON CONFLICT DO NOTHING — so the exclusion hit the existing include
// row, was silently discarded, and the API reported success while the guard
// never fired.
func TestTaskScopeExclusionOverridesExistingInclude(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("scope override", "exclusion beats an existing include", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	host := fmt.Sprintf("override-%d.invalid", task.ID)

	// Auto-scope first, exactly as insert_assets does for a discovered domain.
	if err := assets.AddAutoScope(task.ID, "root_domain", host, "", ""); err != nil {
		t.Fatalf("auto scope: %v", err)
	}
	checker := NewTaskScopeChecker(assets, task.ID)
	if out, _ := checker.Judge(host); out {
		t.Fatal("the host is not excluded yet, but the checker refused it")
	}

	// The operator now excludes it.
	ts, err := assets.AddAgentScope(task.ID, "root_domain", host, "operator ruled it out", "manual", "exclude")
	if err != nil {
		t.Fatalf("exclusion over an existing include was rejected: %v", err)
	}
	if ts.Effect != "exclude" {
		t.Fatalf("effect = %q, want exclude", ts.Effect)
	}

	// Both rows must exist: the include keeps the host in coverage, the
	// exclusion keeps it out of reach, and the checker's exclude-wins rule
	// decides. A single flipped row would lose one of the two meanings.
	rows, err := assets.ListTaskScope(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	var includes, excludes int
	for _, row := range rows {
		if row.Domain != host {
			continue
		}
		switch row.Effect {
		case "include":
			includes++
		case "exclude":
			excludes++
		}
	}
	if includes != 1 || excludes != 1 {
		t.Fatalf("scope rows for %s: %d include, %d exclude; want 1 and 1", host, includes, excludes)
	}

	if out, reason := checker.Judge(host); !out {
		t.Errorf("%q is excluded but was allowed", host)
	} else if reason == "" {
		t.Errorf("%q was refused with no reason", host)
	}
	if out, _ := checker.Judge("api." + host); !out {
		t.Errorf("a subdomain of the excluded root was allowed")
	}
}

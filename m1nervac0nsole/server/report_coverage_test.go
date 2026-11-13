package server

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// TestUncoveredAssets is DB-backed: it needs the real asset/exploration stores
// to build the coverage graph, so it skips without M1NERVAC0NSOLE_PG_DSN.
func TestUncoveredAssets(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	suffix := time.Now().UnixNano()
	var taskIDs, assetIDs []int64
	t.Cleanup(func() {
		for _, id := range taskIDs {
			_, _ = m.DeleteTask(strconv.FormatInt(id, 10), DeleteTaskOptions{})
		}
		for _, id := range assetIDs {
			_, _ = m.pg.Exec(`DELETE FROM assets WHERE id=$1`, id)
		}
	})
	createTask := func(name string) (*Task, int64) {
		t.Helper()
		task, err := m.CreateTask(name, "cover the scope", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, err := strconv.ParseInt(task.ID, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		taskIDs = append(taskIDs, id)
		return task, id
	}
	addAsset := func(id int64, err error) int64 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		assetIDs = append(assetIDs, id)
		return id
	}

	// One scope with a root domain, its subdomain and an IP. The root domain is
	// a container (its subdomain is in scope), the subdomain is tested, and the
	// IP is an untouched leaf: exactly the IP is a real coverage gap.
	root := fmt.Sprintf("cov%d.test", suffix)
	sub := "api." + root
	ip := fmt.Sprintf("10.%d.%d.%d", byte(suffix>>16), byte(suffix>>8), byte(suffix))
	task, taskID := createTask("coverage graph")
	rootID := addAsset(m.assets.UpsertRootDomain(pgdb.UpsertRootDomainReq{Domain: root}))
	subID := addAsset(m.assets.UpsertSubdomain(pgdb.UpsertSubdomainReq{Domain: sub}))
	addAsset(m.assets.UpsertIP(pgdb.UpsertIPReq{IP: ip}))
	for _, scope := range []struct{ typ, domain, ip string }{
		{"root_domain", root, ""},
		{"subdomain", sub, ""},
		{"ip", "", ip},
	} {
		if err := m.assets.AddAutoScope(taskID, scope.typ, scope.domain, "", scope.ip); err != nil {
			t.Fatal(err)
		}
	}
	// A fact anchored to the subdomain marks it tested; the root domain stays
	// untested itself but is still a container, not a gap.
	if _, err := task.Store.AddNode(pgdb.KindFact, map[string]any{"summary": "probed the API"}, 1, "confirmed", "worker", []int64{subID}); err != nil {
		t.Fatal(err)
	}
	got := uncoveredAssets(m.assets, task)
	if len(got) != 1 || got[0].Kind != "ip" || got[0].Label != ip {
		t.Fatalf("uncovered = %+v, want only the untested IP %s", got, ip)
	}
	if rootID <= 0 || got[0].Label == root {
		t.Fatalf("root domain %d leaked into the gap list: %+v", rootID, got)
	}

	// A task scoped only to a root domain with nothing anchored to it is a real
	// untested target, not a container: the report must name it.
	lone := fmt.Sprintf("lone%d.test", suffix)
	loneTask, loneTaskID := createTask("lone root domain")
	addAsset(m.assets.UpsertRootDomain(pgdb.UpsertRootDomainReq{Domain: lone}))
	if err := m.assets.AddAutoScope(loneTaskID, "root_domain", lone, "", ""); err != nil {
		t.Fatal(err)
	}
	got = uncoveredAssets(m.assets, loneTask)
	if len(got) != 1 || got[0].Kind != "root_domain" || got[0].Label != lone {
		t.Fatalf("uncovered = %+v, want the lone untested root domain %s", got, lone)
	}

	// A fully tested scope is a KNOWN-empty result (non-nil), never "unknown".
	ip2 := fmt.Sprintf("10.%d.%d.%d", byte(suffix>>16), byte(suffix>>8), byte(suffix)+1)
	testedTask, testedTaskID := createTask("fully tested")
	testedIP := addAsset(m.assets.UpsertIP(pgdb.UpsertIPReq{IP: ip2}))
	if err := m.assets.AddAutoScope(testedTaskID, "ip", "", "", ip2); err != nil {
		t.Fatal(err)
	}
	if _, err := testedTask.Store.AddNode(pgdb.KindFact, map[string]any{"summary": "probed"}, 1, "confirmed", "worker", []int64{testedIP}); err != nil {
		t.Fatal(err)
	}
	if got := uncoveredAssets(m.assets, testedTask); got == nil || len(got) != 0 {
		t.Fatalf("fully tested scope = %#v, want a known-empty slice", got)
	}

	// A failed computation is unknown, not covered.
	if got := uncoveredAssets(nil, task); got != nil {
		t.Fatalf("no asset store = %+v, want nil (unknown)", got)
	}
	if got := uncoveredAssets(m.assets, nil); got != nil {
		t.Fatalf("no task = %+v, want nil (unknown)", got)
	}
}

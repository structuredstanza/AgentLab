package agent

import (
	"context"
	"net"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/scope"
)

func TestFlagPending(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("pending fixture", "scope", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	defer d.Assets().DeleteByTaskID(task.ID)
	for host, ips := range map[string][]string{
		"vhost.htb":   {"10.9.8.5"},
		"other.htb":   {"203.0.113.9"},
		"partial.htb": {"10.9.8.6", "203.0.113.10"},
	} {
		for _, ip := range ips {
			if _, err := d.Assets().UpsertIP(db.UpsertIPReq{IP: ip, BoundDomains: []string{host}, TaskID: task.ID}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := d.AddPolicyRule(context.Background(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: "10.9.8.0/24", Protocol: "any", Authorized: true,
	}, "goal"); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)

	notified := map[string]int64{}
	old := ScopePending
	t.Cleanup(func() { ScopePending = old })
	ScopePending = func(taskID int64, pattern string, ruleID int64) {
		if taskID != task.ID {
			t.Errorf("notified task = %d, want %d", taskID, task.ID)
		}
		notified[pattern] = ruleID
	}

	for _, c := range []struct {
		name, kind, value string
		want              string
	}{
		{"covered ip", "ip", "10.9.8.77", ""},
		{"uncovered ip", "ip", "192.0.2.5", "192.0.2.5"},
		{"uncovered ip again", "ip", "192.0.2.5", ""},
		{"host with covered ip", "subdomain", "vhost.htb", ""},
		{"host with uncovered ip", "subdomain", "other.htb", "other.htb"},
		{"host with partly covered IPs", "subdomain", "partial.htb", "partial.htb"},
		{"root domain", "root_domain", "example.org", "*.example.org"},
	} {
		if got := ts.flagPending(c.kind, c.value); got != c.want {
			t.Errorf("%s: pending = %q, want %q", c.name, got, c.want)
		}
	}
	rules, err := d.ListPolicyRules(context.Background(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, r := range rules {
		if !r.Authorized {
			pending++
			if notified[r.Pattern] != r.ID {
				t.Errorf("notified rule for %q = %d, want %d", r.Pattern, notified[r.Pattern], r.ID)
			}
		}
	}
	if pending != 4 || len(notified) != 4 {
		t.Fatalf("pending rules = %d, notified = %v; want 4 each", pending, notified)
	}
}

func TestScopeCoverageRequiresEveryRecordedAddress(t *testing.T) {
	rules := []scope.Rule{
		{Effect: scope.Include, Pattern: "*.recorded.test"},
		{Effect: scope.Include, Pattern: "192.0.2.0/24"},
		{Effect: scope.Exclude, Pattern: "192.0.2.10/32"},
	}
	for _, tc := range []struct {
		name string
		ip   string
		want bool
	}{
		{"covered", "192.0.2.9", true},
		{"uncovered", "198.51.100.8", false},
		{"excluded", "192.0.2.10", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ips := []net.IP{net.ParseIP("192.0.2.8"), net.ParseIP(tc.ip)}
			if got := scopeRuleCovers("host.recorded.test", ips, rules); got != tc.want {
				t.Fatalf("coverage with recorded addresses %v = %v, want %v", ips, got, tc.want)
			}
		})
	}
}

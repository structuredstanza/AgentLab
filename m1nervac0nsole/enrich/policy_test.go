package enrich

import (
	"net"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// An HTTP probe is outbound contact, so the task's network policy decides it
// before anything is dialled. A task with no authorized rule, and an engine with
// no authorizer at all, must both leave the destination uncontacted.
func TestEnrichProbeAsksTheNetworkPolicyBeforeDialling(t *testing.T) {
	d, as := testDB(t)
	proxyURL, caFile, gate := startMaskingProxy(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	target := "http://" + ln.Addr().String() + "/"

	for _, tc := range []struct {
		name    string
		auth    netpolicy.Authorizer
		authorz bool
	}{
		{"no authorized rule", netpolicy.NewAuthorizer(d), false},
		{"no authorizer", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task, err := d.CreateTask("enrich policy", tc.name, nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer d.DeleteTask(task.ID)
			if tc.authorz {
				if _, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
					Effect: "include", Pattern: "127.0.0.1", Authorized: true,
				}, "operator"); err != nil {
					t.Fatalf("authorize: %v", err)
				}
			}
			id := upsertSite(t, as, task.ID, target)
			engine := New(as, Options{Workers: 1, Proxy: proxyURL, CAFile: caFile, Authorizer: tc.auth})
			defer engine.Close()
			engine.ProbeSite(task.ID, id, target)
			engine.Wait()

			select {
			case <-accepted:
				t.Fatal("an unauthorized destination was dialled")
			case <-time.After(200 * time.Millisecond):
			}
			if seen := gate.snapshot(); len(seen) != 0 {
				t.Fatalf("the masking proxy was asked to forward an unauthorized probe: %v", seen)
			}
			if a := loadAsset(t, as, id); a.StatusCode != nil {
				t.Fatalf("an unauthorized probe persisted a result: status=%d", *a.StatusCode)
			}
		})
	}
}

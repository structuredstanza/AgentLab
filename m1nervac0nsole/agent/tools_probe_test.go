package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

func callTCPProbe(t *testing.T, ts *ToolSet, payload map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.tcpProbe().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("tcp_probe: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", res.Flatten(), err)
	}
	return out
}

func lastUnreachable(t *testing.T, d *db.DB, id int64) sql.NullTime {
	t.Helper()
	var at sql.NullTime
	if err := d.QueryRow(`SELECT last_unreachable_at FROM assets WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatalf("read last_unreachable_at: %v", err)
	}
	return at
}

func openPorts(t *testing.T, d *db.DB, id int64) []map[string]any {
	t.Helper()
	var raw string
	if err := d.QueryRow(`SELECT array_to_json(open_ports)::text FROM assets WHERE id = $1`, id).Scan(&raw); err != nil {
		t.Fatalf("read open_ports: %v", err)
	}
	var ports []map[string]any
	if err := json.Unmarshal([]byte(raw), &ports); err != nil {
		t.Fatalf("unmarshal open_ports %q: %v", raw, err)
	}
	return ports
}

// A direct probe of a closed port reports the refusal and marks the host
// unreachable; a later successful probe clears the marker and records the port
// as observed rather than asserted.
func TestTCPProbeRecordsLiveness(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	as := d.Assets()

	const ip = "127.0.0.9"
	if _, err := d.Exec(`DELETE FROM assets WHERE ip = $1`, ip); err != nil {
		t.Fatal(err)
	}
	id, err := as.UpsertIP(db.UpsertIPReq{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE ip = $1`, ip)

	// A probe is outbound contact, so the task's network policy decides it.
	task, err := d.CreateTask("tcp probe fixture", "authorize the probed address", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	if _, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: ip, Authorized: true,
	}, "operator"); err != nil {
		t.Fatalf("authorize %s: %v", ip, err)
	}
	oldAuth := NetPolicyAuthorizer
	t.Cleanup(func() { NetPolicyAuthorizer = oldAuth })
	NetPolicyAuthorizer = netpolicy.NewAuthorizer(d)

	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(as, d.Companies())
	ts.SetTaskID(task.ID)

	// Reserve a port on the target address, then release it so nothing listens.
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatalf("loopback %s is not available: %v", ip, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	out := callTCPProbe(t, ts, map[string]any{"host": ip, "port": port})
	if out["result"] != "refused" {
		t.Fatalf("probe of a closed port = %v, want refused", out)
	}
	if at := lastUnreachable(t, d, id); !at.Valid {
		t.Fatal("a refused probe did not record last_unreachable_at")
	}
	if ports := openPorts(t, d, id); len(ports) != 0 {
		t.Fatalf("a refused probe recorded a port: %v", ports)
	}

	ln, err = net.Listen("tcp", ip+":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("rebind %s:%d: %v", ip, port, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	out = callTCPProbe(t, ts, map[string]any{"host": ip, "port": port})
	if out["result"] != "connected" {
		t.Fatalf("probe of an open port = %v, want connected", out)
	}
	if at := lastUnreachable(t, d, id); at.Valid {
		t.Fatalf("a successful probe did not clear the marker (%v)", at.Time)
	}
	ports := openPorts(t, d, id)
	if len(ports) != 1 || ports[0]["provenance"] != db.PortProvenanceProbe {
		t.Fatalf("a successful probe must record the port as probe-derived: %v", ports)
	}
}

// tcp_probe is a direct dial, so the task's network policy decides it before the
// socket is opened: a destination no authorized rule covers is never contacted,
// and neither is any destination when no authorizer is wired.
func TestTCPProbeRefusesUnauthorizedDestination(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	as := d.Assets()

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
	port := ln.Addr().(*net.TCPAddr).Port
	payload := map[string]any{"host": "127.0.0.1", "port": port}

	// A bare task: no authorized rule, which is the state a task is in until an
	// operator approves one.
	task, err := d.CreateTask("tcp probe policy", "no authorized rule", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	oldAuth := NetPolicyAuthorizer
	t.Cleanup(func() { NetPolicyAuthorizer = oldAuth })

	for _, tc := range []struct {
		name    string
		auth    netpolicy.Authorizer
		authorz bool
	}{
		{"no authorized rule", netpolicy.NewAuthorizer(d), false},
		{"no authorizer", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.authorz {
				if _, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
					Effect: "include", Pattern: "127.0.0.1", Authorized: true,
				}, "operator"); err != nil {
					t.Fatalf("authorize: %v", err)
				}
			}
			NetPolicyAuthorizer = tc.auth
			ts := NewToolSet(nil, "worker")
			ts.SetAssetStore(as, d.Companies())
			ts.SetTaskID(task.ID)
			raw, _ := json.Marshal(payload)
			res, err := ts.tcpProbe().Call(context.Background(), raw, nil)
			if err != nil {
				t.Fatalf("tcp_probe: %v", err)
			}
			if !res.IsError || !strings.Contains(res.Flatten(), "refused") {
				t.Fatalf("an unauthorized probe was not refused: %q", res.Flatten())
			}
			select {
			case <-accepted:
				t.Fatal("tcp_probe dialled a destination the network policy did not authorize")
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

// open_ports entries from insert_assets are model assertions, whatever the
// model claims about them.
func TestInsertAssetsPortsCarryModelProvenance(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	const ip = "10.99.99.99"
	d.Exec(`DELETE FROM assets WHERE ip = $1`, ip)
	defer d.Exec(`DELETE FROM assets WHERE ip = $1`, ip)

	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(d.Assets(), d.Companies())
	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{map[string]any{
			"type": "ip", "ip": ip,
			"open_ports": []any{map[string]any{"port": 22, "service": "ssh", "provenance": "probe"}},
		}},
	})
	if errs, _ := out["errors"].([]any); len(errs) > 0 {
		t.Fatalf("insert_assets errors: %v", errs)
	}

	var id int64
	if err := d.QueryRow(`SELECT id FROM assets WHERE type = 'ip' AND ip = $1`, ip).Scan(&id); err != nil {
		t.Fatal(err)
	}
	ports := openPorts(t, d, id)
	if len(ports) != 1 || ports[0]["provenance"] != db.PortProvenanceModel {
		t.Fatalf("insert_assets must record its ports as model assertions: %v", ports)
	}
}

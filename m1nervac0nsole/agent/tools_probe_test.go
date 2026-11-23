package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

// A refusal is a reply, so a refused probe proves the host alive and clears the
// marker rather than setting it; a successful probe also clears it and records
// the port as observed rather than asserted.
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

	if err := as.MarkUnreachable(ip); err != nil {
		t.Fatal(err)
	}
	out := callTCPProbe(t, ts, map[string]any{"host": ip, "port": port})
	if out["result"] != "refused" {
		t.Fatalf("probe of a closed port = %v, want refused", out)
	}
	if at := lastUnreachable(t, d, id); at.Valid {
		t.Fatal("a refused probe left the host marked unreachable")
	}
	if err := as.MarkUnreachable(ip); err != nil {
		t.Fatal(err)
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

func failDNS(t *testing.T) {
	t.Helper()
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no DNS answers for fixture")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = old })
}

func TestResolveDialHostRefusesUncoveredRecordedAddress(t *testing.T) {
	failDNS(t)
	const host = "recorded-only.invalid."
	ts := NewToolSet(nil, "worker")
	ts.SetTaskID(1)
	az := netpolicy.NewAuthorizer(snapshotSource{netpolicy.State{Rules: []netpolicy.Rule{
		{Effect: "include", Pattern: "recorded-only.invalid", Authorized: true},
	}}})
	res, _, err := ts.resolveDialHost(t.Context(), az, host, 443, []net.IP{net.ParseIP("192.0.2.5")})
	if err == nil || len(res.addrs) != 0 {
		t.Fatalf("hostname grant supplied the uncovered recorded dial address: %v (%v)", res.addrs, err)
	}
}

func callPortScan(t *testing.T, ts *ToolSet, payload map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.portScan().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("port_scan: %v", err)
	}
	if res.IsError {
		t.Fatalf("port_scan errored: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", res.Flatten(), err)
	}
	return out
}

// listenCounting accepts on addr and reports each accepted connection.
func listenCounting(t *testing.T, addr string) (int, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted
}

// countingSource counts PolicyState reads.
type countingSource struct {
	src   netpolicy.Source
	calls atomic.Int64
}

func (c *countingSource) PolicyState(ctx context.Context, s netpolicy.Session) (netpolicy.State, error) {
	c.calls.Add(1)
	return c.src.PolicyState(ctx, s)
}

func scanFixture(t *testing.T) (*db.DB, *ToolSet, int64) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("port scan fixture", "authorize the scanned address", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	oldAuth, oldSrc, oldExit := NetPolicyAuthorizer, NetPolicySource, OperatorExitConfigured
	t.Cleanup(func() { NetPolicyAuthorizer, NetPolicySource, OperatorExitConfigured = oldAuth, oldSrc, oldExit })
	NetPolicyAuthorizer = netpolicy.NewAuthorizer(d)
	NetPolicySource = d
	OperatorExitConfigured = func() bool { return false }
	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)
	return d, ts, task.ID
}

// port_scan reports an open port, a refused port, and never dials a port the
// policy does not cover (the rule is port-restricted, so authorization is per
// port).
func TestPortScanClassifiesAndAuthorizesPerPort(t *testing.T) {
	d, ts, taskID := scanFixture(t)
	openPort, _ := listenCounting(t, "127.0.0.1:0")
	denyPort, denied := listenCounting(t, "127.0.0.1:0")
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	if _, err := d.AddPolicyRule(t.Context(), taskID, netpolicy.Rule{
		Effect: "include", Pattern: "127.0.0.1", Authorized: true, Ports: []int{openPort, closedPort},
	}, "operator"); err != nil {
		t.Fatal(err)
	}

	// Both the authorizer and the source read through the counter, so a per-port
	// decision routed back through NetPolicyAuthorizer would show as extra reads.
	cs := &countingSource{src: d}
	NetPolicyAuthorizer = netpolicy.NewAuthorizer(cs)
	NetPolicySource = cs
	spec := strconv.Itoa(openPort) + "," + strconv.Itoa(closedPort) + "," + strconv.Itoa(denyPort)
	out := callPortScan(t, ts, map[string]any{"host": "127.0.0.1", "ports": spec})
	res := out["results"].([]any)[0].(map[string]any)
	if open := res["open"].([]any); len(open) != 1 || int(open[0].(float64)) != openPort {
		t.Fatalf("open = %v, want [%d]", open, openPort)
	}
	counts := res["counts"].(map[string]any)
	if counts["open"] != 1.0 || counts["refused"] != 1.0 || counts["not_authorized"] != 1.0 {
		t.Fatalf("counts = %v", counts)
	}
	if n := cs.calls.Load(); n != 1 {
		t.Fatalf("a %d-port scan read the policy %d times, want 1", 3, n)
	}
	select {
	case <-denied:
		t.Fatal("port_scan dialled a port the network policy did not authorize")
	case <-time.After(200 * time.Millisecond):
	}
}

// A name is scanned at the address the task recorded for it, but only when that
// address is also authorized on its own: a name grant alone never covers a
// recorded claim, and an excluded address is never dialled.
func TestPortScanHostnameUsesAuthorizedAddresses(t *testing.T) {
	d, ts, taskID := scanFixture(t)
	as := d.Assets()
	port, _ := listenCounting(t, "127.0.0.1:0")
	badPort, bad := listenCounting(t, "127.0.0.2:0")
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		d.Exec(`DELETE FROM assets WHERE ip = $1`, ip)
		t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE ip = $1`, ip) })
	}
	if _, err := as.UpsertIP(db.UpsertIPReq{IP: "127.0.0.1", BoundDomains: []string{"scan.test"}, TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.UpsertIP(db.UpsertIPReq{IP: "127.0.0.2", BoundDomains: []string{"bad.test"}, TaskID: taskID}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []netpolicy.Rule{
		{Effect: "include", Pattern: "scan.test", Authorized: true},
		{Effect: "include", Pattern: "127.0.0.1", Authorized: true},
		{Effect: "include", Pattern: "bad.test", Authorized: true},
		{Effect: "exclude", Pattern: "127.0.0.2"},
	} {
		if _, err := d.AddPolicyRule(t.Context(), taskID, r, "operator"); err != nil {
			t.Fatal(err)
		}
	}

	out := callPortScan(t, ts, map[string]any{"host": "scan.test", "ports": strconv.Itoa(port)})
	if got := out["addresses_scanned"].([]any); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("addresses_scanned = %v, want the recorded 127.0.0.1", got)
	}
	res := out["results"].([]any)[0].(map[string]any)
	if open := res["open"].([]any); len(open) != 1 || int(open[0].(float64)) != port {
		t.Fatalf("open = %v, want [%d]", open, port)
	}

	failDNS(t)
	raw, err := json.Marshal(map[string]any{"host": "bad.test", "ports": strconv.Itoa(badPort)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ts.portScan().Call(t.Context(), raw, nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "cannot resolve") {
		t.Fatalf("excluded recorded address did not fall back to DNS: %v %s", err, result.Flatten())
	}
	select {
	case <-bad:
		t.Fatal("port_scan dialled an address the policy excludes")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPortScanRefusesOperatorExit(t *testing.T) {
	oldSrc, oldExit := NetPolicySource, OperatorExitConfigured
	t.Cleanup(func() { NetPolicySource, OperatorExitConfigured = oldSrc, oldExit })
	src := &countingSource{src: snapshotSource{}}
	NetPolicySource = src
	ts := NewToolSet(nil, "worker")
	ts.SetTaskID(1)
	for _, tc := range []struct {
		exit func() bool
		want string
	}{
		{nil, "operator exit configuration is unavailable"},
		{func() bool { return true }, "operator global proxy is configured"},
	} {
		OperatorExitConfigured = tc.exit
		res, err := ts.portScan().Call(t.Context(), json.RawMessage(`{"host":"192.0.2.1","ports":"80"}`), nil)
		if err != nil || !res.IsError || !strings.Contains(res.Flatten(), tc.want) {
			t.Errorf("expected refusal %q: %v %s", tc.want, err, res.Flatten())
		}
	}
	if n := src.calls.Load(); n != 0 {
		t.Errorf("read policy %d times despite operator exit refusal", n)
	}
}

func TestPortScanPolicyStopsAfterRevocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &countingSource{src: snapshotSource{netpolicy.State{Revision: 1}}}
		p := portScanPolicy{src: src, session: dialSession(1), exitConfigured: func() bool { return false }}
		if err := p.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		src.src = snapshotSource{netpolicy.State{Revision: 2, Rules: []netpolicy.Rule{
			{Effect: "exclude", Pattern: "192.0.2.1"},
		}}}
		// A worker is still dialing after the last job is dispatched.
		jobs := make(chan portScanJob, 1)
		ctx, cancel := context.WithTimeout(t.Context(), 3*portScanPolicyInterval)
		defer cancel()
		start := time.Now()
		err := p.feed(ctx, jobs, nil, 1, 1)
		if err == nil || !strings.Contains(err.Error(), "network policy changed") {
			t.Fatalf("scan did not stop on a new policy revision: %v", err)
		}
		if src.calls.Load() != 2 || time.Since(start) != portScanPolicyInterval {
			t.Fatalf("policy refreshed %d times after %s", src.calls.Load(), time.Since(start))
		}
	})
}

func TestPortScanSuppressesMiddleboxPorts(t *testing.T) {
	ts := NewToolSet(nil, "worker")
	for _, n := range []int{1000, 1001} {
		tl := &portScanTally{open: make([]int, n), counts: map[string]int{"open": n}}
		result, replied := ts.recordPortScanTally("scan.invalid", "192.0.2.1", tl)
		if !replied {
			t.Fatal("scan reply reported as silence")
		}
		if n == 1000 {
			if result["note"] != nil || len(result["open"].([]int)) != n {
				t.Fatalf("credible open ports suppressed: %v", result["note"])
			}
		} else if result["note"] != "answers on 1001 ports, likely a middlebox" || len(result["open"].([]int)) != 0 {
			t.Fatalf("middlebox replies still reported as open ports: note = %v, ports = %d", result["note"], len(result["open"].([]int)))
		}
	}
}

func TestPortScanKeepsMiddleboxRepliesOutOfAssets(t *testing.T) {
	d, ts, taskID := scanFixture(t)
	const addr = "198.51.100.10"
	t.Cleanup(func() { d.Assets().DeleteByTaskID(taskID) })
	id, err := d.Assets().UpsertIP(db.UpsertIPReq{IP: addr, TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Assets().MarkUnreachable(addr); err != nil {
		t.Fatal(err)
	}
	ports := make([]int, 1001)
	for i := range ports {
		ports[i] = i + 1
	}
	ts.recordPortScanTally(addr, addr, &portScanTally{open: ports, counts: map[string]int{"open": len(ports)}})
	if len(openPorts(t, d, id)) != 0 || !lastUnreachable(t, d, id).Valid {
		t.Fatal("middlebox replies were persisted as port or liveness observations")
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("80, 22,8000-8002,80")
	if err != nil || len(got) != 5 || got[0] != 22 || got[4] != 8002 {
		t.Fatalf("parsePorts = %v, %v", got, err)
	}
	if top, err := parsePorts("top"); err != nil || len(top) < 90 {
		t.Fatalf("top preset = %d ports, %v", len(top), err)
	}
	for _, bad := range []string{"", "0", "65536", "9-3", "x", "1-"} {
		if _, err := parsePorts(bad); err == nil {
			t.Fatalf("parsePorts(%q) accepted", bad)
		}
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

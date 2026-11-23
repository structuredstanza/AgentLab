package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/enrich"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/useragent"
	actool "github.com/structuredstanza/norma/tool"
)

// staticRoute is a fixed recorder route: one proxy and CA, no session to revoke.
func staticRoute(proxyURL, caFile string) enrich.Route {
	return func(context.Context, int64) (string, string, func(), error) {
		return proxyURL, caFile, func() {}, nil
	}
}

// startConnectTunnel runs a CONNECT tunnel on loopback that stands in for
// the recording proxy and returns its URL and the CA to trust: the certificate
// every httptest TLS origin presents.
func startConnectTunnel(t *testing.T) (proxyURL, caFile string) {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up, err := net.Dial("tcp", r.Host)
		if r.Method != http.MethodConnect || err != nil {
			http.Error(w, "tunnel refused", http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		go func() { _, _ = io.Copy(conn, up); conn.Close() }()
	}))
	t.Cleanup(p.Close)
	origin := httptest.NewTLSServer(http.NotFoundHandler())
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	origin.Close()
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p.URL, caFile
}

func insertAssetsToolFor(t *testing.T, ts *ToolSet) actool.CoreTool {
	t.Helper()
	for _, tool := range ts.WorkerTools() {
		if tool.Name() == "insert_assets" {
			return tool
		}
	}
	t.Fatal("insert_assets is not in the worker tool set")
	return nil
}

func callInsertTool(t *testing.T, tool actool.CoreTool, assets ...map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"assets": assets})
	res, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("insert_assets: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", res.Flatten(), err)
	}
	if errs, _ := out["errors"].([]any); len(errs) > 0 {
		t.Fatalf("insert_assets errors: %v", errs)
	}
	return out
}

func serviceRow(t *testing.T, d *db.DB, url string) (title string, status *int, taskIDs string) {
	t.Helper()
	var pt *string
	if err := d.QueryRow(`SELECT page_title, status_code, array_to_json(task_ids)::text FROM assets WHERE type='service' AND url=$1`, url).Scan(&pt, &status, &taskIDs); err != nil {
		t.Fatalf("read service %s: %v", url, err)
	}
	if pt != nil {
		title = *pt
	}
	return title, status, taskIDs
}

// A worker's insert_assets call persists a web service, the manager-wide engine
// probes it through the recorder route under the worker's task, and the origin's
// title lands on the persisted asset. The whole chain is real: tool, engine,
// recorder stand-in, local origin, database.
func TestInsertAssetsEnrichesPersistedServiceThroughMaskingProxy(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("enrich wiring", "insert_assets drives enrichment", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	// The probe asks the network policy before it dials, so the fixture task
	// authorizes the origin it probes.
	if _, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: "127.0.0.1", Authorized: true,
	}, "operator"); err != nil {
		t.Fatalf("authorize the fixture origin: %v", err)
	}
	proxyURL, caFile := startConnectTunnel(t)

	var mu sync.Mutex
	var ua string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ua = r.Header.Get("User-Agent")
		mu.Unlock()
		io.WriteString(w, "<html><head><title>Wired Title</title></head></html>")
	}))
	defer origin.Close()
	url := origin.URL + "/wired"
	defer d.Exec(`DELETE FROM assets WHERE url=$1 OR domain='127.0.0.1'`, url)

	engine := enrich.New(d.Assets(), enrich.Options{Workers: 2, Route: staticRoute(proxyURL, caFile), Authorizer: netpolicy.NewAuthorizer(d)})
	defer engine.Close()
	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)
	ts.SetEnrich(engine)

	callInsertTool(t, insertAssetsToolFor(t, ts), map[string]any{"type": "service", "url": url})
	engine.Wait()

	title, status, taskIDs := serviceRow(t, d, url)
	if title != "Wired Title" || status == nil || *status != http.StatusOK {
		t.Fatalf("enrichment result not persisted on the inserted asset: title=%q status=%v", title, status)
	}
	var ids []int64
	_ = json.Unmarshal([]byte(taskIDs), &ids)
	found := false
	for _, id := range ids {
		found = found || id == task.ID
	}
	if !found {
		t.Fatalf("asset lost the worker's task: task_ids=%v want %d", ids, task.ID)
	}
	mu.Lock()
	defer mu.Unlock()
	if ua != useragent.Get() {
		t.Fatalf("origin saw User-Agent %q, want the engagement identity %q: the probe did not go through the recorder route", ua, useragent.Get())
	}
}

// No task context, no probe: the engine is manager-wide and has no boundary to
// check a task-less destination against, so the reachable origin stays untouched.
func TestInsertAssetsWithoutTaskDoesNotProbe(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	proxyURL, caFile := startConnectTunnel(t)

	var mu sync.Mutex
	hits := 0
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer origin.Close()
	url := origin.URL + "/notask"
	defer d.Exec(`DELETE FROM assets WHERE url=$1 OR domain='127.0.0.1'`, url)

	engine := enrich.New(d.Assets(), enrich.Options{Workers: 2, Route: staticRoute(proxyURL, caFile), Authorizer: netpolicy.NewAuthorizer(d)})
	defer engine.Close()
	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetEnrich(engine)

	callInsertTool(t, insertAssetsToolFor(t, ts), map[string]any{"type": "service", "url": url})
	engine.Wait()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("origin was probed %d time(s) with no task context", hits)
	}
}

// A host the operator excluded for the task can still be inserted as an asset
// (the insert gate is rule-based), but it is never probed.
func TestInsertAssetsExcludedHostIsNotProbed(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("enrich wiring exclusion", "excluded hosts are not probed", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	proxyURL, caFile := startConnectTunnel(t)

	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	var mu sync.Mutex
	hits := 0
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	_ = origin.Listener.Close()
	origin.Listener = ln
	origin.StartTLS()
	defer origin.Close()
	url := origin.URL + "/excluded"
	defer d.Exec(`DELETE FROM assets WHERE url=$1 OR domain='127.0.0.2'`, url)

	if _, err := d.Assets().AddAgentScope(task.ID, "ip", "127.0.0.2", "operator excluded it", "manual", "exclude"); err != nil {
		t.Fatal(err)
	}
	engine := enrich.New(d.Assets(), enrich.Options{Workers: 2, Route: staticRoute(proxyURL, caFile), Authorizer: netpolicy.NewAuthorizer(d)})
	defer engine.Close()
	ts := NewToolSet(nil, "worker")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)
	ts.SetEnrich(engine)

	callInsertTool(t, insertAssetsToolFor(t, ts), map[string]any{"type": "service", "url": url})
	engine.Wait()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("an excluded host was probed %d time(s)", hits)
	}
	if _, status, _ := serviceRow(t, d, url); status != nil {
		t.Fatalf("an excluded host's probe result was persisted: status=%d", *status)
	}
}

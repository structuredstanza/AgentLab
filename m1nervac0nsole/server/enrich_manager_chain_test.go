package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/enrich"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

// Enrichment goes through the real recorder and gateway under a backend-issued
// enrichment session: the origin sees the Chrome identity and navigation headers
// the gateway applies to that session, the recorder stores the exchange against
// the task, an origin outside the task's grant is never contacted, the session
// is revoked afterwards, and with capture off nothing is probed (no direct path).
func TestManagerEnrichmentGoesThroughTheRecorderSession(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("manager enrich session", "enrichment through the recorder", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	as := pg.Assets()

	m := &Manager{pg: pg, assets: as, trafficOn: true}
	m.gw = m.newGatewayTransport()
	addr := freeServerLoopbackAddr(t)
	tr, err := openRecorder(filepath.Join(t.TempDir(), "traffic"), addr, m.gw)
	if err != nil {
		t.Fatalf("open recorder: %v", err)
	}
	defer tr.Close()
	m.traffic = tr
	go func() { _ = tr.Start() }()
	waitServerListening(t, addr)

	var mu sync.Mutex
	var seenUA, seenMode string
	hits := 0
	granted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUA, seenMode = r.Header.Get("User-Agent"), r.Header.Get("Sec-Fetch-Mode")
		hits++
		mu.Unlock()
		io.WriteString(w, "<html><title>Via Recorder</title></html>")
	}))
	defer granted.Close()
	// A second origin on another loopback address is outside the task's grant.
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	outside := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		io.WriteString(w, "<html><title>Outside</title></html>")
	}))
	_ = outside.Listener.Close()
	outside.Listener = ln
	outside.StartTLS()
	defer outside.Close()

	// The grant covers 127.0.0.1 only; the origins' certificates are self-signed,
	// so the operator's certificate exception for the granted authority applies.
	for _, pattern := range []string{"localhost", "127.0.0.1"} {
		if _, err := pg.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{Effect: "include", Pattern: pattern, Authorized: true}, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	// A hostname, not the IP literal: Go sends no SNI for an IP.
	grantedURL := strings.Replace(granted.URL, "127.0.0.1", "localhost", 1)
	if err := pg.AddCertException(t.Context(), task.ID, "localhost", "fixture origin", nil, "operator"); err != nil {
		t.Fatal(err)
	}
	engine := enrich.New(as, enrich.Options{Workers: 1, Route: m.enrichRoute, Authorizer: netpolicy.NewAuthorizer(pg)})
	defer engine.Close()

	probe := func(rawURL string) (string, *int) {
		t.Helper()
		id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: rawURL, TaskID: task.ID})
		if err != nil {
			t.Fatal(err)
		}
		defer as.DeleteByHost("localhost")
		defer as.DeleteByHost("127.0.0.1")
		defer as.DeleteByHost("127.0.0.2")
		engine.ProbeSite(task.ID, id, rawURL)
		engine.Wait()
		rows, err := as.GetByIDs([]int64{id})
		if err != nil || len(rows) != 1 {
			t.Fatalf("load asset: %v (%d rows)", err, len(rows))
		}
		return rows[0].PageTitle, rows[0].StatusCode
	}

	title, status := probe(grantedURL + "/in")
	if title != "Via Recorder" || status == nil || *status != http.StatusOK {
		t.Fatalf("probe through the recorder not persisted: title=%q status=%v", title, status)
	}
	mu.Lock()
	ua, mode := seenUA, seenMode
	mu.Unlock()
	if !strings.Contains(ua, "Chrome/") {
		t.Fatalf("origin saw User-Agent %q, want the Chrome identity", ua)
	}
	if mode != "navigate" {
		t.Fatalf("origin saw Sec-Fetch-Mode %q: the enrichment session did not get navigation masking", mode)
	}
	if _, total, err := tr.Page(traffic.PageQuery{TaskID: task.ID, RespMin: -1, RespMax: -1}, 0, 10); err != nil || total != 1 {
		t.Fatalf("recorder stored %d exchange(s) for the task (err=%v), want the probe's one", total, err)
	}
	m.sessMu.RLock()
	live := len(m.sessions)
	m.sessMu.RUnlock()
	if live != 0 {
		t.Fatalf("%d gateway session(s) still live after the probe batch", live)
	}

	mu.Lock()
	before := hits
	mu.Unlock()
	if title, status := probe(outside.URL + "/out"); status != nil || title != "" {
		t.Fatalf("an origin outside the grant was probed: title=%q status=%v", title, status)
	}
	mu.Lock()
	after := hits
	mu.Unlock()
	if after != before {
		t.Fatalf("the out-of-grant origin was contacted %d time(s)", after-before)
	}

	// Capture off: no recorder to probe through, and no direct fallback.
	m.mu.Lock()
	m.trafficOn = false
	m.mu.Unlock()
	if _, status := probe(grantedURL + "/off"); status != nil {
		t.Fatalf("a probe ran with capture off: status=%d", *status)
	}
}

// Each speed profile maps to its masking level, enrichment sessions always get
// navigation masking, and a session with no task (research, install) gets the
// default.
func TestMaskForMapsProfilesAndEnrichment(t *testing.T) {
	for profile, want := range map[string]string{
		db.SpeedProfileStealth:  "navigation",
		db.SpeedProfileCareful:  "ua",
		db.SpeedProfileStandard: "ua",
		db.SpeedProfileUnbound:  "ua",
		"no-such-profile":       "ua",
		"":                      "ua",
	} {
		if got := string(maskForProfile(profile)); got != want {
			t.Errorf("maskForProfile(%q) = %q, want %q", profile, got, want)
		}
	}
	m := &Manager{}
	for name, tc := range map[string]struct {
		s    netpolicy.Session
		want string
	}{
		"enrichment":       {netpolicy.Session{ID: enrichSessionPrefix + "abc", TaskID: 5, Purpose: netpolicy.PurposeTesting}, "navigation"},
		"research no task": {netpolicy.Session{ID: "r", Purpose: netpolicy.PurposeResearch}, "ua"},
		"install no task":  {netpolicy.Session{ID: "i", Purpose: netpolicy.PurposeInstall}, "ua"},
	} {
		if got := string(m.maskFor(tc.s)); got != tc.want {
			t.Errorf("%s: maskFor = %q, want %q", name, got, tc.want)
		}
	}
}

// maskFor must not read PostgreSQL per gateway request: two requests inside the
// TTL cost one profile read, and a stealth task maps to navigation masking.
func TestMaskForCachesTheTaskProfile(t *testing.T) {
	reads := 0
	m := &Manager{}
	m.readProfile = func(ctx context.Context, _ int64) (string, error) {
		reads++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("profile read has no deadline")
		}
		if !m.profMu.TryLock() {
			t.Error("profile cache is locked during the database read")
		} else {
			m.profMu.Unlock()
		}
		return db.SpeedProfileStealth, nil
	}
	s := netpolicy.Session{ID: "s", TaskID: 9, Purpose: netpolicy.PurposeTesting}
	for range 2 {
		if got := m.maskFor(s); got != "navigation" {
			t.Fatalf("maskFor = %q, want navigation", got)
		}
	}
	if reads != 1 {
		t.Fatalf("TaskSpeedProfile read %d times for two requests inside the TTL, want 1", reads)
	}
}

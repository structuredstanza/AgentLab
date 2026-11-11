package enrich

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/egress"
	"github.com/andybalholm/brotli"
)

// ---- fixtures ----------------------------------------------------------

// recordingGate is a real egress.Gate that admits everything and records the
// host of each request the proxy is about to forward. An absent host means no
// request left for it.
type recordingGate struct {
	mu    sync.Mutex
	hosts []string
}

func (g *recordingGate) Allow(_ context.Context, host, _ string) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hosts = append(g.hosts, host)
	return true, ""
}

func (g *recordingGate) seen(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, h := range g.hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func (g *recordingGate) snapshot() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.hosts...)
}

// startMaskingProxy runs the real masking egress proxy (the type `artex
// egress-proxy` serves) on a loopback port with a distinctive identity, and
// returns its URL plus the CA path a client must trust. The identity an origin
// sees can only come from this proxy, which is what makes assertions on it
// meaningful.
func startMaskingProxy(t *testing.T) (proxyURL, caFile string, gate *recordingGate) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "user-agent.txt"), []byte("FixtureMask/1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := egress.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create fixture CA: %v", err)
	}
	identity, err := egress.LoadIdentity(dir)
	if err != nil {
		t.Fatalf("load fixture identity: %v", err)
	}
	gate = &recordingGate{}
	p, err := egress.New("127.0.0.1:0", ca, identity, gate)
	if err != nil {
		t.Fatalf("start fixture masking proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = p.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("fixture masking proxy did not stop")
		}
	})
	return "http://" + p.Addr(), filepath.Join(dir, "ca.pem"), gate
}

// foreignCA writes a CA unrelated to the masking proxy's.
func foreignCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := egress.LoadOrCreateCA(dir); err != nil {
		t.Fatalf("create foreign CA: %v", err)
	}
	return filepath.Join(dir, "ca.pem")
}

// deadProxyURL returns a loopback URL nothing listens on.
func deadProxyURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	return "http://" + addr
}

// tlsServerOn starts a TLS origin on a specific loopback address, so two
// reachable origins can have different hosts (127.0.0.1 vs 127.0.0.2) and an
// exclusion of one does not cover the other.
func tlsServerOn(t *testing.T, addr string, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func testDB(t *testing.T) (*db.DB, *db.AssetStore) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, d.Assets()
}

func testTask(t *testing.T, d *db.DB) *db.Task {
	t.Helper()
	task, err := d.CreateTask("enrich fixture", "exercise asset auto-completion", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	return task
}

func upsertSite(t *testing.T, as *db.AssetStore, taskID int64, rawURL string) int64 {
	t.Helper()
	id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: rawURL, TaskID: taskID})
	if err != nil {
		t.Fatalf("seed service %s: %v", rawURL, err)
	}
	t.Cleanup(func() { _, _ = as.DeleteByHost(targetHost(rawURL)) })
	return id
}

func loadAsset(t *testing.T, as *db.AssetStore, id int64) *db.Asset {
	t.Helper()
	rows, err := as.GetByIDs([]int64{id})
	if err != nil {
		t.Fatalf("load asset %d: %v", id, err)
	}
	if len(rows) != 1 {
		t.Fatalf("asset %d not found", id)
	}
	return rows[0]
}

func staticRoute(proxyURL, caFile string) Options {
	return Options{Workers: 2, Proxy: proxyURL, CAFile: caFile}
}

// ---- behaviors ---------------------------------------------------------

// A persisted web asset is probed through the masking proxy and the result is
// written back to that asset. The origin sees the proxy's identity, not this
// process's own: the observable difference between a masked request and a
// direct dial that merely carries a browser User-Agent.
func TestEnrichProbePersistsResultThroughMaskingProxy(t *testing.T) {
	t.Setenv("ARTEX_USER_AGENT", "GoClient/1.0")
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, gate := startMaskingProxy(t)

	var mu sync.Mutex
	var seenUA, seenPath string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUA, seenPath = r.Header.Get("User-Agent"), r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><head><title> Enriched &amp; Fine </title></head><body>ok</body></html>")
	}))
	defer origin.Close()

	id := upsertSite(t, as, task.ID, origin.URL+"/")
	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()
	engine.ProbeSite(task.ID, id, origin.URL+"/")
	engine.Wait()

	got := loadAsset(t, as, id)
	if got.StatusCode == nil || *got.StatusCode != http.StatusOK {
		t.Fatalf("status_code not persisted: %v", got.StatusCode)
	}
	if got.PageTitle != "Enriched & Fine" {
		t.Fatalf("page_title = %q, want the origin's <title>", got.PageTitle)
	}
	if got.ContentLength == nil || *got.ContentLength == 0 {
		t.Fatalf("content_length not persisted: %v", got.ContentLength)
	}
	found := false
	for _, tid := range got.TaskIDs {
		if tid == task.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("enrichment lost the task context: asset task_ids=%v, want %d", got.TaskIDs, task.ID)
	}

	mu.Lock()
	ua, path := seenUA, seenPath
	mu.Unlock()
	if ua != "FixtureMask/1.0" {
		t.Fatalf("origin saw User-Agent %q, want the masking proxy's identity: the request did not go through the proxy", ua)
	}
	if path != "/" {
		t.Fatalf("origin saw path %q, want /", path)
	}
	if !gate.seen("127.0.0.1") {
		t.Fatalf("masking proxy never saw the target; gate recorded %v", gate.snapshot())
	}
}

// An explicitly excluded target is never contacted, even though it is reachable
// and its asset row was persisted before enrichment was scheduled.
func TestEnrichSkipsExcludedTarget(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, gate := startMaskingProxy(t)

	var mu sync.Mutex
	hits := 0
	origin := tlsServerOn(t, "127.0.0.2:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		io.WriteString(w, "<html><title>Reached</title></html>")
	}))
	if _, err := as.AddAgentScope(task.ID, "ip", "127.0.0.2", "operator excluded it", "manual", "exclude"); err != nil {
		t.Fatalf("record exclusion: %v", err)
	}

	id := upsertSite(t, as, task.ID, origin.URL+"/admin")
	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()
	engine.ProbeSite(task.ID, id, origin.URL+"/admin")
	engine.Wait()

	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 0 || len(gate.snapshot()) != 0 {
		t.Fatalf("an excluded target was contacted: origin hits=%d, proxy saw %v", got, gate.snapshot())
	}
	if a := loadAsset(t, as, id); a.StatusCode != nil {
		t.Fatalf("an excluded target's probe result was persisted: status=%d", *a.StatusCode)
	}
}

// A redirect is re-checked before it is followed. The destination here is a
// reachable origin, so the only thing keeping it uncontacted is the check.
func TestEnrichChecksRedirectDestinations(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, gate := startMaskingProxy(t)

	t.Run("excluded destination is not followed", func(t *testing.T) {
		var mu sync.Mutex
		hits := 0
		secret := tlsServerOn(t, "127.0.0.2:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			mu.Unlock()
			io.WriteString(w, "<html><title>Secret</title></html>")
		}))
		if _, err := as.AddAgentScope(task.ID, "ip", "127.0.0.2", "operator excluded it", "manual", "exclude"); err != nil {
			t.Fatalf("record exclusion: %v", err)
		}
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, secret.URL+"/secret", http.StatusFound)
		}))
		defer origin.Close()

		id := upsertSite(t, as, task.ID, origin.URL+"/start")
		engine := New(as, staticRoute(proxyURL, caFile))
		defer engine.Close()
		engine.ProbeSite(task.ID, id, origin.URL+"/start")
		engine.Wait()

		mu.Lock()
		got := hits
		mu.Unlock()
		if got != 0 || gate.seen("127.0.0.2") {
			t.Fatalf("the redirect destination was contacted: origin hits=%d, proxy saw %v", got, gate.snapshot())
		}
		a := loadAsset(t, as, id)
		if a.StatusCode == nil || *a.StatusCode != http.StatusFound {
			t.Fatalf("the in-boundary 302 was not recorded: status=%v", a.StatusCode)
		}
	})

	t.Run("in-boundary destination is followed", func(t *testing.T) {
		final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html><title>Final</title></html>")
		}))
		defer final.Close()
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL+"/landing", http.StatusFound)
		}))
		defer origin.Close()

		id := upsertSite(t, as, task.ID, origin.URL+"/hop")
		engine := New(as, staticRoute(proxyURL, caFile))
		defer engine.Close()
		engine.ProbeSite(task.ID, id, origin.URL+"/hop")
		engine.Wait()

		a := loadAsset(t, as, id)
		if a.StatusCode == nil || *a.StatusCode != http.StatusOK {
			t.Fatalf("a redirect inside the boundary was not followed: status=%v", a.StatusCode)
		}
		if a.PageTitle != "Final" {
			t.Fatalf("final page title = %q, want Final", a.PageTitle)
		}
	})
}

// When the masking proxy is unreachable the probe fails; it must not fall back
// to a direct connection, which would reach the target with this process's own
// TLS fingerprint.
func TestEnrichFailsClosedWithoutMaskingProxy(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)

	var mu sync.Mutex
	hits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		io.WriteString(w, "<html><title>Direct</title></html>")
	}))
	defer origin.Close()

	id := upsertSite(t, as, task.ID, origin.URL+"/")
	engine := New(as, staticRoute(deadProxyURL(t), foreignCA(t)))
	defer engine.Close()
	engine.ProbeSite(task.ID, id, origin.URL+"/")
	engine.Wait()

	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 0 {
		t.Fatalf("origin was contacted directly %d time(s) after the masking proxy failed", got)
	}
	if a := loadAsset(t, as, id); a.StatusCode != nil {
		t.Fatalf("a failed probe persisted a result: status=%d", *a.StatusCode)
	}
}

// The proxy's CA is trusted explicitly, and only it: a client trusting an
// unrelated CA fails verification instead of accepting the leaf unverified.
func TestEnrichTrustsOnlyTheEgressCA(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, _, _ := startMaskingProxy(t)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><title>Should Not Be Trusted</title></html>")
	}))
	defer origin.Close()

	id := upsertSite(t, as, task.ID, origin.URL+"/")
	engine := New(as, staticRoute(proxyURL, foreignCA(t)))
	defer engine.Close()
	engine.ProbeSite(task.ID, id, origin.URL+"/")
	engine.Wait()

	if a := loadAsset(t, as, id); a.StatusCode != nil {
		t.Fatalf("a leaf signed by the egress CA was accepted while only an unrelated CA was trusted: status=%d", *a.StatusCode)
	}
}

// No configured proxy means HTTP enrichment is disabled, not pointed at a
// guessed loopback port that some unrelated process may hold.
func TestEnrichHTTPDisabledWithoutConfiguredProxy(t *testing.T) {
	t.Setenv("ARTEX_EGRESS_PROXY", "")
	t.Setenv("ARTEX_EGRESS_CA", "")
	t.Setenv("SSL_CERT_FILE", "")
	d, as := testDB(t)
	task := testTask(t, d)

	var mu sync.Mutex
	hits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer origin.Close()

	id := upsertSite(t, as, task.ID, origin.URL+"/")
	engine := New(as, Options{Workers: 2})
	defer engine.Close()
	engine.ProbeSite(task.ID, id, origin.URL+"/")
	engine.Wait()

	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 0 {
		t.Fatalf("origin was contacted %d time(s) with no masking proxy configured", got)
	}
	if a := loadAsset(t, as, id); a.StatusCode != nil {
		t.Fatalf("a probe persisted a result with no masking proxy configured: status=%d", *a.StatusCode)
	}
}

// A job with no task context is dropped at enqueue: the engine is manager-wide,
// so there is no boundary to check the destination against. Dropping must not
// leak the wait-group count (Wait would hang).
func TestEnrichDropsJobsWithoutTaskContext(t *testing.T) {
	d, as := testDB(t)
	_ = d
	proxyURL, caFile, gate := startMaskingProxy(t)

	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()
	engine.ProbeSite(0, 1, "https://127.0.0.1/")
	engine.ResolveDomain(0, 1, "task-less.invalid")

	waited := make(chan struct{})
	go func() {
		engine.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait blocked: a task-less job was queued instead of dropped")
	}
	if len(gate.snapshot()) != 0 {
		t.Fatalf("a task-less job reached the proxy: %v", gate.snapshot())
	}
}

// Close rejects new work and leaves nothing queued or running, so Wait cannot
// block afterwards and no job can outlive the database.
func TestEnrichCloseRejectsNewJobsAndReleasesQueued(t *testing.T) {
	e := New(nil, Options{Workers: 1, Proxy: deadProxyURL(t), CAFile: foreignCA(t)})
	for i := int64(1); i <= 50; i++ {
		e.ProbeSite(1, i, "http://127.0.0.1:1/")
	}
	e.Close()
	e.ProbeSite(1, 999, "http://127.0.0.1:1/") // after Close: must not be accepted
	done := make(chan struct{})
	go func() {
		e.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait blocked after Close: an accepted job was stranded")
	}
	if n := len(e.jobs); n != 0 {
		t.Fatalf("%d job(s) still queued after Close", n)
	}
}

// One task's cooldown entry must not suppress another task's job for the same
// asset.
func TestEnrichCooldownIsPerTask(t *testing.T) {
	e := &Engine{cool: map[string]time.Time{}}
	if e.onCooldown(job{kind: jobHTTP, taskID: 1, id: 7}) {
		t.Fatal("first job was treated as a duplicate")
	}
	if !e.onCooldown(job{kind: jobHTTP, taskID: 1, id: 7}) {
		t.Fatal("same task, same asset was not deduplicated")
	}
	if e.onCooldown(job{kind: jobHTTP, taskID: 2, id: 7}) {
		t.Fatal("another task's job was suppressed by task 1's cooldown entry")
	}
}

// Proxy credentials never reach a log line.
func TestRedactProxyURLDropsCredentials(t *testing.T) {
	for _, raw := range []string{"http://user:s3cret@127.0.0.1:8888", "http://user:s3cret@127.0.0.1:8888/"} {
		got := RedactProxyURL(raw)
		if got != "http://127.0.0.1:8888" {
			t.Errorf("RedactProxyURL(%q) = %q", raw, got)
		}
	}
	if got := RedactProxyURL("::not a url::"); strings.Contains(got, "not a url") {
		t.Errorf("an unparseable proxy was echoed: %q", got)
	}
	err := errDetail(errors.New(`dial http://u:pw@10.0.0.1:3128 and https://t.example/?token=abc failed`), "https://t.example/?token=abc")
	if strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "abc") {
		t.Errorf("errDetail leaked a secret: %v", err)
	}
}

// A body over the read cap must not have the cap reported as its length.
func TestEnrichTruncatedBodyDoesNotStoreCapAsLength(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)

	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<title>Big</title>")
		io.WriteString(w, strings.Repeat("x", 2<<20))
	}))
	defer big.Close()
	id := upsertSite(t, as, task.ID, big.URL+"/big")
	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()
	engine.ProbeSite(task.ID, id, big.URL+"/big")
	engine.Wait()
	a := loadAsset(t, as, id)
	if a.PageTitle != "Big" {
		t.Fatalf("title from the read prefix not stored: %q", a.PageTitle)
	}
	if a.ContentLength != nil && *a.ContentLength == maxBodyBytes {
		t.Fatalf("the 1 MiB read cap was stored as the content length")
	}
}

// Dedup state stays bounded under a burst of distinct assets.
func TestEnrichCooldownStateIsBounded(t *testing.T) {
	e := &Engine{cool: map[string]time.Time{}}
	for i := int64(1); i <= maxCoolEntries+2*coolSweepEvery; i++ {
		e.onCooldown(job{kind: jobHTTP, id: i})
	}
	e.coolMu.Lock()
	n := len(e.cool)
	e.coolMu.Unlock()
	if n > maxCoolEntries+coolSweepEvery {
		t.Fatalf("dedup map grew to %d entries, want it bounded near %d", n, maxCoolEntries)
	}
}

// A second probe of the same asset inside the window is suppressed.
//
// Separate from the bound test on purpose: eviction drops arbitrary keys, so
// asserting that one particular key survived a burst is racy by construction.
func TestEnrichCooldownSuppressesRepeat(t *testing.T) {
	e := &Engine{cool: map[string]time.Time{}}
	j := job{kind: jobHTTP, id: 7}
	if e.onCooldown(j) {
		t.Fatal("the first probe was treated as a repeat")
	}
	if !e.onCooldown(j) {
		t.Fatal("a repeat probe was not suppressed")
	}
	if e.onCooldown(job{kind: jobHTTP, id: 8}) {
		t.Fatal("a different asset inherited the cooldown")
	}
}

type observationLog struct {
	mu  sync.Mutex
	obs []Observation
}

func (l *observationLog) add(o Observation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.obs = append(l.obs, o)
}

func (l *observationLog) all() []Observation {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Observation(nil), l.obs...)
}

// Every redirect hop is observed uniformly, exact bodies are offered as
// Complete, and a body that is over the cap is NOT offered as a body at all (a
// prefix would be bound later as if it were the whole response).
func TestEnrichObservesEveryHopAndNeverOffersAPrefix(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)

	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><title>Final</title></html>")
	}))
	defer final.Close()
	hop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/landing", http.StatusFound)
	}))
	defer hop.Close()
	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<title>Big</title>")
		io.WriteString(w, strings.Repeat("x", 2<<20))
	}))
	defer big.Close()

	var log observationLog
	engine := New(as, Options{Workers: 1, Proxy: proxyURL, CAFile: caFile, Observe: log.add})
	defer engine.Close()

	hopID := upsertSite(t, as, task.ID, hop.URL+"/start")
	engine.ProbeSite(task.ID, hopID, hop.URL+"/start")
	engine.Wait()
	got := log.all()
	if len(got) != 2 {
		t.Fatalf("a redirect chain must yield one observation per hop, got %d: %+v", len(got), got)
	}
	if got[0].Status != http.StatusFound || !got[0].Complete || got[0].Failed {
		t.Fatalf("first hop = %+v, want a complete 302", got[0])
	}
	if got[1].Status != http.StatusOK || !got[1].Complete || !strings.Contains(got[1].ResponseBody, "<title>Final</title>") {
		t.Fatalf("final hop = %+v, want the exact 200 body", got[1])
	}

	bigID := upsertSite(t, as, task.ID, big.URL+"/big")
	engine.ProbeSite(task.ID, bigID, big.URL+"/big")
	engine.Wait()
	all := log.all()
	last := all[len(all)-1]
	if last.Status != http.StatusOK || last.Complete || last.ResponseBody != "" {
		t.Fatalf("an over-cap body must be Complete=false with no body offered, got %+v", last)
	}
}

// A transport failure is observed as Failed (no response), with credentials
// scrubbed from the error text.
func TestEnrichObservesTransportFailureWithoutCredentials(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	dead := strings.Replace(deadProxyURL(t), "http://", "http://user:s3cret@", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	var log observationLog
	engine := New(as, Options{Workers: 1, Proxy: dead, CAFile: foreignCA(t), Observe: log.add})
	defer engine.Close()
	id := upsertSite(t, as, task.ID, origin.URL+"/")
	engine.ProbeSite(task.ID, id, origin.URL+"/")
	engine.Wait()

	got := log.all()
	if len(got) != 1 || !got[0].Failed || got[0].Status != 0 || got[0].Complete {
		t.Fatalf("a refused proxy connection must be one Failed observation, got %+v", got)
	}
	if msg := got[0].ResponseHeaders["x-capture-error"]; msg == "" || strings.Contains(msg, "s3cret") {
		t.Fatalf("failure text missing or leaked credentials: %q", msg)
	}
}

// Work for a task that is deleted, paused or finished is refused before any
// request leaves: such a task has no scope rows, which would otherwise read as
// "nothing is excluded".
func TestEnrichRefusesTasksThatAreNotLive(t *testing.T) {
	d, as := testDB(t)
	proxyURL, caFile, gate := startMaskingProxy(t)

	var mu sync.Mutex
	hits := 0
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		io.WriteString(w, "<title>Reached</title>")
	}))
	defer origin.Close()
	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()

	for name, stop := range map[string]func(*db.Task) error{
		"paused":   func(task *db.Task) error { return d.SetPaused(task.ID, true) },
		"finished": func(task *db.Task) error { return d.SetStatus(task.ID, "done") },
		"deleted":  func(task *db.Task) error { _, err := d.DeleteTaskCascade(task.ID, true, true); return err },
	} {
		t.Run(name, func(t *testing.T) {
			task := testTask(t, d)
			url := origin.URL + "/" + name
			id := upsertSite(t, as, task.ID, url)
			if err := stop(task); err != nil {
				t.Fatal(err)
			}
			engine.ProbeSite(task.ID, id, url)
			engine.Wait()
			mu.Lock()
			got := hits
			mu.Unlock()
			if got != 0 || len(gate.snapshot()) != 0 {
				t.Fatalf("a %s task's asset was contacted: origin hits=%d proxy saw %v", name, got, gate.snapshot())
			}
		})
	}
}

func TestEnrichResumedTaskCanRetryRefusedProbe(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<title>Resumed probe</title>")
	}))
	defer origin.Close()
	target := origin.URL + "/resume"
	id := upsertSite(t, as, task.ID, target)
	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	engine.ProbeSite(task.ID, id, target)
	engine.Wait()
	if err := d.SetPaused(task.ID, false); err != nil {
		t.Fatal(err)
	}
	engine.ProbeSite(task.ID, id, target)
	engine.Wait()
	rows, err := as.GetByIDs([]int64{id})
	if err != nil || len(rows) != 1 {
		t.Fatalf("load resumed asset: %v (%d rows)", err, len(rows))
	}
	if rows[0].PageTitle != "Resumed probe" {
		t.Fatalf("refused job consumed the retry's cooldown: title=%q", rows[0].PageTitle)
	}
}

// A task deleted while its probe is in flight must not get the asset recreated:
// the write re-checks the task row in the same transaction that writes.
func TestEnrichDeletionWhileProbeInFlightCannotRecreateAsset(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)

	started := make(chan struct{})
	release := make(chan struct{})
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "<title>Late</title>")
	}))
	defer origin.Close()
	url := origin.URL + "/slow"
	id := upsertSite(t, as, task.ID, url)
	engine := New(as, staticRoute(proxyURL, caFile))
	defer engine.Close()

	engine.ProbeSite(task.ID, id, url)
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the probe never reached the origin")
	}
	if _, err := d.DeleteTaskCascade(task.ID, true, true); err != nil {
		t.Fatal(err)
	}
	close(release)
	engine.Wait()

	var n int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE url=$1`, url).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("the probe recreated %d asset row(s) for a task deleted while it was in flight", n)
	}
}

func encodeBody(t *testing.T, coding string, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch coding {
	case "gzip":
		w := gzip.NewWriter(&buf)
		w.Write(plain)
		w.Close()
	case "deflate": // HTTP deflate = zlib-wrapped
		w := zlib.NewWriter(&buf)
		w.Write(plain)
		w.Close()
	case "deflate-raw": // the bare RFC 1951 stream some servers send
		w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		w.Write(plain)
		w.Close()
	case "br":
		w := brotli.NewWriter(&buf)
		w.Write(plain)
		w.Close()
	default:
		t.Fatalf("unknown coding %q", coding)
	}
	return buf.Bytes()
}

// The mask offers "gzip, deflate, br" and forwards whatever the origin picks, so
// the engine must decode all three itself. The stored length is the decoded
// size, and the wire observation stays the raw encoded bytes.
func TestEnrichDecodesContentEncodings(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)
	plain := []byte("<html><head><title>Encoded Title</title></head><body>" + strings.Repeat("padding ", 200) + "</body></html>")

	for _, coding := range []string{"gzip", "deflate", "deflate-raw", "br"} {
		t.Run(coding, func(t *testing.T) {
			wire := encodeBody(t, coding, plain)
			header := strings.TrimSuffix(coding, "-raw")
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Encoding", header)
				w.Write(wire)
			}))
			defer origin.Close()
			var obs observationLog
			engine := New(as, Options{Workers: 1, Proxy: proxyURL, CAFile: caFile, Observe: obs.add})
			defer engine.Close()
			url := origin.URL + "/" + coding
			id := upsertSite(t, as, task.ID, url)
			engine.ProbeSite(task.ID, id, url)
			engine.Wait()

			a := loadAsset(t, as, id)
			if a.PageTitle != "Encoded Title" {
				t.Fatalf("title from a %s body = %q (the compressed bytes were not decoded)", coding, a.PageTitle)
			}
			if a.ContentLength == nil || *a.ContentLength != int64(len(plain)) {
				t.Fatalf("content_length = %v, want the decoded size %d", a.ContentLength, len(plain))
			}
			got := obs.all()
			if len(got) != 1 || !got[0].Complete || got[0].ResponseBody != string(wire) {
				t.Fatalf("the observation must be the complete raw %s bytes, got %+v", coding, got)
			}
		})
	}
}

// Decoding is bounded by what is read DECODED: a tiny compressed body that
// expands enormously cannot exhaust memory, and a truncated decode reports no
// length.
func TestEnrichBoundsDecompressedBody(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)
	plain := append([]byte("<title>Bomb</title>"), bytes.Repeat([]byte{'a'}, 8<<20)...)
	wire := encodeBody(t, "gzip", plain)
	if len(wire) >= maxBodyBytes {
		t.Fatalf("fixture is not a bomb: %d compressed bytes", len(wire))
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(wire)
	}))
	defer origin.Close()
	engine := New(as, Options{Workers: 1, Proxy: proxyURL, CAFile: caFile})
	defer engine.Close()
	url := origin.URL + "/bomb"
	id := upsertSite(t, as, task.ID, url)
	engine.ProbeSite(task.ID, id, url)
	engine.Wait()

	a := loadAsset(t, as, id)
	if a.PageTitle != "Bomb" {
		t.Fatalf("title from the decoded prefix missing: %q", a.PageTitle)
	}
	if a.ContentLength != nil {
		t.Fatalf("a truncated decode reported a length: %d", *a.ContentLength)
	}
}

package server

import (
	"context"
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

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/enrich"
	"github.com/Autumn-27/artex/traffic"
)

// With traffic capture ON, a real recorder, a real masking proxy and TLS origins,
// enrichment goes straight to the mask in every case (hostname or IP literal,
// redirects included) with verification on, and what it exchanged is stored
// through the existing RecordExternal path — only when the evidence is exact.
func TestManagerEnrichmentWithCaptureOnAndTLSOrigins(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("manager enrich capture", "mask direct with first-party capture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	as := pg.Assets()

	edir := t.TempDir()
	if err := os.WriteFile(filepath.Join(edir, "user-agent.txt"), []byte("ManagerMask/1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := egress.LoadOrCreateCA(edir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := egress.LoadIdentity(edir)
	if err != nil {
		t.Fatal(err)
	}
	mask, err := egress.New("127.0.0.1:0", ca, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	mctx, mcancel := context.WithCancel(context.Background())
	mdone := make(chan struct{})
	go func() { defer close(mdone); _ = mask.Serve(mctx) }()
	defer func() {
		mcancel()
		_ = mask.Close()
		select {
		case <-mdone:
		case <-time.After(5 * time.Second):
		}
	}()

	// Real traffic store (capture ON). Its recorder is not in the probe path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	raddr := ln.Addr().String()
	_ = ln.Close()
	tr, err := traffic.Open(t.TempDir(), raddr)
	if err != nil {
		t.Fatalf("open traffic store: %v", err)
	}
	defer tr.Close()

	m := &Manager{
		pg: pg, assets: as, traffic: tr, trafficOn: true,
		enrichMask: "http://" + mask.Addr(), enrichMaskCA: filepath.Join(edir, "ca.pem"),
	}
	engine := enrich.New(as, enrich.Options{Workers: 1, Proxy: m.enrichMask, CAFile: m.enrichMaskCA, Observe: m.observeEnrichment})
	defer engine.Close()

	var mu sync.Mutex
	var uas []string
	origin := func(h http.HandlerFunc) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			uas = append(uas, r.Header.Get("User-Agent"))
			mu.Unlock()
			h(w, r)
		}))
	}
	probe := func(t *testing.T, rawURL string) (title string, status *int) {
		t.Helper()
		id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: rawURL, TaskID: task.ID})
		if err != nil {
			t.Fatal(err)
		}
		engine.ProbeSite(task.ID, id, rawURL)
		engine.Wait()
		rows, err := as.GetByIDs([]int64{id})
		if err != nil || len(rows) != 1 {
			t.Fatalf("load asset: %v (%d rows)", err, len(rows))
		}
		return rows[0].PageTitle, rows[0].StatusCode
	}
	count := func() int { n, _ := tr.Count(); return n }

	// Redirects: hostname -> final on an IP literal. Both hops are verified (the
	// mask mints the leaf for the CONNECT authority, IPs included) and recorded.
	t.Run("hostname redirecting to an https IP literal, every hop recorded", func(t *testing.T) {
		final := origin(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html><title>Chain Final</title></html>")
		})
		defer final.Close()
		hop := origin(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL+"/landing", http.StatusFound) // https://127.0.0.1:port
		})
		defer hop.Close()
		defer as.DeleteByHost("localhost")
		defer as.DeleteByHost("127.0.0.1")
		before := count()
		title, status := probe(t, strings.Replace(hop.URL, "127.0.0.1", "localhost", 1)+"/start")
		if title != "Chain Final" || status == nil || *status != http.StatusOK {
			t.Fatalf("redirect chain not persisted: title=%q status=%v", title, status)
		}
		if got := count() - before; got != 2 {
			t.Fatalf("expected both redirect hops recorded, got %d new exchanges", got)
		}
	})

	t.Run("https IP literal, no special route", func(t *testing.T) {
		o := origin(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html><title>IP Origin</title></html>")
		})
		defer o.Close()
		defer as.DeleteByHost("127.0.0.1")
		before := count()
		title, status := probe(t, o.URL+"/ip")
		if title != "IP Origin" || status == nil || *status != http.StatusOK {
			t.Fatalf("IP-literal TLS probe not persisted: title=%q status=%v", title, status)
		}
		if got := count() - before; got != 1 {
			t.Fatalf("expected 1 recorded exchange, got %d", got)
		}
	})

	t.Run("an over-cap body is probed but not stored as evidence", func(t *testing.T) {
		big := origin(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<title>Big Page</title>")
			io.WriteString(w, strings.Repeat("x", 2<<20))
		})
		defer big.Close()
		defer as.DeleteByHost("127.0.0.1")
		before := count()
		title, status := probe(t, big.URL+"/big")
		if title != "Big Page" || status == nil {
			t.Fatalf("big page not enriched: title=%q status=%v", title, status)
		}
		if got := count() - before; got != 0 {
			t.Fatalf("a partial body was stored in the traffic store (%d new exchanges)", got)
		}
	})

	t.Run("capture off stores nothing", func(t *testing.T) {
		m.mu.Lock()
		m.trafficOn = false
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			m.trafficOn = true
			m.mu.Unlock()
		}()
		o := origin(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "<title>Quiet</title>") })
		defer o.Close()
		defer as.DeleteByHost("127.0.0.1")
		before := count()
		if title, _ := probe(t, o.URL+"/quiet"); title != "Quiet" {
			t.Fatalf("probe failed with capture off: %q", title)
		}
		if got := count() - before; got != 0 {
			t.Fatalf("capture is off but %d exchange(s) were stored", got)
		}
	})

	mu.Lock()
	defer mu.Unlock()
	if len(uas) == 0 {
		t.Fatal("no origin was reached")
	}
	for _, ua := range uas {
		if ua != "ManagerMask/1.0" {
			t.Fatalf("an origin saw User-Agent %q, want the mask's identity", ua)
		}
	}
}

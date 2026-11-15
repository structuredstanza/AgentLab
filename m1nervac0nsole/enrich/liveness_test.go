package enrich

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/egress"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// unreachableAt reads the liveness marker straight from the row: Asset does not
// carry it, and NULL is the fact under test.
func unreachableAt(t *testing.T, d *db.DB, id int64) sql.NullString {
	t.Helper()
	var marker sql.NullString
	if err := d.QueryRow(`SELECT last_unreachable_at::text FROM assets WHERE id = $1`, id).Scan(&marker); err != nil {
		t.Fatalf("read last_unreachable_at for asset %d: %v", id, err)
	}
	return marker
}

// A successful probe is proof the host answered, so it must clear the marker a
// failed tcp_probe left: otherwise graph_overview keeps reporting a host that
// came back as unreachable until someone happens to dial it again.
func TestSuccessfulProbeClearsUnreachableMarker(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)
	proxyURL, caFile, _ := startMaskingProxy(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><title>Back</title></html>")
	}))
	defer origin.Close()

	target := origin.URL + "/"
	id := upsertSite(t, as, task.ID, target)
	if err := as.MarkUnreachable(targetHost(target)); err != nil {
		t.Fatalf("mark unreachable: %v", err)
	}
	if !unreachableAt(t, d, id).Valid {
		t.Fatalf("fixture: the marker was not set")
	}

	engine := New(as, staticRoute(d, proxyURL, caFile))
	defer engine.Close()
	engine.ProbeSite(task.ID, id, target)
	engine.Wait()

	if got := loadAsset(t, as, id); got.StatusCode == nil || *got.StatusCode != http.StatusOK {
		t.Fatalf("the probe did not store the answer: %v", got.StatusCode)
	}
	if marker := unreachableAt(t, d, id); marker.Valid {
		t.Fatalf("a host that answered is still listed unreachable since %s", marker.String)
	}
}

// A response the egress proxy labelled is the proxy's failure, not the target's
// answer, so it must leave the marker alone.
func TestProxyLabelledFailureKeepsUnreachableMarker(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(egress.HeaderEgress, "dial-failed")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "m1nervac0nsole egress: upstream dial-failed\n")
	}))
	defer proxy.Close()

	target := "http://203.0.113.7/probe"
	id := upsertSite(t, as, task.ID, target)
	if err := as.MarkUnreachable(targetHost(target)); err != nil {
		t.Fatalf("mark unreachable: %v", err)
	}

	engine := New(as, Options{Workers: 1, Proxy: proxy.URL, CAFile: foreignCA(t), Authorizer: netpolicy.NewAuthorizer(d)})
	defer engine.Close()
	engine.ProbeSite(task.ID, id, target)
	engine.Wait()

	if marker := unreachableAt(t, d, id); !marker.Valid {
		t.Fatalf("a proxy-labelled failure cleared the liveness marker: the target never answered")
	}
}

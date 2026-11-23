package enrich

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// A 502 carrying the proxy's failure header is the proxy's answer, not the
// target's. Storing it would record the proxy's failure as the site's status
// code and bump last_seen for a host that never answered.
func TestProxyLabelledFailureIsNotTheTargetsResponse(t *testing.T) {
	d, as := testDB(t)
	task := testTask(t, d)

	// Stands in for the gateway when it cannot dial the target: it answers the
	// request itself and names the stage.
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.Header().Set(gateway.HeaderStage, "dial")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "gateway: upstream dial failed\n")
	}))
	defer proxy.Close()

	engine := New(as, Options{Workers: 1, Route: staticRouteFunc(proxy.URL, foreignCA(t)), Authorizer: netpolicy.NewAuthorizer(d)})
	defer engine.Close()

	target := "http://203.0.113.7/probe"
	id := upsertSite(t, as, task.ID, target)
	// A known last_seen makes a bump visible even if the probe runs in the same
	// second as the insert.
	if _, err := d.Exec(`UPDATE assets SET last_seen = '2020-01-01T00:00:00Z' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	engine.ProbeSite(task.ID, id, target)
	engine.Wait()

	if n := proxyHits.Load(); n != 1 {
		t.Fatalf("the probe should have reached the proxy once, got %d", n)
	}
	asset := loadAsset(t, as, id)
	if asset.StatusCode != nil {
		t.Fatalf("the proxy's status was stored as the target's: %d", *asset.StatusCode)
	}
	if !strings.HasPrefix(asset.LastSeen, "2020-01-01") {
		t.Fatalf("a failed probe bumped last_seen to %q", asset.LastSeen)
	}
}

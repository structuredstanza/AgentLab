package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// TestMain dispatches the session child. A supervisor re-executes
// os.Executable() to build a session's filesystem, so a test binary that hosts
// one must answer that mode as well as run the tests.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "execbox" && os.Args[2] == execbox.ChildMode {
		os.Exit(execbox.RunChild(os.Args[3:]))
	}
	os.Exit(m.Run())
}

// integrationCredential is the session credential the gateway fixture demands.
// Production mints one per launch; the driver only needs an opaque string, and
// the gateway fixture is the only thing that checks it.
const integrationCredential = "integration-session-credential"

// fixtureBody is the marker the fixture origin returns, so the test asserts the
// response body and not merely that a navigation was attempted.
const fixtureBody = "gateway-fixture-body"

// fixtureOriginHost is the origin the task scope allows. It is not loopback, so
// Chromium sends it to the proxy instead of bypassing it.
const fixtureOriginHost = "fixture.invalid"

// excludedOriginHost is the destination the task scope refuses. The gateway
// refuses it too, so a request that reaches it is one no layer judged.
const excludedOriginHost = "excluded.invalid"

const fixturePage = `<!doctype html><html><head><title>Smoke</title></head><body>
<button onclick="document.getElementById('out').textContent='clicked'">Press</button>
<input aria-label="Name">
<a href="/popup" target="_blank" onclick="window.__popup = window.open('/popup','fixture-popup'); return false;">Popup</a>
<div id="out">waiting</div>
<p>` + fixtureBody + `</p>
</body></html>`

// workerScript runs in a dedicated worker. Its own script is in scope, so the
// worker must run; both requests it makes to the excluded origin must be
// refused, and it reports which of the two got through.
const workerScript = `let imported = "ok";
try { importScripts("http://` + excludedOriginHost + `/import.js"); } catch (e) { imported = "blocked"; }
fetch("http://` + excludedOriginHost + `/worker-fetch").then(
  () => self.postMessage("fetch-ok:" + imported),
  () => self.postMessage("fetch-blocked:" + imported)
);`

// sharedWorkerScript is the same case for a shared worker: the script is in
// scope, the request it makes is not.
const sharedWorkerScript = `onconnect = (e) => {
  const port = e.ports[0];
  fetch("http://` + excludedOriginHost + `/shared-fetch").then(
    () => port.postMessage("fetch-ok"),
    () => port.postMessage("fetch-blocked")
  );
};`

// newFixtureOrigin serves the pages and scripts the browser cases drive. A path
// the fixture does not know is a 404, so a case cannot pass on a wrong document.
func newFixtureOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/popup":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(fixturePage))
		case "/frame":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><p>allowed-frame-body</p></body></html>"))
		case "/worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte(workerScript))
		case "/shared-worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte(sharedWorkerScript))
		case "/redirect-out":
			http.Redirect(w, r, "http://"+excludedOriginHost+"/redirected", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// excludedOrigin counts every hit it receives. The gateway refuses its host, so
// a non-zero count means a request reached the destination no layer refused.
type excludedOrigin struct {
	*httptest.Server

	hits atomic.Int64
}

func newExcludedOrigin(t *testing.T) *excludedOrigin {
	t.Helper()
	o := &excludedOrigin{}
	o.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		o.hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>excluded-origin-body</p></body></html>"))
	}))
	t.Cleanup(o.Close)
	return o
}

// TestIntegrationRealChromium is the one test that talks to a browser. It is
// opt-in so the unit suite stays hermetic, and it reports BLOCKED rather than
// passing silently when the host cannot provide the boundary.
//
// The browser runs in a real execbox session, so the only address it can reach
// is the gateway. The gateway fixture refuses an unauthenticated request the
// way the recorder does, and the driver answers the challenge over CDP: that is
// the path a navigation takes in production, and the body the page ends up
// holding is the proof it worked.
func TestIntegrationRealChromium(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_BROWSER_INTEGRATION") != "1" {
		t.Skip("set M1NERVAC0NSOLE_BROWSER_INTEGRATION=1 to drive a real Chromium")
	}
	exe := chromiumPath(t)
	env := newBrowserEnv(t)

	ctx, cancel := context.WithTimeout(env.ctx, 120*time.Second)
	defer cancel()
	d, err := Launch(ctx, Options{
		Executable:  exe,
		UserDataDir: env.profile,
		ProxyServer: "http://" + env.gateway.addr(),
		ProxyUser:   integrationCredential,
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer d.Close()

	// fixture.invalid is not loopback, so Chromium sends it to the proxy instead
	// of bypassing it, and the proxy resolves it to the local origin.
	if _, err := d.Navigate(ctx, "http://fixture.invalid/"); err != nil {
		t.Fatalf("navigate through the gateway: %v", err)
	}
	if err := d.Wait(ctx, fixtureBody, 10*time.Second); err != nil {
		t.Fatalf("the fixture body never reached the page: %v", err)
	}
	if env.gateway.challenges() == 0 {
		t.Fatal("the gateway never challenged: the CDP authentication path was not exercised")
	}

	snap, err := d.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	button := refFor(t, snap.Tree, `button "Press"`)
	if _, err := d.Click(ctx, button); err != nil {
		t.Fatalf("click: %v", err)
	}
	if err := d.Wait(ctx, "clicked", 5*time.Second); err != nil {
		t.Fatalf("wait after click: %v", err)
	}

	snap, err = d.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot after click: %v", err)
	}
	input := refFor(t, snap.Tree, `textbox "Name"`)
	if _, err := d.Type(ctx, input, "hello"); err != nil {
		t.Fatalf("type: %v", err)
	}
	if err := d.Wait(ctx, "hello", 5*time.Second); err != nil {
		t.Fatalf("wait after type: %v", err)
	}

	png, err := d.Screenshot(ctx, false)
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("screenshot is not a PNG: %d bytes", len(png))
	}

	// A popup is a target created after the session started, so nothing attaches
	// it at launch. It must be attached and intercepted before it runs: its
	// requests are answered on its own session, and the body it ends up holding
	// is the proof the interception reached it.
	snap, err = d.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot before the popup: %v", err)
	}
	popupLink := refFor(t, snap.Tree, `link "Popup"`)
	if _, err := d.Click(ctx, popupLink); err != nil {
		t.Fatalf("click the popup link: %v", err)
	}
	if err := waitForPopupBody(ctx, d, fixtureBody, 20*time.Second); err != nil {
		t.Fatalf("the popup never loaded the fixture body: %v", err)
	}
	if popups := d.Popups(); len(popups) != 1 {
		t.Fatalf("popups = %v, want the one the driver attached", popups)
	}
}

// waitForPopupBody polls the page's own handle on the popup it opened: the
// driver drives the page, so the popup's body is read through the opener. A
// popup whose interception never reached it holds the gateway's error page
// instead of the fixture body.
func waitForPopupBody(ctx context.Context, d *Driver, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		raw, err := d.Send(ctx, "Runtime.evaluate", map[string]any{
			"expression":    `(() => { try { const w = window.__popup; if (!w || w.closed || !w.document || !w.document.body) return ""; return w.document.body.innerText; } catch (e) { return "unreadable"; } })()`,
			"returnByValue": true,
		})
		if err == nil {
			var res struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			if json.Unmarshal(raw, &res) == nil {
				last = res.Result.Value
				if strings.Contains(last, want) {
					return nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("last popup body %q, want %q", last, want)
}

// integrationScope is the task scope the driver must enforce: the fixture
// origin is in scope, every other host is not, and a URL the browser handles
// itself is never a host decision.
func integrationScope(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("%s is not a URL", rawURL)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "about", "data", "blob", "javascript":
		return nil
	}
	if strings.EqualFold(parsed.Hostname(), fixtureOriginHost) {
		return nil
	}
	return fmt.Errorf("%s is outside the task scope", parsed.Hostname())
}

// TestIntegrationChildTargetsStayInScope drives what the unit tests cannot
// decide: a popup whose destination is assigned after it opens, a redirect from
// an allowed URL to an excluded one, and a worker, a shared worker and a frame
// whose own requests must never reach an excluded origin.
//
// The excluded origin counts every hit, so a case passes only when the request
// was refused before it left the browser or at the gateway. The page's own
// script is the usability check: a target left paused would hold it up.
func TestIntegrationChildTargetsStayInScope(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_BROWSER_INTEGRATION") != "1" {
		t.Skip("set M1NERVAC0NSOLE_BROWSER_INTEGRATION=1 to drive a real Chromium")
	}
	exe := chromiumPath(t)
	env := newBrowserEnv(t)

	ctx, cancel := context.WithTimeout(env.ctx, 180*time.Second)
	defer cancel()
	d, err := Launch(ctx, Options{
		Executable:   exe,
		UserDataDir:  env.profile,
		ProxyServer:  "http://" + env.gateway.addr(),
		ProxyUser:    integrationCredential,
		AllowRequest: integrationScope,
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer d.Close()

	if _, err := d.Navigate(ctx, "http://"+fixtureOriginHost+"/"); err != nil {
		t.Fatalf("navigate through the gateway: %v", err)
	}
	if err := d.Wait(ctx, fixtureBody, 10*time.Second); err != nil {
		t.Fatalf("the fixture body never reached the page: %v", err)
	}

	t.Run("popup with a delayed allowed destination", func(t *testing.T) {
		if _, err := evaluate(ctx, d, `(() => {
			window.__popup = window.open('about:blank', 'late-allowed');
			setTimeout(() => { window.__popup.location = 'http://`+fixtureOriginHost+`/popup'; }, 250);
			return 'opened';
		})()`); err != nil {
			t.Fatalf("open the popup: %v", err)
		}
		if err := waitForPopupBody(ctx, d, fixtureBody, 20*time.Second); err != nil {
			t.Fatalf("the popup never loaded the allowed destination: %v", err)
		}
		if popups := d.Popups(); len(popups) != 1 || popups[0] != "http://"+fixtureOriginHost+"/popup" {
			t.Fatalf("popups = %v, want the destination the popup asked for", popups)
		}
	})

	t.Run("popup with a delayed excluded destination", func(t *testing.T) {
		before := env.excluded.hits.Load()
		// Start from an empty refusal list: the popup's document request is the
		// only thing that can put the excluded host back in it.
		d.BlockedRequests()
		if _, err := evaluate(ctx, d, `(() => {
			window.__popup = window.open('about:blank', 'late-excluded');
			setTimeout(() => { window.__popup.location = 'http://`+excludedOriginHost+`/popup'; }, 250);
			return 'opened';
		})()`); err != nil {
			t.Fatalf("open the popup: %v", err)
		}
		// The popup's document request is refused, so the entry keeps the
		// placeholder the browser reported and the origin is never contacted.
		if err := waitForBlocked(d, excludedOriginHost, 20*time.Second); err != nil {
			t.Fatalf("the popup's excluded destination was not refused: %v", err)
		}
		if popups := d.Popups(); len(popups) != 1 || !popupPlaceholder(popups[0]) {
			t.Fatalf("popups = %v, want the unnamed popup: its document never loaded", popups)
		}
		if got := env.excluded.hits.Load(); got != before {
			t.Fatalf("the excluded origin was hit %d times by a popup", got-before)
		}
	})

	t.Run("worker requests never reach the excluded origin", func(t *testing.T) {
		before := env.excluded.hits.Load()
		denials := env.gateway.denials()
		d.BlockedRequests()
		if _, err := evaluate(ctx, d, `(() => {
			window.__worker = 'pending';
			const w = new Worker('/worker.js');
			w.onmessage = (e) => { window.__worker = e.data; };
			w.onerror = () => { window.__worker = 'worker-error'; };
			return 'started';
		})()`); err != nil {
			t.Fatalf("start the worker: %v", err)
		}
		// The worker ran. Either the driver refused its requests before they
		// left the browser or the gateway refused them, so the origin is
		// untouched; the excluded script never loaded either way.
		result, err := waitForExpression(ctx, d, `window.__worker`, func(got string) bool {
			return strings.HasPrefix(got, "fetch-")
		}, 20*time.Second)
		if err != nil {
			t.Fatalf("the worker never reported: %v", err)
		}
		if !strings.HasSuffix(result, "blocked") {
			t.Fatalf("the worker imported the excluded script: %q", result)
		}
		layer, err := waitForRefusal(d, env, denials, 20*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("worker requests refused by the %s", layer)
		if got := env.excluded.hits.Load(); got != before {
			t.Fatalf("the excluded origin was hit %d times by a worker", got-before)
		}
	})

	t.Run("shared worker requests never reach the excluded origin", func(t *testing.T) {
		before := env.excluded.hits.Load()
		denials := env.gateway.denials()
		d.BlockedRequests()
		if _, err := evaluate(ctx, d, `(() => {
			window.__shared = 'pending';
			const w = new SharedWorker('/shared-worker.js');
			w.port.onmessage = (e) => { window.__shared = e.data; };
			w.port.start();
			return 'started';
		})()`); err != nil {
			t.Fatalf("start the shared worker: %v", err)
		}
		if _, err := waitForExpression(ctx, d, `window.__shared`, func(got string) bool {
			return strings.HasPrefix(got, "fetch-")
		}, 20*time.Second); err != nil {
			t.Fatalf("the shared worker never reported: %v", err)
		}
		layer, err := waitForRefusal(d, env, denials, 20*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("shared worker requests refused by the %s", layer)
		if got := env.excluded.hits.Load(); got != before {
			t.Fatalf("the excluded origin was hit %d times by a shared worker", got-before)
		}
	})

	t.Run("frame requests never reach the excluded origin", func(t *testing.T) {
		before := env.excluded.hits.Load()
		denials := env.gateway.denials()
		d.BlockedRequests()
		if _, err := evaluate(ctx, d, `(() => {
			window.__frame = 'pending';
			window.__excludedFrame = 'pending';
			const allowed = document.createElement('iframe');
			allowed.src = '/frame';
			allowed.onload = () => {
				try { window.__frame = allowed.contentDocument.body.innerText.trim(); }
				catch (e) { window.__frame = 'unreadable'; }
			};
			document.body.appendChild(allowed);
			const other = document.createElement('iframe');
			other.src = 'http://`+excludedOriginHost+`/frame';
			other.onload = () => { window.__excludedFrame = 'settled'; };
			other.onerror = () => { window.__excludedFrame = 'settled'; };
			document.body.appendChild(other);
			return 'started';
		})()`); err != nil {
			t.Fatalf("create the frames: %v", err)
		}
		// The allowed frame loads, and the excluded one settles without its
		// document: a frame left paused would settle neither.
		if err := waitForValue(ctx, d, `window.__frame`, "allowed-frame-body", 20*time.Second); err != nil {
			t.Fatalf("the allowed frame never loaded: %v", err)
		}
		if _, err := waitForExpression(ctx, d, `window.__excludedFrame`, func(got string) bool {
			return got != "pending"
		}, 20*time.Second); err != nil {
			t.Fatalf("the excluded frame never settled, so its target is still paused: %v", err)
		}
		layer, err := waitForRefusal(d, env, denials, 20*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("frame requests refused by the %s", layer)
		if got := env.excluded.hits.Load(); got != before {
			t.Fatalf("the excluded origin was hit %d times by a frame", got-before)
		}
	})

	t.Run("redirect from an allowed url to an excluded one", func(t *testing.T) {
		before := env.excluded.hits.Load()
		d.BlockedRequests()
		// The redirect is a new document request, so it is judged like any
		// other: the allowed URL does not authorize where it points. The
		// evaluate may lose its context to the navigation it starts, so the
		// refusal below is what proves the navigation ran.
		_, _ = evaluate(ctx, d, `(() => { location.href = '/redirect-out'; return 'navigating'; })()`)
		if err := waitForBlocked(d, excludedOriginHost, 20*time.Second); err != nil {
			t.Fatalf("the redirect target was not refused: %v", err)
		}
		if got := env.excluded.hits.Load(); got != before {
			t.Fatalf("the excluded origin was hit %d times by a redirect", got-before)
		}
	})

	// The page keeps running after every child target: one left paused would
	// hold up the script that created it.
	if _, err := d.Navigate(ctx, "http://"+fixtureOriginHost+"/"); err != nil {
		t.Fatalf("navigate back to the fixture page: %v", err)
	}
	if got, err := evaluate(ctx, d, `document.title`); err != nil || got != "Smoke" {
		t.Fatalf("the page stopped responding: %q, %v", got, err)
	}
	// Which layer refused the excluded requests is the evidence the plan asks
	// for: the driver normally, the gateway when a target type cannot be
	// intercepted. Both leave the excluded origin untouched.
	t.Logf("driver refused %d hosts, gateway refused %d out-of-scope requests",
		len(d.BlockedRequests()), env.gateway.denials())
}

// evaluate runs one expression in the page and returns its value. A user
// gesture is set because a popup opened without one is blocked by the browser.
func evaluate(ctx context.Context, d *Driver, expression string) (string, error) {
	raw, err := d.Send(ctx, "Runtime.evaluate", map[string]any{
		"expression":    expression,
		"returnByValue": true,
		"userGesture":   true,
	})
	if err != nil {
		return "", err
	}
	var res struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", err
	}
	if res.ExceptionDetails != nil {
		return "", fmt.Errorf("%s", res.ExceptionDetails.Text)
	}
	if res.Result.Value == nil {
		return "", nil
	}
	return fmt.Sprint(res.Result.Value), nil
}

// waitForExpression polls an expression until it satisfies ok, and returns the
// value it settled on.
func waitForExpression(ctx context.Context, d *Driver, expression string, ok func(string) bool, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		got, err := evaluate(ctx, d, expression)
		if err == nil {
			last = got
			if ok(got) {
				return got, nil
			}
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last, fmt.Errorf("last value %q", last)
}

// waitForValue polls an expression until it returns want.
func waitForValue(ctx context.Context, d *Driver, expression, want string, timeout time.Duration) error {
	_, err := waitForExpression(ctx, d, expression, func(value string) bool {
		return value == want
	}, timeout)
	if err != nil {
		return fmt.Errorf("%v, want %q", err, want)
	}
	return nil
}

// blockedHosts is a snapshot of the hosts the driver refused, without draining
// the list a tool result reports.
func blockedHosts(d *Driver) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.blocked...)
}

// waitForBlocked waits until the driver refused one host.
func waitForBlocked(d *Driver, host string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last []string
	for time.Now().Before(deadline) {
		last = blockedHosts(d)
		for _, got := range last {
			if got == host {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("blocked = %v, want %s", last, host)
}

// waitForRefusal waits until the driver or the gateway refused the excluded
// host, and reports which layer did it. Both are acceptable for a target type
// the browser may not let the driver intercept; the origin stays untouched
// either way.
func waitForRefusal(d *Driver, env *browserEnv, denials int, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, host := range blockedHosts(d) {
			if host == excludedOriginHost {
				return "driver", nil
			}
		}
		if env.gateway.denials() > denials {
			return "gateway", nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("neither the driver nor the gateway refused %s", excludedOriginHost)
}

// TestLaunchWithoutSessionIsRefused is the hermetic case: a browser that cannot
// be given a session must be refused, not started outside the boundary and not
// left waiting for one that will never arrive.
func TestLaunchWithoutSessionIsRefused(t *testing.T) {
	execbox.Install(fakeExecClient{})
	t.Cleanup(func() { execbox.Install(nil) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Launch(ctx, Options{Executable: "/bin/true", UserDataDir: t.TempDir()})
	if !errors.Is(err, execbox.ErrNoSession) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("launch without a session = %v, want the execbox session refusal", err)
	}
}

// TestGatewayFixtureChallengesAndForwards is the hermetic half of the real
// case: the fixture the browser must satisfy refuses a request with no session
// credential and serves the fixture body once the credential arrives. Without
// it a broken fixture would only ever show up in the root-only run.
func TestGatewayFixtureChallengesAndForwards(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fixturePage))
	}))
	defer origin.Close()
	gw := newGatewayFixture(t, origin.URL)

	proxyURL, err := url.Parse("http://" + gw.addr())
	if err != nil {
		t.Fatal(err)
	}
	anonymous := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := anonymous.Get("http://fixture.invalid/")
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated request = %d, want 407", resp.StatusCode)
	}
	if gw.challenges() != 1 {
		t.Fatalf("challenges = %d, want 1", gw.challenges())
	}

	// The credential is the proxy URL's user name, which is how the recording
	// gateway receives it.
	proxyURL.User = url.User(integrationCredential)
	authenticated := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err = authenticated.Get("http://fixture.invalid/")
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), fixtureBody) {
		t.Fatalf("body = %q, want the fixture marker", body)
	}
}

// chromiumPath resolves the browser binary, or reports the missing prerequisite.
func chromiumPath(t *testing.T) string {
	t.Helper()
	exe := os.Getenv("M1NERVAC0NSOLE_CHROMIUM")
	if exe == "" {
		exe = "/opt/ms-playwright/current/chrome"
	}
	if _, err := os.Stat(exe); err == nil {
		return exe
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
		if found, err := exec.LookPath(name); err == nil {
			return found
		}
	}
	t.Skipf("BLOCKED: needs a Chromium binary (set M1NERVAC0NSOLE_CHROMIUM or install %s)", exe)
	return ""
}

// browserEnv is one supervisor, one gateway fixture and the session context a
// launch runs under.
type browserEnv struct {
	ctx      context.Context
	gateway  *gatewayFixture
	excluded *excludedOrigin
	profile  string
}

func newBrowserEnv(t *testing.T) *browserEnv {
	t.Helper()
	requireBoundary(t)

	base := t.TempDir()
	tasks := filepath.Join(base, "tasks")
	profile := filepath.Join(tasks, "1", "browser-profile")
	// The registry creates the profile root-owned and the supervisor hands it to
	// the session uid before the browser starts.
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}

	// The origin the browser must reach: a local fixture, never a real target.
	origin := newFixtureOrigin(t)
	gw := newGatewayFixture(t, origin.URL)
	// The gateway refuses the excluded host the way production does, so a
	// request that gets past the driver still never reaches that origin.
	gw.exclude(excludedOriginHost)
	excluded := newExcludedOrigin(t)

	cfg := execbox.DefaultConfig()
	cfg.Socket = filepath.Join(base, "supervisor.sock")
	cfg.StateDir = filepath.Join(base, "state")
	cfg.CgroupRoot = filepath.Join("/sys/fs/cgroup", fmt.Sprintf("execbox-browser-%d", os.Getpid()))
	cfg.WritableRoots = []string{tasks}
	cfg.ToolboxRoot = filepath.Join(base, "toolbox")
	cfg.Gateway = gw.addr()
	cfg.Resolver = "127.0.0.1:53"
	cfg.Logf = t.Logf
	sup, err := execbox.NewSupervisor(cfg)
	if err != nil {
		t.Skipf("BLOCKED: needs a working execbox supervisor: %v", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sup.Serve(ctx)
	}()
	t.Cleanup(func() {
		stop()
		_ = sup.Close()
		<-done
		_ = os.Remove(cfg.CgroupRoot)
	})
	waitForSocket(t, cfg.Socket)

	// Production installs one client for the process and gives each launch a
	// session of its own.
	execbox.Install(execbox.NewClient(cfg.Socket))
	t.Cleanup(func() { execbox.Install(nil) })

	sess := netpolicy.Session{
		ID: "browser-integration", TaskID: 1, ConversationID: 1,
		Purpose: netpolicy.PurposeTesting, Revision: 1,
	}
	return &browserEnv{ctx: execbox.WithSession(ctx, sess), gateway: gw, excluded: excluded, profile: profile}
}

// requireBoundary names the missing prerequisite instead of skipping green: a
// browser outside the boundary proves nothing about the browser.
func requireBoundary(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BLOCKED: needs root (the execbox supervisor creates namespaces, cgroups and iptables rules)")
	}
	for _, bin := range []string{"ip", "iptables", "setpriv"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("BLOCKED: needs %s", bin)
		}
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("BLOCKED: needs cgroup v2 mounted at /sys/fs/cgroup")
	}
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		t.Skip("BLOCKED: needs network namespaces")
	}
}

// gatewayFixture is the recording gateway's shape: a proxy that answers a
// request carrying no Proxy-Authorization with 407, refuses a host outside the
// task scope the way the gateway does, and forwards an authenticated in-scope
// request to the origin.
type gatewayFixture struct {
	*httptest.Server

	mu       sync.Mutex
	refused  int
	denied   int
	excluded map[string]bool
}

func newGatewayFixture(t *testing.T, originURL string) *gatewayFixture {
	t.Helper()
	origin, err := url.Parse(originURL)
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(integrationCredential+":"))
	forward := httputil.NewSingleHostReverseProxy(origin)
	// Chromium sends its background https requests as CONNECT, which this
	// fixture does not serve; the rejection is expected, not an error to print.
	forward.ErrorLog = log.New(io.Discard, "", 0)
	g := &gatewayFixture{excluded: map[string]bool{}}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != want {
			g.mu.Lock()
			g.refused++
			g.mu.Unlock()
			w.Header().Set("Proxy-Authenticate", `Basic realm="gateway"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if g.refuseHost(r.URL.Hostname()) {
			http.Error(w, "outside the task scope", http.StatusForbidden)
			return
		}
		forward.ServeHTTP(w, r)
	}))
	t.Cleanup(g.Close)
	return g
}

// exclude makes the fixture refuse one host, the way the gateway refuses a host
// the task scope does not cover.
func (g *gatewayFixture) exclude(host string) {
	g.mu.Lock()
	g.excluded[host] = true
	g.mu.Unlock()
}

// refuseHost counts one out-of-scope request and reports whether it is refused.
func (g *gatewayFixture) refuseHost(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.excluded[host] {
		return false
	}
	g.denied++
	return true
}

// denials counts the requests the gateway refused for being out of scope.
func (g *gatewayFixture) denials() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.denied
}

// addr is the host:port the supervisor admits and the browser dials.
func (g *gatewayFixture) addr() string { return g.Listener.Addr().String() }

// challenges counts the requests the gateway refused for want of a credential.
func (g *gatewayFixture) challenges() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refused
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("supervisor socket %s never appeared", path)
}

func refFor(t *testing.T, tree, needle string) string {
	t.Helper()
	for _, line := range strings.Split(tree, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		start := strings.Index(line, "[ref=")
		end := strings.Index(line, "]")
		if start < 0 || end <= start {
			continue
		}
		return line[start+len("[ref=") : end]
	}
	t.Fatalf("no ref for %q in:\n%s", needle, tree)
	return ""
}

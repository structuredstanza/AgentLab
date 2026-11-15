package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// The pipe is the only transport detail a browser would otherwise hide: a
// request must be NUL-terminated and a response must unblock the matching id.
func TestPipeConnFramesNulTerminatedMessages(t *testing.T) {
	clientOut, serverIn := net.Pipe()
	serverOut, clientIn := net.Pipe()
	p := newPipeConn(clientOut, clientIn, nil)
	defer p.Close()

	events := make(chan string, 1)
	p.On(func(method string, params json.RawMessage) {
		events <- method
	})

	go func() {
		reader := bufio.NewReader(serverIn)
		line, err := reader.ReadBytes(0)
		if err != nil {
			return
		}
		var request struct {
			ID int64 `json:"id"`
		}
		if json.Unmarshal(line[:len(line)-1], &request) != nil {
			return
		}
		serverOut.Write([]byte(`{"id":` + strconv.FormatInt(request.ID, 10) + `,"result":{"ok":true}}` + "\x00"))
		serverOut.Write([]byte(`{"method":"Page.loadEventFired","params":{}}` + "\x00"))
	}()

	raw, err := p.Send(context.Background(), "Test.ping", map[string]any{"n": 1})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if string(raw) != `{"ok":true}` {
		t.Fatalf("result = %s", raw)
	}

	select {
	case method := <-events:
		if method != "Page.loadEventFired" {
			t.Fatalf("event = %q", method)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not dispatched")
	}
}

// A dead process must not lose the task: the driver relaunches on the same
// profile and puts the page, the viewport and the parked dialog back.
func TestRecoveryRelaunchesAndRestoresState(t *testing.T) {
	first := newFakeConn()
	first.replies["Page.navigate"] = map[string]any{"frameId": "F1"}
	first.emitOn["Page.navigate"] = []fakeEvent{{Method: "Page.loadEventFired", Params: map[string]any{}}}
	first.replies["Page.getNavigationHistory"] = map[string]any{
		"currentIndex": 0,
		"entries": []any{
			map[string]any{"url": "https://example.test/start", "title": "Start"},
		},
	}
	first.replies["Emulation.setDeviceMetricsOverride"] = map[string]any{}

	second := newFakeConn()
	second.replies["Page.enable"] = map[string]any{}
	second.replies["DOM.enable"] = map[string]any{}
	second.replies["Page.navigate"] = map[string]any{"frameId": "F2"}
	second.replies["Emulation.setDeviceMetricsOverride"] = map[string]any{}
	second.replies["Accessibility.getFullAXTree"] = json.RawMessage(axButtonFixture)

	launches := 0
	d := newTestDriver(t, first, func(context.Context) (conn, error) {
		launches++
		return second, nil
	})
	ctx := context.Background()

	if _, err := d.Navigate(ctx, "https://example.test/start"); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := d.SetViewport(ctx, Viewport{Width: 1024, Height: 768}); err != nil {
		t.Fatalf("viewport: %v", err)
	}
	d.mu.Lock()
	d.parked = &Dialog{Type: "alert", Message: "still pending"}
	d.mu.Unlock()

	first.setDead(true)
	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot after crash: %v", err)
	}
	if launches != 1 {
		t.Fatalf("relaunches = %d, want 1", launches)
	}

	navigations := second.callsOf("Page.navigate")
	if len(navigations) != 1 {
		t.Fatalf("restore navigations = %d, want 1", len(navigations))
	}
	var restored struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(navigations[0].Params, &restored); err != nil {
		t.Fatalf("decode restore: %v", err)
	}
	if restored.URL != "https://example.test/start" {
		t.Fatalf("restored URL = %q", restored.URL)
	}
	if got := len(second.callsOf("Emulation.setDeviceMetricsOverride")); got != 1 {
		t.Fatalf("viewport restores = %d, want 1", got)
	}
	if got := d.URL(); got != "https://example.test/start" {
		t.Fatalf("URL() = %q", got)
	}
	parked, ok := d.PendingDialog()
	if !ok || parked.Message != "still pending" {
		t.Fatalf("parked dialog = %+v, %v; want it preserved", parked, ok)
	}
}

// attachTarget emits what the browser sends for a target it auto-attached: a
// popup, a worker, anything a page creates after the session started.
func attachTarget(f *fakeConn, session, targetID, kind, url string) {
	f.emit("Target.attachedToTarget", map[string]any{
		"sessionId":          session,
		"waitingForDebugger": true,
		"targetInfo": map[string]any{
			"targetId": targetID,
			"type":     kind,
			"url":      url,
		},
	})
}

// A popup is a target the driver did not attach to at launch. It must get the
// page's interception before it runs, or it never reaches the gateway and
// nothing judges where it goes.
func TestPopupTargetIsInterceptedBeforeItRuns(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	attachTarget(f, "S2", "T2", "page", "http://popup.invalid/")

	enabled := f.callsOn("S2", "Fetch.enable")
	if len(enabled) != 1 {
		t.Fatalf("Fetch.enable on the popup session = %d, want 1", len(enabled))
	}
	var params struct {
		HandleAuth bool `json:"handleAuthRequests"`
		Patterns   []struct {
			URLPattern string `json:"urlPattern"`
		} `json:"patterns"`
	}
	if err := json.Unmarshal(enabled[0].Params, &params); err != nil {
		t.Fatalf("decode Fetch.enable: %v", err)
	}
	if !params.HandleAuth {
		t.Fatal("the popup's interception does not answer authentication challenges")
	}
	if len(params.Patterns) != 1 || params.Patterns[0].URLPattern != "*" {
		t.Fatalf("patterns = %+v, want every request", params.Patterns)
	}
	// Interception first, release second: the popup must not run before the
	// session can answer for it.
	if got := f.callsOn("S2", "Runtime.runIfWaitingForDebugger"); len(got) != 1 {
		t.Fatalf("the popup was not released: %d resumes", len(got))
	}
	if got := d.Popups(); len(got) != 1 || got[0] != "http://popup.invalid/" {
		t.Fatalf("popups = %v, want the popup the driver attached", got)
	}
	if again := d.Popups(); len(again) != 0 {
		t.Fatalf("second drain = %v, want empty", again)
	}
	if got := f.callsOf("Target.closeTarget"); len(got) != 0 {
		t.Fatalf("an in-scope popup was closed: %v", got)
	}
}

// A popup whose destination the scope refuses must be refused, not attached
// and left to run: it is paused before it starts, so closing it is the refusal.
func TestPopupOutsideScopeIsRefused(t *testing.T) {
	f := newFakeConn()
	f.replies["Target.closeTarget"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(rawURL string) error {
		if strings.Contains(rawURL, "outside.invalid") {
			return errors.New("outside the task scope")
		}
		return nil
	}
	d.mu.Unlock()

	attachTarget(f, "S2", "T2", "page", "http://outside.invalid/popup")

	if got := f.callsOf("Fetch.enable"); len(got) != 0 {
		t.Fatalf("interception was installed on a refused popup: %v", got)
	}
	closed := f.callsOf("Target.closeTarget")
	if len(closed) != 1 {
		t.Fatalf("closeTarget = %d, want 1", len(closed))
	}
	var params struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(closed[0].Params, &params); err != nil {
		t.Fatalf("decode closeTarget: %v", err)
	}
	if params.TargetID != "T2" {
		t.Fatalf("closed target = %q, want T2", params.TargetID)
	}
	if got := f.callsOf("Runtime.runIfWaitingForDebugger"); len(got) != 0 {
		t.Fatalf("a refused popup was released: %v", got)
	}
	if got := d.BlockedRequests(); len(got) != 1 || got[0] != "outside.invalid" {
		t.Fatalf("blocked = %v, want [outside.invalid]", got)
	}
	if got := d.Popups(); len(got) != 0 {
		t.Fatalf("popups = %v, want none: a refused popup never ran", got)
	}
}

// With no scope handle there is nothing to judge a popup against. The driver
// must not invent one: it attaches and releases the popup, and reports it.
func TestPopupWithoutScopeIsAttachedNotRefused(t *testing.T) {
	f := newFakeConn()
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	d := newTestDriver(t, f, nil)

	attachTarget(f, "S2", "T2", "page", "http://popup.invalid/")

	if got := f.callsOf("Target.closeTarget"); len(got) != 0 {
		t.Fatalf("a popup was refused without a scope handle: %v", got)
	}
	if got := f.callsOf("Fetch.enable"); len(got) != 0 {
		t.Fatalf("interception was installed with nothing to intercept for: %v", got)
	}
	if got := f.callsOn("S2", "Runtime.runIfWaitingForDebugger"); len(got) != 1 {
		t.Fatalf("the popup was left paused: %d resumes", len(got))
	}
	if got := d.Popups(); len(got) != 1 || got[0] != "http://popup.invalid/" {
		t.Fatalf("popups = %v, want the popup reported", got)
	}
}

// A request paused in a popup can only be answered on the popup's session; the
// page's own interception must keep working on the page's session.
func TestPopupRequestsAreAnsweredOnTheirOwnSession(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Fetch.continueRequest"] = map[string]any{}
	f.replies["Fetch.continueWithAuth"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	// A real browser hands the popup over before it knows where it is going.
	attachTarget(f, "S2", "T2", "page", "")

	f.emitSession("S2", "Fetch.requestPaused", map[string]any{
		"requestId":    "R1",
		"resourceType": "Document",
		"request":      map[string]any{"url": "http://popup.invalid/"},
	})
	if got := f.callsOn("S2", "Fetch.continueRequest"); len(got) != 1 {
		t.Fatalf("continueRequest on the popup session = %d, want 1", len(got))
	}
	if got := f.callsOf("Fetch.continueRequest"); len(got) != 1 {
		t.Fatalf("a popup request was answered on the page session: %v", got)
	}
	// The popup is named by the request it makes, not by the empty handover.
	if got := d.Popups(); len(got) != 1 || got[0] != "http://popup.invalid/" {
		t.Fatalf("popups = %v, want the destination the popup asked for", got)
	}

	f.emitSession("S2", "Fetch.authRequired", map[string]any{
		"requestId":     "R2",
		"authChallenge": map[string]any{"source": "Proxy"},
	})
	auth := f.callsOn("S2", "Fetch.continueWithAuth")
	if len(auth) != 1 {
		t.Fatalf("continueWithAuth on the popup session = %d, want 1", len(auth))
	}
	var answer struct {
		AuthChallengeResponse struct {
			Response string `json:"response"`
			Username string `json:"username"`
		} `json:"authChallengeResponse"`
	}
	if err := json.Unmarshal(auth[0].Params, &answer); err != nil {
		t.Fatalf("decode continueWithAuth: %v", err)
	}
	if answer.AuthChallengeResponse.Response != "ProvideCredentials" ||
		answer.AuthChallengeResponse.Username != "session-credential" {
		t.Fatalf("the popup was not given the gateway credential: %+v", answer.AuthChallengeResponse)
	}

	// The page the driver drives keeps its own interception.
	f.emit("Fetch.requestPaused", map[string]any{
		"requestId": "R3",
		"request":   map[string]any{"url": "http://fixture.invalid/"},
	})
	if got := f.callsOn("", "Fetch.continueRequest"); len(got) != 1 {
		t.Fatalf("the page's own request was not continued on the page session: %v", got)
	}
}

// A popup the browser hands over before it knows where it is going is judged on
// the request it makes, which is the only place its destination exists.
func TestPopupWithUnknownDestinationIsJudgedAtItsFirstRequest(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Fetch.failRequest"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(rawURL string) error {
		if strings.Contains(rawURL, "outside.invalid") {
			return errors.New("outside the task scope")
		}
		return nil
	}
	d.mu.Unlock()

	attachTarget(f, "S2", "T2", "page", "")
	if got := f.callsOf("Target.closeTarget"); len(got) != 0 {
		t.Fatalf("a popup with no known destination was closed: %v", got)
	}

	f.emitSession("S2", "Fetch.requestPaused", map[string]any{
		"requestId": "R1",
		"request":   map[string]any{"url": "http://outside.invalid/popup"},
	})
	failed := f.callsOn("S2", "Fetch.failRequest")
	if len(failed) != 1 {
		t.Fatalf("failRequest on the popup session = %d, want 1", len(failed))
	}
	if got := d.BlockedRequests(); len(got) != 1 || got[0] != "outside.invalid" {
		t.Fatalf("blocked = %v, want [outside.invalid]", got)
	}
	if got := d.Popups(); len(got) != 1 || got[0] != "" {
		t.Fatalf("popups = %v, want the popup reported unnamed: it never loaded", got)
	}
}

// callIndex is the position of the first call to method on one target session,
// or -1. It is how a test asserts that setup happened before a target ran.
func callIndex(f *fakeConn, session, method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, call := range f.calls {
		if call.Method == method && call.Session == session {
			return i
		}
	}
	return -1
}

// A frame or a worker makes requests of its own, so it must get the page's
// interception before it runs: the page's own interception cannot see them.
func TestChildTargetsAreInterceptedBeforeTheyRun(t *testing.T) {
	for _, kind := range []string{"iframe", "worker", "shared_worker", "service_worker"} {
		t.Run(kind, func(t *testing.T) {
			f := newFakeConn()
			f.replies["Fetch.enable"] = map[string]any{}
			f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
			d := newTestDriver(t, f, nil)
			d.mu.Lock()
			d.proxyUser = "session-credential"
			d.mu.Unlock()

			attachTarget(f, "S3", "T3", kind, "http://fixture.invalid/"+kind)

			// Nested auto-attach first, then interception, then release: the
			// target must not run before it can be judged, and a target it
			// creates must be handed over the same way.
			nested := callIndex(f, "S3", "Target.setAutoAttach")
			enabled := callIndex(f, "S3", "Fetch.enable")
			resumed := callIndex(f, "S3", "Runtime.runIfWaitingForDebugger")
			if nested < 0 || enabled < 0 || resumed < 0 {
				t.Fatalf("setup on the child session: autoAttach=%d enable=%d resume=%d", nested, enabled, resumed)
			}
			if !(nested < enabled && enabled < resumed) {
				t.Fatalf("order autoAttach=%d enable=%d resume=%d, want setup before release", nested, enabled, resumed)
			}
			var params struct {
				HandleAuth bool `json:"handleAuthRequests"`
			}
			if err := json.Unmarshal(f.callsOn("S3", "Fetch.enable")[0].Params, &params); err != nil {
				t.Fatalf("decode Fetch.enable: %v", err)
			}
			if !params.HandleAuth {
				t.Fatal("the child's interception does not answer authentication challenges")
			}
			if got := d.Popups(); len(got) != 0 {
				t.Fatalf("popups = %v, want none: a %s is not a popup", got, kind)
			}
		})
	}
}

// Every request a child target makes is judged on its own session, not only the
// first one: a worker that fetches ten times must be refused ten times.
func TestChildTargetRequestsAreJudgedOnItsSession(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Fetch.failRequest"] = map[string]any{}
	f.replies["Fetch.continueRequest"] = map[string]any{}
	f.replies["Fetch.continueWithAuth"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(rawURL string) error {
		if strings.Contains(rawURL, "outside.invalid") {
			return errors.New("outside the task scope")
		}
		return nil
	}
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	attachTarget(f, "S3", "T3", "worker", "http://fixture.invalid/w.js")

	for i := range 10 {
		f.emitSession("S3", "Fetch.requestPaused", map[string]any{
			"requestId":    "R" + strconv.Itoa(i),
			"resourceType": "Fetch",
			"request":      map[string]any{"url": "http://outside.invalid/beacon"},
		})
	}
	if got := len(f.callsOn("S3", "Fetch.failRequest")); got != 10 {
		t.Fatalf("failRequest on the worker session = %d, want 10", got)
	}
	if got := len(f.callsOf("Fetch.failRequest")); got != 10 {
		t.Fatalf("failRequest total = %d: a child request was answered on the page session", got)
	}

	f.emitSession("S3", "Fetch.requestPaused", map[string]any{
		"requestId":    "OK",
		"resourceType": "Script",
		"request":      map[string]any{"url": "http://fixture.invalid/extra.js"},
	})
	if got := len(f.callsOn("S3", "Fetch.continueRequest")); got != 1 {
		t.Fatalf("continueRequest on the worker session = %d, want 1", got)
	}

	f.emitSession("S3", "Fetch.authRequired", map[string]any{
		"requestId":     "A1",
		"authChallenge": map[string]any{"source": "Proxy"},
	})
	auth := f.callsOn("S3", "Fetch.continueWithAuth")
	if len(auth) != 1 {
		t.Fatalf("continueWithAuth on the worker session = %d, want 1", len(auth))
	}
	var answer struct {
		AuthChallengeResponse struct {
			Response string `json:"response"`
			Username string `json:"username"`
		} `json:"authChallengeResponse"`
	}
	if err := json.Unmarshal(auth[0].Params, &answer); err != nil {
		t.Fatalf("decode continueWithAuth: %v", err)
	}
	if answer.AuthChallengeResponse.Response != "ProvideCredentials" ||
		answer.AuthChallengeResponse.Username != "session-credential" {
		t.Fatalf("the worker was not given the gateway credential: %+v", answer.AuthChallengeResponse)
	}
}

// A target type this package cannot drive is released rather than left paused:
// the page that created it must not wait on a debugger nobody releases.
func TestUnknownTargetTypeIsReleased(t *testing.T) {
	f := newFakeConn()
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(string) error { return nil }
	d.mu.Unlock()

	attachTarget(f, "S4", "T4", "other", "")

	if got := f.callsOf("Fetch.enable"); len(got) != 0 {
		t.Fatalf("interception was installed on an unknown target type: %v", got)
	}
	if got := f.callsOn("S4", "Runtime.runIfWaitingForDebugger"); len(got) != 1 {
		t.Fatalf("an unknown target type was left paused: %d resumes", len(got))
	}
}

// A target that cannot be intercepted must not run: it would be a hole the
// page's own interception cannot see.
func TestChildTargetThatCannotBeInterceptedIsClosed(t *testing.T) {
	f := newFakeConn()
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Target.closeTarget"] = map[string]any{}
	f.handle = func(method string, _ json.RawMessage) (any, bool, error) {
		if method == "Fetch.enable" {
			return nil, false, errors.New("browser: Fetch.enable: connection reset")
		}
		return nil, false, nil
	}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(string) error { return nil }
	d.mu.Unlock()

	attachTarget(f, "S3", "T3", "worker", "http://fixture.invalid/w.js")

	if got := f.callsOn("S3", "Runtime.runIfWaitingForDebugger"); len(got) != 0 {
		t.Fatalf("a worker that cannot be intercepted was released: %v", got)
	}
	closed := f.callsOf("Target.closeTarget")
	if len(closed) != 1 {
		t.Fatalf("closeTarget = %d, want 1", len(closed))
	}
	var params struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(closed[0].Params, &params); err != nil {
		t.Fatalf("decode closeTarget: %v", err)
	}
	if params.TargetID != "T3" {
		t.Fatalf("closed target = %q, want T3", params.TargetID)
	}
	if got := d.BlockedRequests(); len(got) != 1 || got[0] != "fixture.invalid" {
		t.Fatalf("blocked = %v, want [fixture.invalid]", got)
	}
}

// A type the browser cannot close is detached instead, so it never stays
// paused with a debugger nobody releases.
func TestChildTargetCloseFailureDetaches(t *testing.T) {
	f := newFakeConn()
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Target.detachFromTarget"] = map[string]any{}
	f.handle = func(method string, _ json.RawMessage) (any, bool, error) {
		switch method {
		case "Fetch.enable":
			return nil, false, errors.New("browser: Fetch.enable: connection reset")
		case "Target.closeTarget":
			return nil, false, errors.New("browser: Target.closeTarget: cannot close this target")
		}
		return nil, false, nil
	}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(string) error { return nil }
	d.mu.Unlock()

	attachTarget(f, "S3", "T3", "shared_worker", "http://fixture.invalid/w.js")

	if got := f.callsOn("S3", "Runtime.runIfWaitingForDebugger"); len(got) != 0 {
		t.Fatalf("a shared worker that cannot be intercepted was released: %v", got)
	}
	detached := f.callsOf("Target.detachFromTarget")
	if len(detached) != 1 {
		t.Fatalf("detachFromTarget = %d, want 1", len(detached))
	}
	var params struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(detached[0].Params, &params); err != nil {
		t.Fatalf("decode detachFromTarget: %v", err)
	}
	if params.SessionID != "S3" {
		t.Fatalf("detached session = %q, want S3", params.SessionID)
	}
}

// Chromium refusing interception for a target type is a browser limit, not a
// reason to leave the target paused: it is released, and the gateway is then
// the layer that refuses the request.
func TestChildTargetWithoutFetchSupportIsReleased(t *testing.T) {
	f := newFakeConn()
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.handle = func(method string, _ json.RawMessage) (any, bool, error) {
		if method == "Fetch.enable" {
			return nil, false, &cdpError{Code: -32601, Message: "'Fetch.enable' wasn't found"}
		}
		return nil, false, nil
	}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(string) error { return nil }
	d.mu.Unlock()

	attachTarget(f, "S3", "T3", "service_worker", "http://fixture.invalid/sw.js")

	if got := f.callsOf("Target.closeTarget"); len(got) != 0 {
		t.Fatalf("a target type without interception was closed: %v", got)
	}
	if got := f.callsOn("S3", "Runtime.runIfWaitingForDebugger"); len(got) != 1 {
		t.Fatalf("the target was left paused: %d resumes", len(got))
	}
	if got := d.BlockedRequests(); len(got) != 0 {
		t.Fatalf("blocked = %v, want none: the target ran", got)
	}
}

// A target attached to a session with handlers of its own is only delivered
// there: left unhandled, a popup's worker would stay paused forever.
func TestNestedTargetOfAPopupIsIntercepted(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	attachTarget(f, "S2", "T2", "page", "")
	f.emitSession("S2", "Target.attachedToTarget", map[string]any{
		"sessionId":          "S3",
		"waitingForDebugger": true,
		"targetInfo": map[string]any{
			"targetId": "T3",
			"type":     "worker",
			"url":      "http://fixture.invalid/w.js",
		},
	})

	if got := f.callsOn("S3", "Fetch.enable"); len(got) != 1 {
		t.Fatalf("Fetch.enable on the nested worker = %d, want 1", len(got))
	}
	if got := f.callsOn("S3", "Runtime.runIfWaitingForDebugger"); len(got) != 1 {
		t.Fatalf("the nested worker was left paused: %d resumes", len(got))
	}
}

// The popup entry must exist before the popup runs: its first request is judged
// against that entry.
func TestPopupIsRecordedBeforeItIsReleased(t *testing.T) {
	for _, reported := range []string{"", "about:blank"} {
		t.Run("reported="+strconv.Quote(reported), func(t *testing.T) {
			f := newFakeConn()
			f.replies["Fetch.enable"] = map[string]any{}
			f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
			d := newTestDriver(t, f, nil)
			d.mu.Lock()
			d.proxyUser = "session-credential"
			d.mu.Unlock()

			var atRelease []string
			var indexed bool
			f.handle = func(method string, _ json.RawMessage) (any, bool, error) {
				if method != "Runtime.runIfWaitingForDebugger" {
					return nil, false, nil
				}
				d.mu.Lock()
				atRelease = append([]string(nil), d.popups...)
				i, ok := d.popupAt["S2"]
				indexed = ok && i == 0
				d.mu.Unlock()
				return map[string]any{}, true, nil
			}

			attachTarget(f, "S2", "T2", "page", reported)

			if len(atRelease) != 1 || atRelease[0] != reported || !indexed {
				t.Fatalf("at release the popup entry = %v (indexed %v), want %q recorded first", atRelease, indexed, reported)
			}
			if got := d.Popups(); len(got) != 1 || got[0] != reported {
				t.Fatalf("popups = %v, want %q", got, reported)
			}
		})
	}
}

// A popup is named by the document it asks for, not by a subresource it loads
// on the way.
func TestPopupIsNamedByItsAllowedDocumentRequest(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Fetch.continueRequest"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(rawURL string) error {
		if strings.Contains(rawURL, "outside.invalid") {
			return errors.New("outside the task scope")
		}
		return nil
	}
	d.mu.Unlock()

	name := func() string {
		t.Helper()
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.popups) != 1 {
			t.Fatalf("popups = %v, want one entry", d.popups)
		}
		return d.popups[0]
	}

	attachTarget(f, "S2", "T2", "page", "about:blank")

	f.emitSession("S2", "Fetch.requestPaused", map[string]any{
		"requestId":    "R1",
		"resourceType": "Image",
		"request":      map[string]any{"url": "http://cdn.invalid/logo.png"},
	})
	if got := name(); got != "about:blank" {
		t.Fatalf("popup name = %q after an image, want the placeholder", got)
	}

	f.emitSession("S2", "Fetch.requestPaused", map[string]any{
		"requestId":    "R2",
		"resourceType": "Document",
		"request":      map[string]any{"url": "http://popup.invalid/"},
	})
	if got := name(); got != "http://popup.invalid/" {
		t.Fatalf("popup name = %q, want the document it asked for", got)
	}
	if got := len(f.callsOn("S2", "Fetch.continueRequest")); got != 2 {
		t.Fatalf("continueRequest = %d, want both requests allowed", got)
	}
}

// A document the scope refuses does not name the popup: it never loaded.
func TestPopupBlockedDocumentDoesNotNameIt(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Runtime.runIfWaitingForDebugger"] = map[string]any{}
	f.replies["Fetch.failRequest"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(rawURL string) error {
		if strings.Contains(rawURL, "outside.invalid") {
			return errors.New("outside the task scope")
		}
		return nil
	}
	d.mu.Unlock()

	attachTarget(f, "S2", "T2", "page", "about:blank")
	f.emitSession("S2", "Fetch.requestPaused", map[string]any{
		"requestId":    "R1",
		"resourceType": "Document",
		"request":      map[string]any{"url": "http://outside.invalid/popup"},
	})
	if got := len(f.callsOn("S2", "Fetch.failRequest")); got != 1 {
		t.Fatalf("failRequest = %d, want the excluded document refused", got)
	}
	if got := d.Popups(); len(got) != 1 || got[0] != "about:blank" {
		t.Fatalf("popups = %v, want the placeholder: a refused popup never loaded", got)
	}
	if got := d.BlockedRequests(); len(got) != 1 || got[0] != "outside.invalid" {
		t.Fatalf("blocked = %v, want [outside.invalid]", got)
	}
}

// Without auto-attach the browser never hands the driver a target created after
// launch, so the interception on the page would be the only one.
func TestLaunchArmsAutoAttachForNewTargets(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	if err := d.enableCapabilities(context.Background(), f); err != nil {
		t.Fatalf("enable: %v", err)
	}
	calls := f.callsOf("Target.setAutoAttach")
	if len(calls) != 1 {
		t.Fatalf("setAutoAttach = %d, want 1", len(calls))
	}
	var params struct {
		AutoAttach bool `json:"autoAttach"`
		Wait       bool `json:"waitForDebuggerOnStart"`
		Flatten    bool `json:"flatten"`
	}
	if err := json.Unmarshal(calls[0].Params, &params); err != nil {
		t.Fatalf("decode setAutoAttach: %v", err)
	}
	if !params.AutoAttach || !params.Wait || !params.Flatten {
		t.Fatalf("setAutoAttach = %+v, want autoAttach, paused and flattened", params)
	}
}

// pageConn is a fake conn that names the page session it drives, the way the
// pipe does, so the page's own auto-attach is testable.
type pageConn struct {
	*fakeConn
	session string
}

func (p pageConn) PageSession() string { return p.session }

// A browser-level auto-attach does not hand over a page's out-of-process
// frames: the page's own session must arm it too, or an iframe's requests are
// never judged.
func TestLaunchArmsAutoAttachOnThePageSession(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	c := pageConn{fakeConn: f, session: "P1"}
	d := newTestDriver(t, c, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	if err := d.enableCapabilities(context.Background(), c); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := len(f.callsOn("", "Target.setAutoAttach")); got != 1 {
		t.Fatalf("browser auto-attach = %d, want 1", got)
	}
	if got := len(f.callsOn("P1", "Target.setAutoAttach")); got != 1 {
		t.Fatalf("page auto-attach = %d, want 1", got)
	}
}

// Chromium ignores credentials embedded in --proxy-server, so the command line
// must carry the bare address: the credential travels over CDP instead.
func TestLaunchArgsCarryNoProxyCredential(t *testing.T) {
	argv := launchArgs(Options{
		Executable:  "/usr/bin/chromium",
		UserDataDir: "/tmp/profile",
		ProxyServer: "http://127.0.0.1:8888",
		ProxyUser:   "session-credential",
	})
	proxy := ""
	for _, arg := range argv {
		if strings.Contains(arg, "session-credential") {
			t.Fatalf("credential on the command line: %q", arg)
		}
		if strings.HasPrefix(arg, "--proxy-server=") {
			proxy = strings.TrimPrefix(arg, "--proxy-server=")
		}
	}
	if proxy != "http://127.0.0.1:8888" {
		t.Fatalf("--proxy-server = %q, want the bare address", proxy)
	}
}

// fakeExecClient is a session client that hands startPipe a process whose
// stdout is the synchronous pipe execbox's frame pump writes to.
type fakeExecClient struct{ proc execbox.Process }

func (fakeExecClient) Run(context.Context, netpolicy.Session, execbox.Spec) (io.ReadWriteCloser, error) {
	return nil, errors.New("unexpected Run")
}

func (fakeExecClient) RunOnce(context.Context, netpolicy.Session, execbox.Spec) (execbox.Result, error) {
	return execbox.Result{}, errors.New("unexpected RunOnce")
}

func (fakeExecClient) Capabilities(context.Context) (execbox.Report, error) {
	return execbox.Report{}, nil
}

func (f fakeExecClient) RunWithFiles(_ context.Context, _ netpolicy.Session, _ execbox.Spec, files []*os.File) (io.ReadWriteCloser, error) {
	for _, file := range files {
		_ = file.Close()
	}
	return f.proc, nil
}

// fakeProc is a browser process whose stdout blocks until someone reads it.
type fakeProc struct {
	out  *io.PipeWriter
	read *io.PipeReader
	done chan struct{}
	once sync.Once
}

func (p *fakeProc) Read(b []byte) (int, error)  { return p.read.Read(b) }
func (p *fakeProc) Write(b []byte) (int, error) { return len(b), nil }
func (p *fakeProc) Close() error                { return nil }
func (p *fakeProc) Stderr() io.Reader           { return nil }
func (p *fakeProc) CloseStdin() error           { return nil }
func (p *fakeProc) Resize(int, int) error       { return nil }
func (p *fakeProc) Wait() (int, error)          { <-p.done; return 0, nil }
func (p *fakeProc) Kill() error {
	p.once.Do(func() { close(p.done) })
	return nil
}

// A browser that prints to stdout must not wedge its own CDP pipe: the client
// writes each frame to a synchronous stream, so an unread stdout stalls the
// connection with it.
func TestStartPipeDrainsBrowserStdout(t *testing.T) {
	read, write := io.Pipe()
	proc := &fakeProc{read: read, out: write, done: make(chan struct{})}
	execbox.Install(fakeExecClient{proc: proc})
	t.Cleanup(func() { execbox.Install(nil) })

	wrote := make(chan struct{})
	go func() {
		_, _ = write.Write(make([]byte, 1<<16))
		_ = write.Close()
		close(wrote)
	}()

	ctx, cancel := context.WithTimeout(execbox.WithSession(context.Background(), netpolicy.Session{
		ID: "s", TaskID: 1, Purpose: netpolicy.PurposeTesting,
	}), 5*time.Second)
	defer cancel()
	// The fake answers no CDP, so the launch fails; the drain must still run.
	_, _ = startPipe(ctx, Options{Executable: "/bin/true", UserDataDir: t.TempDir()})

	select {
	case <-wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("browser stdout was not drained: the frame pump is blocked")
	}
}

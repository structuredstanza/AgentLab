package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refused request never leaves the browser: it is failed with the client
// error and its host is reported for the next tool result.
func TestFetchBlocksOutOfScopeRequests(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.continueRequest"] = map[string]any{}
	f.replies["Fetch.failRequest"] = map[string]any{}

	var seen []string
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(rawURL string) error {
		seen = append(seen, rawURL)
		if strings.Contains(rawURL, "thirdparty.example") {
			return errors.New("out of scope")
		}
		return nil
	}
	d.mu.Unlock()

	f.emit("Fetch.requestPaused", map[string]any{
		"requestId": "r1",
		"request":   map[string]any{"url": "https://cdn.thirdparty.example/a.js?x=1"},
	})
	f.emit("Fetch.requestPaused", map[string]any{
		"requestId": "r2",
		"request":   map[string]any{"url": "https://target.test/index.html"},
	})

	want := []string{
		"https://cdn.thirdparty.example/a.js?x=1",
		"https://target.test/index.html",
	}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("callback URLs = %v, want %v", seen, want)
	}

	failed := f.callsOf("Fetch.failRequest")
	if len(failed) != 1 {
		t.Fatalf("fail calls = %d, want 1", len(failed))
	}
	var fail struct {
		RequestID   string `json:"requestId"`
		ErrorReason string `json:"errorReason"`
	}
	if err := json.Unmarshal(failed[0].Params, &fail); err != nil {
		t.Fatalf("decode fail: %v", err)
	}
	if fail.RequestID != "r1" || fail.ErrorReason != "BlockedByClient" {
		t.Fatalf("fail params = %+v, want r1 BlockedByClient", fail)
	}
	continued := f.callsOf("Fetch.continueRequest")
	if len(continued) != 1 {
		t.Fatalf("continue calls = %d, want 1", len(continued))
	}
	var cont struct {
		RequestID string `json:"requestId"`
	}
	if err := json.Unmarshal(continued[0].Params, &cont); err != nil {
		t.Fatalf("decode continue: %v", err)
	}
	if cont.RequestID != "r2" {
		t.Fatalf("continued request = %q, want r2", cont.RequestID)
	}

	blocked := d.BlockedRequests()
	if len(blocked) != 1 || blocked[0] != "cdn.thirdparty.example" {
		t.Fatalf("blocked = %v, want [cdn.thirdparty.example]", blocked)
	}
	if again := d.BlockedRequests(); len(again) != 0 {
		t.Fatalf("second drain = %v, want empty", again)
	}
}

// A proxy challenge is answered with the launch credential. Chromium ignores
// credentials embedded in --proxy-server, so this exchange is the only way the
// testing browser authenticates to the gateway.
func TestFetchAnswersProxyAuthWithCredential(t *testing.T) {
	const credential = "session-credential"
	// The loopback proxy enforces what the gateway enforces: no credential, no
	// service.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(credential+":"))
		if r.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="gateway"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()

	// The proxy really does refuse an unauthenticated request, so the success
	// below is the credential's doing.
	if res, err := http.Get(proxy.URL); err != nil || res.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated proxy request = %v, %v; want 407", res, err)
	}

	f := newFakeConn()
	// The fake browser does what Chromium does with the answer: retries the
	// request through the proxy carrying the credentials it was given.
	var status int
	var answer struct {
		Response string `json:"response"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	f.replies["Fetch.continueWithAuth"] = map[string]any{}
	f.handle = func(method string, params json.RawMessage) (any, bool, error) {
		if method != "Fetch.continueWithAuth" {
			return nil, false, nil
		}
		var call struct {
			AuthChallengeResponse struct {
				Response string `json:"response"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"authChallengeResponse"`
		}
		if err := json.Unmarshal(params, &call); err != nil {
			return nil, true, err
		}
		answer.Response = call.AuthChallengeResponse.Response
		answer.Username = call.AuthChallengeResponse.Username
		answer.Password = call.AuthChallengeResponse.Password

		req, err := http.NewRequest(http.MethodGet, proxy.URL, nil)
		if err != nil {
			return nil, true, err
		}
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(answer.Username+":"+answer.Password)))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, true, err
		}
		res.Body.Close()
		status = res.StatusCode
		return map[string]any{}, true, nil
	}

	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = credential
	d.mu.Unlock()

	f.emit("Fetch.authRequired", map[string]any{
		"requestId":     "a1",
		"authChallenge": map[string]any{"source": "Proxy", "scheme": "basic", "realm": "gateway"},
	})

	if answer.Response != "ProvideCredentials" || answer.Username != credential || answer.Password != "" {
		t.Fatalf("challenge answer = %+v, want ProvideCredentials with the session credential", answer)
	}
	if status != http.StatusOK {
		t.Fatalf("proxy request with the answered credential = %d, want 200", status)
	}
}

// An origin challenge keeps today's behaviour: a headless browser has no
// credentials to offer, so the request is cancelled rather than paused.
func TestFetchCancelsOriginAuthChallenge(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.continueWithAuth"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	f.emit("Fetch.authRequired", map[string]any{
		"requestId":     "a1",
		"authChallenge": map[string]any{"source": "Server", "origin": "https://example.test"},
	})

	calls := f.callsOf("Fetch.continueWithAuth")
	if len(calls) != 1 {
		t.Fatalf("continueWithAuth calls = %d, want 1", len(calls))
	}
	var call struct {
		RequestID             string `json:"requestId"`
		AuthChallengeResponse struct {
			Response string `json:"response"`
		} `json:"authChallengeResponse"`
	}
	if err := json.Unmarshal(calls[0].Params, &call); err != nil {
		t.Fatalf("decode continueWithAuth: %v", err)
	}
	if call.RequestID != "a1" || call.AuthChallengeResponse.Response != "CancelAuth" {
		t.Fatalf("origin challenge answer = %+v, want a1 CancelAuth", call)
	}
}

// A launch with a proxy credential enables authentication handling even when no
// request scope is set.
func TestEnableCapabilitiesWiresProxyAuth(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.proxyUser = "session-credential"
	d.mu.Unlock()

	if err := d.enableCapabilities(context.Background(), f); err != nil {
		t.Fatalf("enable: %v", err)
	}
	enabled := f.callsOf("Fetch.enable")
	if len(enabled) != 1 {
		t.Fatalf("Fetch.enable calls = %d, want 1", len(enabled))
	}
	var params struct {
		Patterns           []any `json:"patterns"`
		HandleAuthRequests bool  `json:"handleAuthRequests"`
	}
	if err := json.Unmarshal(enabled[0].Params, &params); err != nil {
		t.Fatalf("decode Fetch.enable: %v", err)
	}
	if !params.HandleAuthRequests || len(params.Patterns) != 1 {
		t.Fatalf("Fetch.enable params = %s, want handleAuthRequests and one pattern", enabled[0].Params)
	}
}

// The same blocked host is named once per drain, so a page that hammers it
// does not flood the tool result.
func TestBlockedRequestsDeduplicateHosts(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.failRequest"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(string) error { return errors.New("out of scope") }
	d.mu.Unlock()

	for _, id := range []string{"r1", "r2", "r3"} {
		f.emit("Fetch.requestPaused", map[string]any{
			"requestId": id,
			"request":   map[string]any{"url": "https://cdn.thirdparty.example/" + id},
		})
	}
	if got := d.BlockedRequests(); len(got) != 1 || got[0] != "cdn.thirdparty.example" {
		t.Fatalf("blocked = %v, want one host", got)
	}
}

// Launch-time wiring: interception only with a scope, downloads only with a
// directory, console capture always.
func TestEnableCapabilitiesWiresScopeAndDownloads(t *testing.T) {
	f := newFakeConn()
	f.replies["Fetch.enable"] = map[string]any{}
	f.replies["Browser.setDownloadBehavior"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.allowRequest = func(string) error { return nil }
	d.downloadDir = "/tmp/task-downloads"
	d.mu.Unlock()

	if err := d.enableCapabilities(context.Background(), f); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if calls := f.callsOf("Runtime.enable"); len(calls) != 1 {
		t.Fatalf("Runtime.enable calls = %d, want 1", len(calls))
	}

	enabled := f.callsOf("Fetch.enable")
	if len(enabled) != 1 {
		t.Fatalf("Fetch.enable calls = %d, want 1", len(enabled))
	}
	var patterns struct {
		Patterns []struct {
			URLPattern   string `json:"urlPattern"`
			RequestStage string `json:"requestStage"`
		} `json:"patterns"`
	}
	if err := json.Unmarshal(enabled[0].Params, &patterns); err != nil {
		t.Fatalf("decode Fetch.enable: %v", err)
	}
	if len(patterns.Patterns) != 1 ||
		patterns.Patterns[0].URLPattern != "*" ||
		patterns.Patterns[0].RequestStage != "Request" {
		t.Fatalf("Fetch.enable params = %s", enabled[0].Params)
	}

	behavior := f.callsOf("Browser.setDownloadBehavior")
	if len(behavior) != 1 {
		t.Fatalf("setDownloadBehavior calls = %d, want 1", len(behavior))
	}
	var download struct {
		Behavior      string `json:"behavior"`
		DownloadPath  string `json:"downloadPath"`
		EventsEnabled bool   `json:"eventsEnabled"`
	}
	if err := json.Unmarshal(behavior[0].Params, &download); err != nil {
		t.Fatalf("decode setDownloadBehavior: %v", err)
	}
	if download.Behavior != "allow" || download.DownloadPath != "/tmp/task-downloads" || !download.EventsEnabled {
		t.Fatalf("download params = %+v", download)
	}
}

func TestEnableCapabilitiesSkipsInterceptionWithoutScope(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	if err := d.enableCapabilities(context.Background(), f); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if calls := f.callsOf("Fetch.enable"); len(calls) != 0 {
		t.Fatalf("Fetch.enable calls = %d, want none", len(calls))
	}
	if calls := f.callsOf("Browser.setDownloadBehavior"); len(calls) != 0 {
		t.Fatalf("setDownloadBehavior calls = %d, want none", len(calls))
	}
}

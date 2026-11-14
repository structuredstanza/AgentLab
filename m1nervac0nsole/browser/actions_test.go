package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

const axButtonFixture = `{"nodes":[
 {"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"Start"},"childIds":["2"]},
 {"nodeId":"2","parentId":"1","role":{"value":"button"},"name":{"value":"Go"},"backendDOMNodeId":42}
]}`

const axTextboxFixture = `{"nodes":[
 {"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"Form"},"childIds":["2"]},
 {"nodeId":"2","parentId":"1","role":{"value":"textbox"},"name":{"value":"Email"},"backendDOMNodeId":21}
]}`

const axSelectFixture = `{"nodes":[
 {"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"Form"},"childIds":["2"]},
 {"nodeId":"2","parentId":"1","role":{"value":"combobox"},"name":{"value":"Color"},"backendDOMNodeId":31}
]}`

func TestNavigateRefusesNonHTTP(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	for _, target := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,hello",
		"https://",
		"",
	} {
		if _, err := d.Navigate(context.Background(), target); err == nil {
			t.Fatalf("Navigate(%q) accepted a non-http URL", target)
		}
	}
	if calls := f.callsOf("Page.navigate"); len(calls) != 0 {
		t.Fatalf("sent %d navigations for refused URLs", len(calls))
	}
}

// A ref from before a top-level navigation must fail with the exact text the
// tool layer promises, not silently click whatever now sits at that index.
func TestStaleRefAfterNavigation(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axButtonFixture)
	f.replies["Page.navigate"] = map[string]any{"frameId": "F1"}
	f.emitOn["Page.navigate"] = []fakeEvent{{Method: "Page.loadEventFired", Params: map[string]any{}}}
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := d.Navigate(ctx, "https://example.test/next"); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	_, err := d.Click(ctx, "g1e2")
	if err == nil || err.Error() != "stale reference, take a new snapshot" {
		t.Fatalf("click stale ref error = %v", err)
	}
	if calls := f.callsOf("Input.dispatchMouseEvent"); len(calls) != 0 {
		t.Fatalf("stale ref still dispatched %d mouse events", len(calls))
	}

	snap, err := d.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot after navigation: %v", err)
	}
	if _, ok := snap.Refs["g2e2"]; !ok {
		t.Fatalf("refs after navigation = %v, want g2 refs", snap.Refs)
	}
}

// The click must land on the centre of the content box, which is what the box
// model reports, not on the top-left corner.
func TestClickUsesBoxModelCentre(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axButtonFixture)
	f.replies["DOM.scrollIntoViewIfNeeded"] = map[string]any{}
	f.replies["DOM.getBoxModel"] = map[string]any{
		"model": map[string]any{"content": []float64{10, 20, 110, 20, 110, 60, 10, 60}},
	}
	f.replies["Page.getNavigationHistory"] = map[string]any{
		"currentIndex": 0,
		"entries": []any{
			map[string]any{"url": "https://example.test/form", "title": "Form"},
		},
	}
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	state, err := d.Click(ctx, "g1e2")
	if err != nil {
		t.Fatalf("click: %v", err)
	}
	if state.URL != "https://example.test/form" || state.Title != "Form" {
		t.Fatalf("state = %+v, want the history entry", state)
	}

	// The element is scrolled into view before its coordinates are read, so a
	// ref below the fold does not click whatever sits at its old position.
	if scrolled := f.callsOf("DOM.scrollIntoViewIfNeeded"); len(scrolled) != 1 {
		t.Fatalf("scroll calls = %d, want 1", len(scrolled))
	}
	calls := f.callsOf("Input.dispatchMouseEvent")
	if len(calls) != 2 {
		t.Fatalf("mouse events = %d, want pressed and released", len(calls))
	}
	var pressed struct {
		Type       string  `json:"type"`
		X          float64 `json:"x"`
		Y          float64 `json:"y"`
		Button     string  `json:"button"`
		ClickCount int     `json:"clickCount"`
	}
	if err := json.Unmarshal(calls[0].Params, &pressed); err != nil {
		t.Fatalf("decode mouse event: %v", err)
	}
	if pressed.Type != "mousePressed" || pressed.X != 60 || pressed.Y != 40 {
		t.Fatalf("pressed = %+v, want left press at 60,40", pressed)
	}
	if pressed.Button != "left" || pressed.ClickCount != 1 {
		t.Fatalf("pressed = %+v, want a single left click", pressed)
	}
}

func TestTypeFocusesAndInsertsText(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axTextboxFixture)
	f.replies["DOM.scrollIntoViewIfNeeded"] = map[string]any{}
	f.replies["DOM.getBoxModel"] = map[string]any{
		"model": map[string]any{"content": []float64{0, 0, 100, 0, 100, 20, 0, 20}},
	}
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := d.Type(ctx, "g1e2", "hello"); err != nil {
		t.Fatalf("type: %v", err)
	}
	calls := f.callsOf("Input.insertText")
	if len(calls) != 1 {
		t.Fatalf("insertText calls = %d, want 1", len(calls))
	}
	var inserted struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(calls[0].Params, &inserted); err != nil {
		t.Fatalf("decode insertText: %v", err)
	}
	if inserted.Text != "hello" {
		t.Fatalf("inserted %q, want hello", inserted.Text)
	}
}

func TestPressMapsNamedKeys(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Press(ctx, "Enter"); err != nil {
		t.Fatalf("press: %v", err)
	}
	calls := f.callsOf("Input.dispatchKeyEvent")
	if len(calls) != 2 {
		t.Fatalf("key events = %d, want down and up", len(calls))
	}
	var down struct {
		Type                  string `json:"type"`
		Key                   string `json:"key"`
		Code                  string `json:"code"`
		Text                  string `json:"text"`
		WindowsVirtualKeyCode int    `json:"windowsVirtualKeyCode"`
	}
	if err := json.Unmarshal(calls[0].Params, &down); err != nil {
		t.Fatalf("decode key event: %v", err)
	}
	if down.Type != "keyDown" || down.Key != "Enter" || down.Code != "Enter" {
		t.Fatalf("key down = %+v", down)
	}
	if down.WindowsVirtualKeyCode != 13 || down.Text != "\r" {
		t.Fatalf("key down = %+v, want vk 13 and CR text", down)
	}

	if _, err := d.Press(ctx, "NotAKey"); err == nil {
		t.Fatal("Press accepted an unknown multi-character key")
	}
}

func TestSelectCallsIntoThePage(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axSelectFixture)
	f.replies["DOM.resolveNode"] = map[string]any{
		"object": map[string]any{"objectId": "obj-1"},
	}
	f.replies["Runtime.callFunctionOn"] = map[string]any{
		"result": map[string]any{"value": true},
	}
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := d.Select(ctx, "g1e2", "red"); err != nil {
		t.Fatalf("select: %v", err)
	}
	calls := f.callsOf("Runtime.callFunctionOn")
	if len(calls) != 1 {
		t.Fatalf("callFunctionOn calls = %d, want 1", len(calls))
	}
	var call struct {
		ObjectID  string `json:"objectId"`
		Arguments []struct {
			Value []string `json:"value"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(calls[0].Params, &call); err != nil {
		t.Fatalf("decode call: %v", err)
	}
	if call.ObjectID != "obj-1" {
		t.Fatalf("objectId = %q", call.ObjectID)
	}
	if len(call.Arguments) != 1 || len(call.Arguments[0].Value) != 1 || call.Arguments[0].Value[0] != "red" {
		t.Fatalf("arguments = %+v, want [red]", call.Arguments)
	}
}

func TestWaitFindsTextAndTimesOut(t *testing.T) {
	found := newFakeConn()
	found.replies["Accessibility.getFullAXTree"] = json.RawMessage(
		`{"nodes":[{"nodeId":"1","role":{"value":"StaticText"},"name":{"value":"Ready now"}}]}`)
	d := newTestDriver(t, found, nil)
	if err := d.Wait(context.Background(), "Ready", time.Second); err != nil {
		t.Fatalf("wait: %v", err)
	}

	missing := newFakeConn()
	missing.replies["Accessibility.getFullAXTree"] = json.RawMessage(`{"nodes":[]}`)
	d = newTestDriver(t, missing, nil)
	if err := d.Wait(context.Background(), "Never", 30*time.Millisecond); err == nil {
		t.Fatal("wait returned nil for text that never appeared")
	}
}

func TestScreenshotDecodesAndCapturesFullPage(t *testing.T) {
	f := newFakeConn()
	f.replies["Page.captureScreenshot"] = map[string]any{
		"data": base64.StdEncoding.EncodeToString([]byte("png-bytes")),
	}
	f.replies["Page.getLayoutMetrics"] = map[string]any{
		"cssContentSize": map[string]any{"width": 800, "height": 1200},
	}
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	png, err := d.Screenshot(ctx, false)
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}
	if string(png) != "png-bytes" {
		t.Fatalf("screenshot = %q", png)
	}

	if _, err := d.Screenshot(ctx, true); err != nil {
		t.Fatalf("full page screenshot: %v", err)
	}
	calls := f.callsOf("Page.captureScreenshot")
	if len(calls) != 2 {
		t.Fatalf("capture calls = %d, want 2", len(calls))
	}
	var capture struct {
		CaptureBeyondViewport bool `json:"captureBeyondViewport"`
		Clip                  struct {
			Width  float64 `json:"width"`
			Height float64 `json:"height"`
		} `json:"clip"`
	}
	if err := json.Unmarshal(calls[1].Params, &capture); err != nil {
		t.Fatalf("decode capture: %v", err)
	}
	if !capture.CaptureBeyondViewport || capture.Clip.Width != 800 || capture.Clip.Height != 1200 {
		t.Fatalf("full page capture = %+v", capture)
	}
}

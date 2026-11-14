package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"
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

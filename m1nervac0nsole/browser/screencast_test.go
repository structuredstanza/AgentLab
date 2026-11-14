package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func newScreencastFake() *fakeConn {
	f := newFakeConn()
	f.replies["Emulation.setDeviceMetricsOverride"] = map[string]any{}
	f.replies["Page.startScreencast"] = map[string]any{}
	f.replies["Page.stopScreencast"] = map[string]any{}
	f.replies["Page.screencastFrameAck"] = map[string]any{}
	return f
}

func emitFrame(f *fakeConn, sessionID int, payload []byte) {
	f.emit("Page.screencastFrame", map[string]any{
		"data":      base64.StdEncoding.EncodeToString(payload),
		"sessionId": sessionID,
	})
}

// A live view is only usable if the frame the browser sent is both acknowledged
// (Chromium waits for the ack before sending the next one) and handed to the
// caller with the geometry the viewport was set to.
func TestScreencastAcksAndDeliversFrames(t *testing.T) {
	f := newScreencastFake()
	d := newTestDriver(t, f, nil)
	frames := make(chan screencastFrame, 4)
	if err := d.StartScreencast(context.Background(), ScreencastOptions{Width: 800, Height: 600}, func(seq int, jpeg []byte) {
		frames <- screencastFrame{seq: seq, jpeg: jpeg}
	}); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = d.StopScreencast(context.Background()) })

	start := f.callsOf("Page.startScreencast")
	if len(start) != 1 {
		t.Fatalf("start calls = %d, want 1", len(start))
	}
	var opts struct {
		Format    string `json:"format"`
		Quality   int    `json:"quality"`
		MaxWidth  int    `json:"maxWidth"`
		MaxHeight int    `json:"maxHeight"`
	}
	if err := json.Unmarshal(start[0].Params, &opts); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if opts.Format != "jpeg" || opts.Quality != defaultScreencastQuality || opts.MaxWidth != 800 || opts.MaxHeight != 600 {
		t.Fatalf("start options = %+v", opts)
	}
	viewport := f.callsOf("Emulation.setDeviceMetricsOverride")
	if len(viewport) != 1 {
		t.Fatalf("viewport calls = %d, want 1", len(viewport))
	}

	payload := []byte{0xff, 0xd8, 0x01, 0x02}
	emitFrame(f, 9, payload)

	select {
	case got := <-frames:
		if got.seq != 1 {
			t.Fatalf("seq = %d, want 1", got.seq)
		}
		if string(got.jpeg) != string(payload) {
			t.Fatalf("jpeg = %x, want %x", got.jpeg, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("frame was not delivered")
	}

	acks := f.callsOf("Page.screencastFrameAck")
	if len(acks) != 1 {
		t.Fatalf("ack calls = %d, want 1", len(acks))
	}
	var ack struct {
		SessionID int `json:"sessionId"`
	}
	if err := json.Unmarshal(acks[0].Params, &ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.SessionID != 9 {
		t.Fatalf("ack session = %d, want 9", ack.SessionID)
	}
}

// The CDP event loop also carries every reply the agent's commands wait on, so
// a viewer slower than the browser must lose frames, never block the loop.
func TestScreencastDropsFramesForSlowConsumer(t *testing.T) {
	f := newScreencastFake()
	d := newTestDriver(t, f, nil)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	delivered := make(chan int, 4)
	if err := d.StartScreencast(context.Background(), ScreencastOptions{Width: 800, Height: 600}, func(seq int, _ []byte) {
		entered <- struct{}{}
		<-release
		delivered <- seq
	}); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = d.StopScreencast(context.Background()) })

	emitFrame(f, 1, []byte{1})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the consumer never received the first frame")
	}

	// The consumer is blocked; two more frames must not block the emitter.
	done := make(chan struct{})
	go func() {
		emitFrame(f, 2, []byte{2})
		emitFrame(f, 3, []byte{3})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a slow consumer blocked frame delivery")
	}
	if acks := f.callsOf("Page.screencastFrameAck"); len(acks) != 3 {
		t.Fatalf("ack calls = %d, want every frame acked", len(acks))
	}

	close(release)
	first := <-delivered
	second := <-delivered
	if first != 1 || second != 2 {
		t.Fatalf("delivered = %d,%d, want 1,2 (the newest frame may drop)", first, second)
	}
	select {
	case seq := <-delivered:
		t.Fatalf("delivered dropped frame %d", seq)
	case <-time.After(50 * time.Millisecond):
	}
}

// Stopping must end delivery and tell Chromium to stop encoding; a frame that
// races the stop is neither delivered nor acknowledged.
func TestScreencastStopEndsDelivery(t *testing.T) {
	f := newScreencastFake()
	d := newTestDriver(t, f, nil)
	delivered := make(chan int, 2)
	if err := d.StartScreencast(context.Background(), ScreencastOptions{Width: 800, Height: 600}, func(seq int, _ []byte) {
		delivered <- seq
	}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := d.StopScreencast(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if calls := f.callsOf("Page.stopScreencast"); len(calls) != 1 {
		t.Fatalf("stop calls = %d, want 1", len(calls))
	}
	acks := len(f.callsOf("Page.screencastFrameAck"))
	emitFrame(f, 1, []byte{1})
	select {
	case seq := <-delivered:
		t.Fatalf("frame %d was delivered after stop", seq)
	case <-time.After(50 * time.Millisecond):
	}
	if got := len(f.callsOf("Page.screencastFrameAck")); got != acks {
		t.Fatalf("acks after stop = %d, want %d", got, acks)
	}
	// Stopping twice is a no-op, not a second command or a panic.
	if err := d.StopScreencast(context.Background()); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if calls := f.callsOf("Page.stopScreencast"); len(calls) != 1 {
		t.Fatalf("stop calls after second stop = %d, want 1", len(calls))
	}
}

// One cast per driver: a second start must not stack handlers or steal the
// frame stream from the first viewer.
func TestScreencastRejectsSecondStart(t *testing.T) {
	f := newScreencastFake()
	d := newTestDriver(t, f, nil)
	if err := d.StartScreencast(context.Background(), ScreencastOptions{Width: 800, Height: 600}, func(int, []byte) {}); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = d.StopScreencast(context.Background()) })
	if err := d.StartScreencast(context.Background(), ScreencastOptions{Width: 800, Height: 600}, func(int, []byte) {}); err == nil {
		t.Fatal("second start was accepted")
	}
	if calls := f.callsOf("Page.startScreencast"); len(calls) != 1 {
		t.Fatalf("start calls = %d, want 1", len(calls))
	}
}

func TestScreencastRequiresPositiveSize(t *testing.T) {
	f := newScreencastFake()
	d := newTestDriver(t, f, nil)
	if err := d.StartScreencast(context.Background(), ScreencastOptions{}, func(int, []byte) {}); err == nil {
		t.Fatal("zero-sized viewport was accepted")
	}
	if calls := f.callsOf("Page.startScreencast"); len(calls) != 0 {
		t.Fatalf("start calls = %d, want 0", len(calls))
	}
}

// The viewport is global to the session: a live view must not leave the agent
// pinned to the viewer's geometry after the operator leaves.
func TestScreencastRestoresTheAgentsViewport(t *testing.T) {
	f := newScreencastFake()
	f.replies["Page.getLayoutMetrics"] = map[string]any{
		"cssLayoutViewport": map[string]any{"clientWidth": 1024, "clientHeight": 768},
	}
	d := newTestDriver(t, f, nil)
	if err := d.StartScreencast(context.Background(), ScreencastOptions{Width: 1280, Height: 800}, func(int, []byte) {}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := d.StopScreencast(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	calls := f.callsOf("Emulation.setDeviceMetricsOverride")
	if len(calls) != 2 {
		t.Fatalf("viewport calls = %d, want 2 (set and restore)", len(calls))
	}
	var restored struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	}
	if err := json.Unmarshal(calls[1].Params, &restored); err != nil {
		t.Fatalf("decode restore: %v", err)
	}
	if restored.Width != 1024 || restored.Height != 768 {
		t.Fatalf("restored viewport = %dx%d, want 1024x768", restored.Width, restored.Height)
	}
}

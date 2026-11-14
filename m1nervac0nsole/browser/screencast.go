package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ScreencastOptions is the frame geometry and JPEG quality the live view asks
// for. Width and Height also set the emulated viewport, so a frame's pixels and
// the page's CSS pixels stay one to one and a click maps without a scale factor.
type ScreencastOptions struct {
	Width   int
	Height  int
	Quality int
}

// defaultScreencastQuality keeps the live view readable without spending the
// task's CPU on full-quality JPEG encoding for every frame.
const defaultScreencastQuality = 60

// screencastAckTimeout bounds the frame acknowledgement. Chromium waits for it
// before sending the next frame, so a wedged pipe must not hold the event
// goroutine forever.
const screencastAckTimeout = 2 * time.Second

// screencastFrame is one encoded frame waiting for the consumer.
type screencastFrame struct {
	seq  int
	jpeg []byte
}

// screencast is one driver's running cast. The frame channel holds a single
// frame: a consumer slower than the browser loses frames instead of blocking
// the CDP read loop, which would stall every command the agent sends.
type screencast struct {
	// prev is the viewport the cast replaced, restored when it stops.
	prev *Viewport

	frames chan screencastFrame
	stop   chan struct{}
	done   chan struct{}
	halt   sync.Once
	seq    atomic.Int64
}

// screencasts keeps one cast per driver. Driver has no screencast field, and
// this file owns the whole feature, so the state lives beside it.
var screencasts sync.Map // map[*Driver]*screencast

// screencastHandlers records the drivers whose event handler is already
// registered, so starting a second cast does not stack handlers.
var screencastHandlers sync.Map // map[*Driver]struct{}

// StartScreencast begins streaming JPEG frames of the page to onFrame. It sets
// the emulated viewport to the requested size first, so the frames and the
// pointer coordinates share one geometry.
//
// Frames are acknowledged immediately and handed to a single consumer through a
// one-frame buffer: a slow consumer drops frames rather than blocking the event
// loop, because that loop also carries every reply the agent's commands wait on.
func (d *Driver) StartScreencast(ctx context.Context, opts ScreencastOptions, onFrame func(seq int, jpeg []byte)) error {
	if opts.Width <= 0 || opts.Height <= 0 {
		return fmt.Errorf("browser: screencast: width and height must be positive")
	}
	if onFrame == nil {
		return fmt.Errorf("browser: screencast: a frame callback is required")
	}
	quality := opts.Quality
	if quality <= 0 || quality > 100 {
		quality = defaultScreencastQuality
	}
	if _, loaded := screencasts.Load(d); loaded {
		return fmt.Errorf("browser: screencast: already running")
	}
	// The viewport is global to the session: remember what the agent was
	// looking at so the last viewer leaving puts it back.
	prev := d.layoutViewport(ctx)
	if err := d.SetViewport(ctx, Viewport{Width: opts.Width, Height: opts.Height}); err != nil {
		return err
	}
	st := &screencast{
		frames: make(chan screencastFrame, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		prev:   prev,
	}
	screencasts.Store(d, st)
	if _, loaded := screencastHandlers.LoadOrStore(d, struct{}{}); !loaded {
		d.On(d.screencastEvent)
	}
	go st.consume(onFrame)
	if _, err := d.Send(ctx, "Page.startScreencast", map[string]any{
		"format":        "jpeg",
		"quality":       quality,
		"maxWidth":      opts.Width,
		"maxHeight":     opts.Height,
		"everyNthFrame": 1,
	}); err != nil {
		screencasts.Delete(d)
		st.haltNow()
		<-st.done
		if prev != nil && !d.Closed() {
			// The cast never started, so the agent keeps the viewport the
			// failed attempt already changed.
			_ = d.SetViewport(ctx, *prev)
		}
		if d.Closed() {
			screencastHandlers.Delete(d)
		}
		return fmt.Errorf("browser: screencast: %w", err)
	}
	return nil
}

// StopScreencast ends the cast and waits for the consumer to finish. It is safe
// to call when no cast is running, and when the browser is already gone.
func (d *Driver) StopScreencast(ctx context.Context) error {
	value, ok := screencasts.LoadAndDelete(d)
	if !ok {
		return nil
	}
	st := value.(*screencast)
	st.haltNow()
	var err error
	if d.Closed() {
		// A closed driver can never start another cast, so drop the registration
		// that would otherwise keep the driver and its dead pipe alive.
		screencastHandlers.Delete(d)
	} else if _, serr := d.Send(ctx, "Page.stopScreencast", nil); serr != nil {
		err = fmt.Errorf("browser: stop screencast: %w", serr)
	}
	<-st.done
	if st.prev != nil && !d.Closed() {
		if rerr := d.SetViewport(ctx, *st.prev); rerr != nil && err == nil {
			err = fmt.Errorf("browser: restore viewport: %w", rerr)
		}
	}
	return err
}

// layoutViewport reads the viewport the page is laid out in. It is the size the
// agent's screenshots and clicks use, so restoring it after a live view leaves
// the agent exactly where it was.
func (d *Driver) layoutViewport(ctx context.Context) *Viewport {
	raw, err := d.Send(ctx, "Page.getLayoutMetrics", nil)
	if err != nil {
		return nil
	}
	var m struct {
		CSSLayoutViewport struct {
			ClientWidth  int `json:"clientWidth"`
			ClientHeight int `json:"clientHeight"`
		} `json:"cssLayoutViewport"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if m.CSSLayoutViewport.ClientWidth <= 0 || m.CSSLayoutViewport.ClientHeight <= 0 {
		return nil
	}
	return &Viewport{Width: m.CSSLayoutViewport.ClientWidth, Height: m.CSSLayoutViewport.ClientHeight}
}

// Closed reports whether Close has run. The live view uses it to end its stream
// when the browser it was showing is gone.
func (d *Driver) Closed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func (st *screencast) haltNow() {
	st.halt.Do(func() { close(st.stop) })
}

// consume delivers frames to the caller's callback until the cast stops. The
// callback runs on this goroutine, never on the CDP event goroutine.
func (st *screencast) consume(onFrame func(seq int, jpeg []byte)) {
	defer close(st.done)
	for {
		select {
		case <-st.stop:
			return
		case frame := <-st.frames:
			onFrame(frame.seq, frame.jpeg)
		}
	}
}

// screencastEvent acks every frame and offers it to the consumer. The ack comes
// first: Chromium will not send the next frame until it arrives, and dropping a
// frame must not stall the cast.
func (d *Driver) screencastEvent(method string, params json.RawMessage) {
	if method != "Page.screencastFrame" {
		return
	}
	value, ok := screencasts.Load(d)
	if !ok {
		return
	}
	st := value.(*screencast)
	var ev struct {
		Data      string `json:"data"`
		SessionID int    `json:"sessionId"`
	}
	if json.Unmarshal(params, &ev) != nil {
		return
	}
	ackCtx, cancel := context.WithTimeout(context.Background(), screencastAckTimeout)
	_, _ = d.Send(ackCtx, "Page.screencastFrameAck", map[string]any{"sessionId": ev.SessionID})
	cancel()
	jpeg, err := base64.StdEncoding.DecodeString(ev.Data)
	if err != nil {
		return
	}
	select {
	case st.frames <- screencastFrame{seq: int(st.seq.Add(1)), jpeg: jpeg}:
	default:
	}
}

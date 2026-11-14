package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// fakeLiveDriver stands in for the task's Chromium: it records the commands the
// live handlers send and lets a test push a frame.
type fakeLiveDriver struct {
	mu      sync.Mutex
	url     string
	sent    []fakeLiveCall
	onFrame func(int, []byte)
	stopped bool
	dialog  *browser.Dialog
	answer  *fakeLiveAnswer
	closed  bool
}

type fakeLiveCall struct {
	method string
	params map[string]any
}

type fakeLiveAnswer struct {
	accept bool
	text   string
}

func (f *fakeLiveDriver) StartScreencast(_ context.Context, _ browser.ScreencastOptions, onFrame func(int, []byte)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = false
	f.onFrame = onFrame
	return nil
}

func (f *fakeLiveDriver) StopScreencast(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return nil
}

func (f *fakeLiveDriver) Send(_ context.Context, method string, params any) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, _ := params.(map[string]any)
	f.sent = append(f.sent, fakeLiveCall{method: method, params: p})
	return json.RawMessage(`{}`), nil
}

func (f *fakeLiveDriver) URL() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.url
}

func (f *fakeLiveDriver) PendingDialog() (browser.Dialog, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dialog == nil {
		return browser.Dialog{}, false
	}
	return *f.dialog, true
}

func (f *fakeLiveDriver) AnswerDialog(_ context.Context, accept bool, promptText string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dialog == nil {
		return fmt.Errorf("browser: no dialog is open")
	}
	f.answer = &fakeLiveAnswer{accept: accept, text: promptText}
	f.dialog = nil
	return nil
}

func (f *fakeLiveDriver) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeLiveDriver) frame(seq int, jpeg []byte) {
	f.mu.Lock()
	cb := f.onFrame
	f.mu.Unlock()
	if cb != nil {
		cb(seq, jpeg)
	}
}

func (f *fakeLiveDriver) calls() []fakeLiveCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeLiveCall(nil), f.sent...)
}

func (f *fakeLiveDriver) isStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

type sseEvent struct {
	name string
	data string
}

// sseReader parses named SSE events in the background so a test can wait with
// a deadline instead of hanging the whole package.
type sseReader struct {
	events chan sseEvent
}

func newSSEReader(body io.Reader) *sseReader {
	r := &sseReader{events: make(chan sseEvent, 16)}
	go func() {
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.name != "" {
					r.events <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return r
}

func (r *sseReader) next(t *testing.T) sseEvent {
	t.Helper()
	select {
	case ev := <-r.events:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an SSE event")
		return sseEvent{}
	}
}

func newLiveTestTask(t *testing.T, m *Manager) *Task {
	t.Helper()
	task, err := m.CreateTaskWithOptions("live view", "probe the lab target for a banner and stop", db.TaskCreateOptions{})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	id, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatalf("task id %q: %v", task.ID, err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(id) })
	return task
}

func newLiveTestServer(t *testing.T, s *Server) (*httptest.Server, string) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return ts, tok
}

func liveDo(t *testing.T, ts *httptest.Server, tok, method, path string, body any, operator string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if operator != "" {
		req.Header.Set("X-Operator-Token", operator)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The live view is the operator's window into the agent's browser: opening it
// must claim the single operator slot, report the viewport, and forward frames.
func TestBrowserLiveStreamAndOwnershipPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task := newLiveTestTask(t, m)
	ts, tok := newLiveTestServer(t, s)

	fake := &fakeLiveDriver{url: "https://in.example/"}
	old := browserLiveFor
	browserLiveFor = func(*Server, string) liveDriver { return fake }
	t.Cleanup(func() { browserLiveFor = old })
	t.Cleanup(func() { liveRelease(task.ID, "op-a") })

	streamPath := "/api/tasks/" + task.ID + "/browser/stream"

	t.Run("frames and viewport", func(t *testing.T) {
		resp := liveDo(t, ts, tok, http.MethodGet, streamPath+"?op=op-a", nil, "")
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("stream status = %d (%s)", resp.StatusCode, body)
		}
		defer resp.Body.Close()
		rd := newSSEReader(resp.Body)

		ev := rd.next(t)
		if ev.name != "viewport" {
			t.Fatalf("first event = %q, want viewport", ev.name)
		}
		var viewport struct {
			Width  int    `json:"width"`
			Height int    `json:"height"`
			Token  string `json:"token"`
		}
		if err := json.Unmarshal([]byte(ev.data), &viewport); err != nil {
			t.Fatalf("decode viewport: %v", err)
		}
		if viewport.Width != liveViewportWidth || viewport.Height != liveViewportHeight || viewport.Token != "op-a" {
			t.Fatalf("viewport = %+v", viewport)
		}

		jpeg := []byte{0xff, 0xd8, 0xff, 0x00}
		fake.frame(7, jpeg)
		ev = rd.next(t)
		if ev.name != "frame" {
			t.Fatalf("event = %q, want frame", ev.name)
		}
		var frame browserLiveFrame
		if err := json.Unmarshal([]byte(ev.data), &frame); err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		if frame.Seq != 7 || frame.Data != base64.StdEncoding.EncodeToString(jpeg) {
			t.Fatalf("frame = %+v", frame)
		}

		resp.Body.Close()
		waitFor(t, "the screencast to stop", fake.isStopped)
		waitFor(t, "the operator slot to be released", func() bool { return liveHolder(task.ID) == "" })
	})

	t.Run("second operator gets 409", func(t *testing.T) {
		first := liveDo(t, ts, tok, http.MethodGet, streamPath+"?op=op-a", nil, "")
		if first.StatusCode != http.StatusOK {
			t.Fatalf("first stream status = %d", first.StatusCode)
		}
		defer first.Body.Close()
		rd := newSSEReader(first.Body)
		rd.next(t) // viewport: the slot is held from here

		second := liveDo(t, ts, tok, http.MethodGet, streamPath+"?op=op-b", nil, "")
		second.Body.Close()
		if second.StatusCode != http.StatusConflict {
			t.Fatalf("second stream status = %d, want 409", second.StatusCode)
		}

		wrong := liveDo(t, ts, tok, http.MethodDelete, streamPath, nil, "op-b")
		wrong.Body.Close()
		if wrong.StatusCode != http.StatusConflict {
			t.Fatalf("wrong-token release status = %d, want 409", wrong.StatusCode)
		}

		release := liveDo(t, ts, tok, http.MethodDelete, streamPath, nil, "op-a")
		release.Body.Close()
		if release.StatusCode != http.StatusNoContent {
			t.Fatalf("release status = %d, want 204", release.StatusCode)
		}
		waitFor(t, "the released stream to end", fake.isStopped)

		third := liveDo(t, ts, tok, http.MethodGet, streamPath+"?op=op-b", nil, "")
		if third.StatusCode != http.StatusOK {
			t.Fatalf("stream after release status = %d, want 200", third.StatusCode)
		}
		third.Body.Close()
		waitFor(t, "the second operator to release the slot", func() bool { return liveHolder(task.ID) == "" })
	})

	t.Run("parked dialog is announced", func(t *testing.T) {
		fake.mu.Lock()
		fake.dialog = &browser.Dialog{Type: "confirm", Message: "delete the record?", URL: "https://in.example/"}
		fake.mu.Unlock()
		t.Cleanup(func() {
			fake.mu.Lock()
			fake.dialog = nil
			fake.mu.Unlock()
		})

		resp := liveDo(t, ts, tok, http.MethodGet, streamPath+"?op=op-a", nil, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream status = %d", resp.StatusCode)
		}
		defer resp.Body.Close()
		rd := newSSEReader(resp.Body)
		if ev := rd.next(t); ev.name != "viewport" {
			t.Fatalf("first event = %q, want viewport", ev.name)
		}
		ev := rd.next(t)
		if ev.name != "dialog" {
			t.Fatalf("event = %q, want dialog", ev.name)
		}
		var announced browserLiveDialogEvent
		if err := json.Unmarshal([]byte(ev.data), &announced); err != nil {
			t.Fatalf("decode dialog: %v", err)
		}
		if !announced.Open || announced.Type != "confirm" || announced.Message != "delete the record?" {
			t.Fatalf("dialog = %+v", announced)
		}
		resp.Body.Close()
		waitFor(t, "the operator slot to be released", func() bool { return liveHolder(task.ID) == "" })
	})
}

// Operator input is a browser action: it must be refused unless the page is in
// scope, and it must be refused when no browser session exists at all.
func TestBrowserLiveInputScopePG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task := newLiveTestTask(t, m)
	ts, tok := newLiveTestServer(t, s)
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)

	fake := &fakeLiveDriver{url: "https://out.example/login"}
	old := browserLiveFor
	browserLiveFor = func(*Server, string) liveDriver { return fake }
	t.Cleanup(func() { browserLiveFor = old })

	ruleID, err := m.Assets().AddTaskScopeRule(taskID, "exclude", "out.example", "live view test")
	if err != nil {
		t.Fatalf("add scope rule: %v", err)
	}
	t.Cleanup(func() { _ = m.Assets().DeleteTaskScopeRule(taskID, ruleID) })

	if !liveClaim(task.ID, "op-a", func() {}, nil) {
		t.Fatal("could not claim the operator slot")
	}
	t.Cleanup(func() { liveRelease(task.ID, "op-a") })

	inputPath := "/api/tasks/" + task.ID + "/browser/input"
	press := map[string]any{"kind": "mouse", "type": "mousePressed", "x": 10, "y": 20, "button": "left", "click_count": 1}

	refused := liveDo(t, ts, tok, http.MethodPost, inputPath, press, "op-a")
	refused.Body.Close()
	if refused.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope input status = %d, want 403", refused.StatusCode)
	}
	if calls := fake.calls(); len(calls) != 0 {
		t.Fatalf("out-of-scope input reached the browser: %+v", calls)
	}

	fake.mu.Lock()
	fake.url = "https://in.example/login"
	fake.mu.Unlock()
	allowed := liveDo(t, ts, tok, http.MethodPost, inputPath, press, "op-a")
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("in-scope input status = %d, want 200", allowed.StatusCode)
	}
	calls := fake.calls()
	if len(calls) != 1 || calls[0].method != "Input.dispatchMouseEvent" {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].params["type"] != "mousePressed" || calls[0].params["x"] != float64(10) || calls[0].params["y"] != float64(20) {
		t.Fatalf("mouse params = %+v", calls[0].params)
	}

	// A viewer that never claimed the slot cannot type into the page.
	stolen := liveDo(t, ts, tok, http.MethodPost, inputPath, press, "op-b")
	stolen.Body.Close()
	if stolen.StatusCode != http.StatusConflict {
		t.Fatalf("unclaimed input status = %d, want 409", stolen.StatusCode)
	}

	// No session at all is a refusal, not a browser launch.
	browserLiveFor = func(*Server, string) liveDriver { return nil }
	missing := liveDo(t, ts, tok, http.MethodPost, inputPath, press, "op-a")
	missing.Body.Close()
	if missing.StatusCode != http.StatusConflict {
		t.Fatalf("input without a session status = %d, want 409", missing.StatusCode)
	}
}

// A parked dialog is the operator's to answer; the answer goes to the page and
// a second answer finds no dialog.
func TestBrowserLiveDialogPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task := newLiveTestTask(t, m)
	ts, tok := newLiveTestServer(t, s)

	fake := &fakeLiveDriver{
		url:    "https://in.example/mfa",
		dialog: &browser.Dialog{Type: "prompt", Message: "enter the code", URL: "https://in.example/mfa"},
	}
	old := browserLiveFor
	browserLiveFor = func(*Server, string) liveDriver { return fake }
	t.Cleanup(func() { browserLiveFor = old })
	if !liveClaim(task.ID, "op-a", func() {}, nil) {
		t.Fatal("could not claim the operator slot")
	}
	t.Cleanup(func() { liveRelease(task.ID, "op-a") })

	dialogPath := "/api/tasks/" + task.ID + "/browser/dialog"
	resp := liveDo(t, ts, tok, http.MethodPost, dialogPath, map[string]any{"accept": true, "prompt_text": "123456"}, "op-a")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dialog answer status = %d, want 200", resp.StatusCode)
	}
	fake.mu.Lock()
	answer := fake.answer
	fake.mu.Unlock()
	if answer == nil || !answer.accept || answer.text != "123456" {
		t.Fatalf("answer = %+v", answer)
	}

	again := liveDo(t, ts, tok, http.MethodPost, dialogPath, map[string]any{"accept": true}, "op-a")
	again.Body.Close()
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("second answer status = %d, want 409", again.StatusCode)
	}
}

// The client's event shape must map to the exact CDP commands, and malformed
// events must be refused before they reach the page.
func TestBrowserInputCDP(t *testing.T) {
	cases := []struct {
		name   string
		in     browserInput
		method string
		params map[string]any
	}{
		{
			name:   "mouse press",
			in:     browserInput{Kind: "mouse", Type: "mousePressed", X: 10, Y: 20, Button: "left", ClickCount: 1},
			method: "Input.dispatchMouseEvent",
			params: map[string]any{"type": "mousePressed", "x": 10.0, "y": 20.0, "button": "left", "clickCount": 1},
		},
		{
			name:   "mouse move needs no click count",
			in:     browserInput{Kind: "mouse", Type: "mouseMoved", X: 1, Y: 2},
			method: "Input.dispatchMouseEvent",
			params: map[string]any{"type": "mouseMoved", "x": 1.0, "y": 2.0},
		},
		{
			name:   "wheel",
			in:     browserInput{Kind: "scroll", X: 5, Y: 6, DeltaX: 0, DeltaY: 120},
			method: "Input.dispatchMouseEvent",
			params: map[string]any{"type": "mouseWheel", "x": 5.0, "y": 6.0, "deltaX": 0.0, "deltaY": 120.0},
		},
		{
			name:   "special key",
			in:     browserInput{Kind: "key", Type: "keyDown", Key: "Enter", Code: "Enter", Modifiers: 8, WindowsVirtualKeyCode: 13},
			method: "Input.dispatchKeyEvent",
			params: map[string]any{"type": "keyDown", "key": "Enter", "code": "Enter", "modifiers": 8, "windowsVirtualKeyCode": 13},
		},
		{
			name:   "text",
			in:     browserInput{Kind: "text", Text: "hello"},
			method: "Input.insertText",
			params: map[string]any{"text": "hello"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			method, params, err := c.in.cdp()
			if err != nil {
				t.Fatalf("cdp: %v", err)
			}
			if method != c.method {
				t.Fatalf("method = %q, want %q", method, c.method)
			}
			if !reflect.DeepEqual(params, c.params) {
				t.Fatalf("params = %#v, want %#v", params, c.params)
			}
		})
	}

	bad := []browserInput{
		{Kind: "nope"},
		{Kind: "mouse", Type: "click", X: 1, Y: 1},
		{Kind: "mouse", Type: "mousePressed", X: -1, Y: 1},
		{Kind: "key", Type: "keyDown"},
		{Kind: "text"},
	}
	for _, in := range bad {
		if _, _, err := in.cdp(); err == nil {
			t.Fatalf("%+v was accepted", in)
		}
	}
}

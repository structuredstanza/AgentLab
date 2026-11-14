package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// fakeConn answers CDP from a table and emits scripted events, so every driver
// behaviour is testable without a browser.
type fakeConn struct {
	mu       sync.Mutex
	calls    []fakeCall
	replies  map[string]any
	handle   func(method string, params json.RawMessage) (any, bool, error)
	emitOn   map[string][]fakeEvent
	handlers []func(string, json.RawMessage)
	dead     bool
}

type fakeCall struct {
	Method string
	Params json.RawMessage
}

type fakeEvent struct {
	Method string
	Params any
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		replies: map[string]any{
			"Page.getNavigationHistory": map[string]any{
				"currentIndex": 0,
				"entries": []any{
					map[string]any{"url": "about:blank", "title": "about:blank"},
				},
			},
			"Input.dispatchMouseEvent":    map[string]any{},
			"Input.dispatchKeyEvent":      map[string]any{},
			"Input.insertText":            map[string]any{},
			"Page.handleJavaScriptDialog": map[string]any{},
		},
		emitOn: map[string][]fakeEvent{},
	}
}

func (f *fakeConn) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	raw, _ := json.Marshal(params)

	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{Method: method, Params: raw})
	if f.dead {
		f.mu.Unlock()
		return nil, fmt.Errorf("fake: %w", errTransport)
	}
	handle := f.handle
	reply, ok := f.replies[method]
	events := append([]fakeEvent(nil), f.emitOn[method]...)
	f.mu.Unlock()

	result := reply
	if handle != nil {
		custom, handled, err := handle(method, raw)
		if err != nil {
			return nil, err
		}
		if handled {
			result = custom
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("fake: unexpected method %s", method)
	}
	for _, event := range events {
		f.emit(event.Method, event.Params)
	}
	return json.Marshal(result)
}

func (f *fakeConn) On(fn func(method string, params json.RawMessage)) {
	f.mu.Lock()
	f.handlers = append(f.handlers, fn)
	f.mu.Unlock()
}

func (f *fakeConn) emit(method string, params any) {
	raw, _ := json.Marshal(params)
	f.mu.Lock()
	handlers := append([]func(string, json.RawMessage){}, f.handlers...)
	f.mu.Unlock()
	for _, fn := range handlers {
		fn(method, raw)
	}
}

func (f *fakeConn) setDead(dead bool) {
	f.mu.Lock()
	f.dead = dead
	f.mu.Unlock()
}

func (f *fakeConn) callsOf(method string) []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeCall
	for _, call := range f.calls {
		if call.Method == method {
			out = append(out, call)
		}
	}
	return out
}

func newTestDriver(t *testing.T, c conn, launch func(context.Context) (conn, error)) *Driver {
	t.Helper()
	if launch == nil {
		launch = func(context.Context) (conn, error) {
			return nil, errors.New("unexpected relaunch")
		}
	}
	return newDriver(c, launch)
}

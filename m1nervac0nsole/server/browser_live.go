package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// The live view shows the task's browser at a fixed emulated size. 1280x800 is
// the size the screencast sets, so one frame pixel is one CSS pixel and a click
// needs no scale factor beyond the rendered image.
const (
	liveViewportWidth  = 1280
	liveViewportHeight = 800
)

// liveDriver is the driver surface the live view uses. It is an interface so
// the handlers can be exercised without Chromium.
type liveDriver interface {
	StartScreencast(ctx context.Context, opts browser.ScreencastOptions, onFrame func(seq int, jpeg []byte)) error
	StopScreencast(ctx context.Context) error
	Send(ctx context.Context, method string, params any) (json.RawMessage, error)
	URL() string
	PendingDialog() (browser.Dialog, bool)
	AnswerDialog(ctx context.Context, accept bool, promptText string) error
	Closed() bool
}

// browserLiveFor returns the task's running browser without launching one: the
// live view shows the browser the agent opened, never a second one. It is a
// package variable so tests can substitute a driver; production reads the
// registry.
var browserLiveFor = func(s *Server, taskID string) liveDriver {
	s.browsers.mu.Lock()
	defer s.browsers.mu.Unlock()
	sess := s.browsers.byID[taskID]
	if sess == nil {
		return nil
	}
	sess.lastUsed = time.Now()
	return sess.drv
}

// liveOwner is the one operator session watching a task's browser. The cancel
// ends the stream when the operator releases it, and done closes once the
// stream has stopped the screencast, so a released view cannot keep a second
// screencast running.
type liveOwner struct {
	token  string
	cancel context.CancelFunc
	done   <-chan struct{}
}

// liveOwners is the one operator session per task. A package-level table keeps
// ownership out of Server, which this feature only touches to add routes.
var liveOwners = struct {
	mu     sync.Mutex
	byTask map[string]*liveOwner
}{byTask: map[string]*liveOwner{}}

// liveClaim takes the task's operator slot for token. Any existing owner is the
// 409 case: one operator stream at a time, even for the same token, because a
// second screencast on one page cannot run.
func liveClaim(taskID, token string, cancel context.CancelFunc, done <-chan struct{}) bool {
	liveOwners.mu.Lock()
	defer liveOwners.mu.Unlock()
	if liveOwners.byTask[taskID] != nil {
		return false
	}
	liveOwners.byTask[taskID] = &liveOwner{token: token, cancel: cancel, done: done}
	return true
}

// liveRelease frees the slot without ending the stream. The stream's own defer
// calls it; releasing an already-released slot is a no-op.
func liveRelease(taskID, token string) {
	liveOwners.mu.Lock()
	defer liveOwners.mu.Unlock()
	if cur := liveOwners.byTask[taskID]; cur != nil && cur.token == token {
		delete(liveOwners.byTask, taskID)
	}
}

// liveStop frees the slot and ends the matching stream, which is what DELETE
// means. It waits for the stream to stop its screencast, so the operator who
// takes over next does not race a cast that is still running.
func liveStop(taskID, token string) bool {
	liveOwners.mu.Lock()
	cur := liveOwners.byTask[taskID]
	if cur == nil || cur.token != token {
		liveOwners.mu.Unlock()
		return false
	}
	delete(liveOwners.byTask, taskID)
	liveOwners.mu.Unlock()
	cur.cancel()
	if cur.done != nil {
		select {
		case <-cur.done:
		case <-time.After(2 * time.Second):
		}
	}
	return true
}

// liveHolder is the token currently holding the task's operator slot.
func liveHolder(taskID string) string {
	liveOwners.mu.Lock()
	defer liveOwners.mu.Unlock()
	if cur := liveOwners.byTask[taskID]; cur != nil {
		return cur.token
	}
	return ""
}

// operatorToken reads the operator's session token: the header for a POST or
// DELETE, the query for an EventSource, which cannot set headers. The query
// parameter is "op", not "token": sseUrl already uses "token" for the JWT, and
// one name cannot carry both.
func operatorToken(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Operator-Token")); v != "" {
		return v
	}
	return strings.TrimSpace(r.URL.Query().Get("op"))
}

// newOperatorToken mints a token for a client that did not bring one. It is not
// an authentication credential: the request is already authenticated, and this
// only arbitrates between two operators of the same task.
func newOperatorToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("op-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// browserStream is the operator's live view: an SSE stream of JPEG frames plus
// the viewport and any parked dialog. Opening it claims the task's single
// operator slot; releasing it (DELETE, or disconnect) frees the slot.
func (s *Server) browserStream(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	drv := browserLiveFor(s, task.ID)
	if drv == nil {
		writeErr(w, http.StatusConflict, "this task has no browser session: the agent has not opened one")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	token := operatorToken(r)
	if token == "" {
		token = newOperatorToken()
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	if !liveClaim(task.ID, token, cancel, done) {
		writeErr(w, http.StatusConflict, "another operator is watching this browser")
		return
	}
	defer liveRelease(task.ID, token)

	frames := make(chan browserLiveFrame, 1)
	if err := drv.StartScreencast(ctx, browser.ScreencastOptions{
		Width:  liveViewportWidth,
		Height: liveViewportHeight,
	}, func(seq int, jpeg []byte) {
		select {
		case frames <- browserLiveFrame{Seq: seq, Data: base64.StdEncoding.EncodeToString(jpeg)}:
		case <-ctx.Done():
		}
	}); err != nil {
		writeErr(w, http.StatusBadGateway, "could not start the live view: "+err.Error())
		return
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = drv.StopScreencast(stopCtx)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		flusher.Flush()
	}
	send("viewport", map[string]any{
		"width":  liveViewportWidth,
		"height": liveViewportHeight,
		"token":  token,
	})

	// A dialog is parked for the operator, not the agent, so the view reports
	// it whenever it appears or is answered. Polling is enough: a dialog blocks
	// the page, and the operator answers it from this same view.
	var dialogKey string
	emitDialog := func() {
		dlg, open := drv.PendingDialog()
		key := ""
		if open {
			key = dlg.Type + "\x00" + dlg.Message + "\x00" + dlg.DefaultPrompt
		}
		if key == dialogKey {
			return
		}
		dialogKey = key
		send("dialog", browserLiveDialogEvent{
			Open:          open,
			Type:          dlg.Type,
			Message:       dlg.Message,
			DefaultPrompt: dlg.DefaultPrompt,
			URL:           dlg.URL,
		})
	}
	emitDialog()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-frames:
			send("frame", frame)
		case <-tick.C:
			if drv.Closed() {
				return
			}
			// Watching is a use of the session: keep the idle reaper from
			// closing a browser the operator is looking at.
			s.touchBrowser(task.ID)
			emitDialog()
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// browserLiveFrame is one SSE frame: the sequence number orders frames, and the
// data is a base64 JPEG.
type browserLiveFrame struct {
	Seq  int    `json:"seq"`
	Data string `json:"data"`
}

// browserLiveDialogEvent reports a parked dialog, or its answer when Open is
// false.
type browserLiveDialogEvent struct {
	Open          bool   `json:"open"`
	Type          string `json:"type,omitempty"`
	Message       string `json:"message,omitempty"`
	DefaultPrompt string `json:"default_prompt,omitempty"`
	URL           string `json:"url,omitempty"`
}

// browserStreamRelease frees the operator slot and ends the stream. It is
// idempotent: a stream that already disconnected leaves nothing to release.
func (s *Server) browserStreamRelease(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	token := operatorToken(r)
	if holder := liveHolder(task.ID); holder != "" && holder != token {
		writeErr(w, http.StatusConflict, "another operator is watching this browser")
		return
	}
	liveStop(task.ID, token)
	w.WriteHeader(http.StatusNoContent)
}

// browserInput forwards one operator input event to the page. Input is a
// browser action like any tool call, so it takes the same boundary check: the
// page must be in scope, and an unreadable page is refused rather than guessed.
func (s *Server) browserInput(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	drv := browserLiveFor(s, task.ID)
	if drv == nil {
		writeErr(w, http.StatusConflict, "this task has no browser session: the agent has not opened one")
		return
	}
	token := operatorToken(r)
	if token == "" || liveHolder(task.ID) != token {
		writeErr(w, http.StatusConflict, "another operator has control of this browser")
		return
	}
	var in browserInput
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	method, params, err := in.cdp()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if refusal := s.liveInputRefusal(task, drv); refusal != "" {
		writeErr(w, http.StatusForbidden, refusal)
		return
	}
	if _, err := drv.Send(r.Context(), method, params); err != nil {
		writeErr(w, http.StatusBadGateway, "the browser did not accept the input: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// browserDialog answers the parked dialog. It needs the operator slot for the
// same reason input does: the answer is a browser action.
func (s *Server) browserDialog(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	drv := browserLiveFor(s, task.ID)
	if drv == nil {
		writeErr(w, http.StatusConflict, "this task has no browser session: the agent has not opened one")
		return
	}
	token := operatorToken(r)
	if token == "" || liveHolder(task.ID) != token {
		writeErr(w, http.StatusConflict, "another operator has control of this browser")
		return
	}
	var in struct {
		Accept     bool   `json:"accept"`
		PromptText string `json:"prompt_text"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if err := drv.AnswerDialog(r.Context(), in.Accept, in.PromptText); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// liveInputRefusal judges the page the operator's input would reach. The same
// two checks a browser tool call gets: a readable absolute http(s) page, and a
// host the task does not exclude.
func (s *Server) liveInputRefusal(task *Task, drv liveDriver) string {
	host, refusal := browserURLHost(drv.URL())
	if refusal != "" {
		return "the browser is not on a page that can be checked: " + refusal
	}
	id, err := parseTaskID(task.ID)
	if err != nil {
		return "the task id is invalid"
	}
	return scopeRefusal(db.NewTaskScopeChecker(s.m.Assets(), id), host)
}

// touchBrowser keeps the idle reaper from closing a browser an operator is
// watching: the live view is a use of the session even when the agent is idle.
func (s *Server) touchBrowser(taskID string) {
	s.browsers.mu.Lock()
	defer s.browsers.mu.Unlock()
	if sess := s.browsers.byID[taskID]; sess != nil {
		sess.lastUsed = time.Now()
	}
}

// browserInput is one operator input event. Kind selects the CDP command; the
// remaining fields are the ones that command needs. Coordinates are CSS pixels
// of the emulated viewport, which the client maps from the rendered image.
type browserInput struct {
	Kind                  string  `json:"kind"`
	Type                  string  `json:"type"`
	X                     float64 `json:"x"`
	Y                     float64 `json:"y"`
	Button                string  `json:"button"`
	ClickCount            int     `json:"click_count"`
	Key                   string  `json:"key"`
	Code                  string  `json:"code"`
	Text                  string  `json:"text"`
	Modifiers             int     `json:"modifiers"`
	DeltaX                float64 `json:"delta_x"`
	DeltaY                float64 `json:"delta_y"`
	WindowsVirtualKeyCode int     `json:"windows_virtual_key_code"`
}

// cdp turns the event into the command Chromium expects. Unknown kinds and
// malformed events are refused here, before anything reaches the page.
func (in browserInput) cdp() (string, map[string]any, error) {
	switch in.Kind {
	case "mouse":
		switch in.Type {
		case "mousePressed", "mouseReleased", "mouseMoved":
		default:
			return "", nil, fmt.Errorf("mouse input needs type mousePressed, mouseReleased or mouseMoved")
		}
		if in.X < 0 || in.Y < 0 {
			return "", nil, fmt.Errorf("mouse input needs non-negative coordinates")
		}
		params := map[string]any{"type": in.Type, "x": in.X, "y": in.Y}
		if in.Button != "" {
			params["button"] = in.Button
		}
		clicks := in.ClickCount
		if clicks <= 0 && in.Type != "mouseMoved" {
			clicks = 1
		}
		if clicks > 0 {
			params["clickCount"] = clicks
		}
		return "Input.dispatchMouseEvent", params, nil
	case "scroll":
		if in.X < 0 || in.Y < 0 {
			return "", nil, fmt.Errorf("scroll input needs non-negative coordinates")
		}
		return "Input.dispatchMouseEvent", map[string]any{
			"type":   "mouseWheel",
			"x":      in.X,
			"y":      in.Y,
			"deltaX": in.DeltaX,
			"deltaY": in.DeltaY,
		}, nil
	case "key":
		switch in.Type {
		case "keyDown", "keyUp", "rawKeyDown", "char":
		default:
			return "", nil, fmt.Errorf("key input needs type keyDown, keyUp, rawKeyDown or char")
		}
		if in.Key == "" {
			return "", nil, fmt.Errorf("key input needs a key")
		}
		params := map[string]any{"type": in.Type, "key": in.Key}
		if in.Code != "" {
			params["code"] = in.Code
		}
		if in.Text != "" {
			params["text"] = in.Text
		}
		if in.Modifiers != 0 {
			params["modifiers"] = in.Modifiers
		}
		if in.WindowsVirtualKeyCode > 0 {
			params["windowsVirtualKeyCode"] = in.WindowsVirtualKeyCode
		}
		return "Input.dispatchKeyEvent", params, nil
	case "text":
		if in.Text == "" {
			return "", nil, fmt.Errorf("text input needs text")
		}
		return "Input.insertText", map[string]any{"text": in.Text}, nil
	}
	return "", nil, fmt.Errorf("unknown input kind %q", in.Kind)
}

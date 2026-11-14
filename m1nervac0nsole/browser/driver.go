// Package browser drives the guest's headless Chromium over the DevTools pipe.
//
// A worker gets one browser per task, launched with its own profile, and talks
// to it through a two-method seam: Send for commands and On for events. The
// real transport is Chromium's --remote-debugging-pipe (CDP JSON on fd 3 and 4,
// NUL-terminated), which keeps the product free of a WebSocket client; tests
// substitute a fake that answers from a table, so ref staleness, dialog policy
// and crash recovery are exercised without a browser.
package browser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// errTransport marks a dead browser connection. Driver.Send uses it to tell a
// lost process (relaunch) from a protocol error (report).
var errTransport = errors.New("browser connection lost")

// conn is the whole CDP surface the driver needs. Keeping it at two methods is
// what makes every behaviour below testable against a table-driven fake.
type conn interface {
	Send(ctx context.Context, method string, params any) (json.RawMessage, error)
	On(func(method string, params json.RawMessage))
}

// Options is what one task's browser needs. The caller owns the profile
// directory: one per task keeps cookies and storage from leaking between
// engagements.
type Options struct {
	// Executable is the Chromium binary. Empty means "chromium" on PATH.
	Executable string
	// UserDataDir is the task's profile directory.
	UserDataDir string
	// ProxyServer is the recording proxy URL. When set, certificate errors are
	// ignored because the proxy presents its own CA.
	ProxyServer string
	// AllowRequest judges every request before the browser sends it. Nil
	// allows everything, which keeps the package usable without a scope. An
	// error blocks the request and its host is reported by BlockedRequests.
	AllowRequest func(rawURL string) error
	// DownloadDir is where downloads land. Empty leaves the browser's default.
	DownloadDir string
}

// Driver is one browser process and the page it is attached to.
type Driver struct {
	launch func(context.Context) (conn, error)

	mu       sync.Mutex
	c        conn
	handlers []func(string, json.RawMessage)
	waiters  map[string][]chan struct{}

	gen        int
	refs       map[string]Ref
	url        string
	title      string
	viewport   *Viewport
	parked     *Dialog
	lastAction time.Time
	closed     bool

	allowRequest func(string) error
	blocked      []string
	blockedSeen  map[string]bool

	console    []ConsoleEntry
	consoleSeq int64

	downloadDir string
	downloads   map[string]string
	downloaded  []string

	recoverMu sync.Mutex
}

// Launch starts the browser with the task's profile and attaches to its page.
//
// The process outlives ctx: the driver is closed explicitly, so a request
// context expiring must not kill the browser mid-task.
func Launch(ctx context.Context, opts Options) (*Driver, error) {
	if strings.TrimSpace(opts.UserDataDir) == "" {
		return nil, fmt.Errorf("browser: launch: a user data dir is required, one profile per task")
	}
	d := newDriver(nil, func(ctx context.Context) (conn, error) {
		return startPipe(ctx, opts)
	})
	d.mu.Lock()
	d.allowRequest = opts.AllowRequest
	d.downloadDir = absPath(opts.DownloadDir)
	d.mu.Unlock()
	c, err := d.launch(ctx)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.c = c
	d.mu.Unlock()
	c.On(d.dispatch)
	if _, err := c.Send(ctx, "Page.enable", nil); err != nil {
		closeConn(c)
		return nil, fmt.Errorf("browser: launch: %w", err)
	}
	if _, err := c.Send(ctx, "DOM.enable", nil); err != nil {
		closeConn(c)
		return nil, fmt.Errorf("browser: launch: %w", err)
	}
	if err := d.enableCapabilities(ctx, c); err != nil {
		closeConn(c)
		return nil, fmt.Errorf("browser: launch: %w", err)
	}
	return d, nil
}

// enableCapabilities turns on the per-driver event surfaces after every
// (re)launch: console capture always, interception and downloads when asked.
func (d *Driver) enableCapabilities(ctx context.Context, c conn) error {
	if _, err := c.Send(ctx, "Runtime.enable", nil); err != nil {
		return err
	}
	if err := d.enableFetch(ctx, c); err != nil {
		return err
	}
	return d.enableDownloads(ctx, c)
}

// newDriver wires the driver's own event handling. Tests call it directly with
// a fake conn and a relaunch function; Launch calls it before the process
// exists.
func newDriver(c conn, launch func(context.Context) (conn, error)) *Driver {
	d := &Driver{
		launch:  launch,
		gen:     1,
		refs:    map[string]Ref{},
		waiters: map[string][]chan struct{}{},
	}
	d.On(d.handleEvent)
	if c != nil {
		d.c = c
		c.On(d.dispatch)
	}
	return d
}

// Send speaks CDP, relaunching once if the browser process died.
//
// A command that died after the browser acted may run twice; that is the price
// of not losing the session, and the common case is a process that is gone.
func (d *Driver) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	d.mu.Lock()
	c := d.c
	d.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("browser: not launched")
	}
	raw, err := c.Send(ctx, method, params)
	if err == nil || !errors.Is(err, errTransport) {
		return raw, err
	}
	if rerr := d.recover(ctx, c); rerr != nil {
		return nil, rerr
	}
	d.mu.Lock()
	c = d.c
	d.mu.Unlock()
	return c.Send(ctx, method, params)
}

// On registers an event handler. Handlers run on the connection's event
// goroutine and must not assume they are the only one.
func (d *Driver) On(fn func(method string, params json.RawMessage)) {
	d.mu.Lock()
	d.handlers = append(d.handlers, fn)
	d.mu.Unlock()
}

// Close stops the browser and its profile process.
func (d *Driver) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	c := d.c
	d.mu.Unlock()
	if c == nil {
		return nil
	}
	return closeConn(c)
}

// URL is the page the driver last navigated to or saw a top-level frame
// navigate to.
func (d *Driver) URL() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.url
}

// Title is the title of the current history entry, refreshed after actions.
func (d *Driver) Title() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.title
}

func closeConn(c conn) error {
	if closer, ok := c.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// dispatch fans an event out to one-shot waiters and to registered handlers.
func (d *Driver) dispatch(method string, params json.RawMessage) {
	d.mu.Lock()
	waiters := d.waiters[method]
	delete(d.waiters, method)
	handlers := append([]func(string, json.RawMessage){}, d.handlers...)
	d.mu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
	for _, fn := range handlers {
		fn(method, params)
	}
}

// expect returns a channel closed by the next event with that method.
func (d *Driver) expect(method string) <-chan struct{} {
	ch := make(chan struct{})
	d.mu.Lock()
	d.waiters[method] = append(d.waiters[method], ch)
	d.mu.Unlock()
	return ch
}

// dropWaiter removes a waiter that will never be satisfied.
func (d *Driver) dropWaiter(method string, ch <-chan struct{}) {
	d.mu.Lock()
	list := d.waiters[method]
	for i, c := range list {
		if c == ch {
			d.waiters[method] = append(list[:i], list[i+1:]...)
			break
		}
	}
	d.mu.Unlock()
}

func (d *Driver) markAction() {
	d.mu.Lock()
	d.lastAction = time.Now()
	d.mu.Unlock()
}

func (d *Driver) setURL(url, title string) {
	d.mu.Lock()
	d.url = url
	d.title = title
	d.mu.Unlock()
}

// PageState is what every mutating call returns, so the caller can decide
// whether the page moved before taking a new snapshot.
type PageState struct {
	URL   string
	Title string
}

func (d *Driver) pageState() PageState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return PageState{URL: d.url, Title: d.title}
}

// refresh updates URL and title from the browser's own history. A failure is
// not reported: the action already happened, and a stale title is harmless.
func (d *Driver) refresh(ctx context.Context) {
	raw, err := d.Send(ctx, "Page.getNavigationHistory", nil)
	if err != nil {
		return
	}
	var history struct {
		CurrentIndex int `json:"currentIndex"`
		Entries      []struct {
			URL   string `json:"url"`
			Title string `json:"title"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &history) != nil {
		return
	}
	if history.CurrentIndex >= 0 && history.CurrentIndex < len(history.Entries) {
		entry := history.Entries[history.CurrentIndex]
		d.setURL(entry.URL, entry.Title)
	}
}

func (d *Driver) handleEvent(method string, params json.RawMessage) {
	switch method {
	case "Page.frameNavigated":
		d.frameNavigated(params)
	case "Page.javascriptDialogOpening":
		d.dialogOpening(params)
	case "Page.javascriptDialogClosed":
		d.dialogClosed()
	case "Fetch.requestPaused":
		d.requestPaused(params)
	case "Runtime.consoleAPICalled":
		d.consoleAPICalled(params)
	case "Runtime.exceptionThrown":
		d.exceptionThrown(params)
	case "Browser.downloadWillBegin":
		d.downloadWillBegin(params)
	case "Browser.downloadProgress":
		d.downloadProgress(params)
	}
}

func (d *Driver) frameNavigated(params json.RawMessage) {
	var ev struct {
		Frame struct {
			ParentID string `json:"parentId"`
			URL      string `json:"url"`
		} `json:"frame"`
	}
	if json.Unmarshal(params, &ev) != nil || ev.Frame.ParentID != "" {
		return
	}
	// A top-level navigation replaces the document, so every ref from the
	// previous snapshot now points into a page that no longer exists.
	d.bumpGeneration()
	d.mu.Lock()
	d.url = ev.Frame.URL
	d.title = ""
	d.mu.Unlock()
}

// recover relaunches on the same profile and restores the URL, the viewport
// and the parked dialog. The page is restored without waiting for load; the
// caller takes a new snapshot anyway.
func (d *Driver) recover(ctx context.Context, failed conn) error {
	d.recoverMu.Lock()
	defer d.recoverMu.Unlock()

	d.mu.Lock()
	if d.closed || d.c != failed {
		d.mu.Unlock()
		return nil
	}
	d.mu.Unlock()

	closeConn(failed)

	nc, err := d.launch(ctx)
	if err != nil {
		return fmt.Errorf("browser: relaunch: %w", err)
	}
	nc.On(d.dispatch)
	if _, err := nc.Send(ctx, "Page.enable", nil); err != nil {
		closeConn(nc)
		return fmt.Errorf("browser: relaunch: %w", err)
	}
	if _, err := nc.Send(ctx, "DOM.enable", nil); err != nil {
		closeConn(nc)
		return fmt.Errorf("browser: relaunch: %w", err)
	}
	if err := d.enableCapabilities(ctx, nc); err != nil {
		closeConn(nc)
		return fmt.Errorf("browser: relaunch: %w", err)
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		closeConn(nc)
		return fmt.Errorf("browser: closed")
	}
	d.c = nc
	d.gen++
	d.refs = map[string]Ref{}
	viewport := d.viewport
	lastURL := d.url
	d.mu.Unlock()

	if viewport != nil {
		// A viewport is cosmetic; the page still works if it cannot be restored.
		_, _ = nc.Send(ctx, "Emulation.setDeviceMetricsOverride", viewport.params())
	}
	if lastURL != "" {
		if _, err := nc.Send(ctx, "Page.navigate", map[string]any{"url": lastURL}); err != nil {
			return fmt.Errorf("browser: relaunch: restore %s: %w", lastURL, err)
		}
	}
	return nil
}

// pipeConn is the real transport: CDP JSON on the browser's fd 3 and 4,
// NUL-terminated, with one flattened page session.
type pipeConn struct {
	out    io.WriteCloser
	in     io.ReadCloser
	cmd    *exec.Cmd
	stderr *tailBuffer

	writeMu  sync.Mutex
	mu       sync.Mutex
	nextID   int64
	pending  map[int64]chan cdpReply
	handlers []func(string, json.RawMessage)
	session  string
	closed   bool
	err      error
	done     chan struct{}

	closeOnce sync.Once
}

type cdpReply struct {
	result json.RawMessage
	err    error
}

// cdpError is a protocol-level error, distinct from a lost connection.
type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *cdpError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("%s (%d): %s", e.Message, e.Code, e.Data)
	}
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

func newPipeConn(out io.WriteCloser, in io.ReadCloser, stderr *tailBuffer) *pipeConn {
	p := &pipeConn{
		out:     out,
		in:      in,
		stderr:  stderr,
		pending: map[int64]chan cdpReply{},
		done:    make(chan struct{}),
	}
	go p.readLoop()
	return p
}

// Send speaks CDP on the attached page session.
func (p *pipeConn) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return p.send(ctx, method, params, p.sessionID())
}

// SendBrowser speaks CDP on the browser target, where Browser.* lives.
func (p *pipeConn) SendBrowser(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return p.send(ctx, method, params, "")
}

// browserSender is a conn that can address the browser target. The fake used
// by tests does not need it: sendBrowser falls back to the page session.
type browserSender interface {
	SendBrowser(ctx context.Context, method string, params any) (json.RawMessage, error)
}

func sendBrowser(ctx context.Context, c conn, method string, params any) (json.RawMessage, error) {
	if b, ok := c.(browserSender); ok {
		return b.SendBrowser(ctx, method, params)
	}
	return c.Send(ctx, method, params)
}

// On registers an event handler. Each event runs in its own goroutine so a
// handler may itself send a command (the dialog policy does).
func (p *pipeConn) On(fn func(method string, params json.RawMessage)) {
	p.mu.Lock()
	p.handlers = append(p.handlers, fn)
	p.mu.Unlock()
}

// Close drops the pipes and kills the process.
func (p *pipeConn) Close() error {
	p.fail(nil)
	p.out.Close()
	p.in.Close()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	return nil
}

func (p *pipeConn) sessionID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.session
}

func (p *pipeConn) setSession(id string) {
	p.mu.Lock()
	p.session = id
	p.mu.Unlock()
}

func (p *pipeConn) send(ctx context.Context, method string, params any, session string) (json.RawMessage, error) {
	select {
	case <-p.done:
		return nil, p.closedErr()
	default:
	}

	id := atomic.AddInt64(&p.nextID, 1)
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if session != "" {
		msg["sessionId"] = session
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("browser: encode %s: %w", method, err)
	}

	// Register before writing: a fast reply must find the channel.
	ch := make(chan cdpReply, 1)
	p.mu.Lock()
	p.pending[id] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
	}()

	p.writeMu.Lock()
	_, werr := p.out.Write(append(body, 0))
	p.writeMu.Unlock()
	if werr != nil {
		p.fail(werr)
		return nil, fmt.Errorf("browser: write %s: %w", method, errTransport)
	}

	select {
	case reply := <-ch:
		if reply.err != nil {
			return nil, fmt.Errorf("browser: %s: %w", method, reply.err)
		}
		return reply.result, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("browser: %s: %w", method, ctx.Err())
	case <-p.done:
		return nil, p.closedErr()
	}
}

func (p *pipeConn) readLoop() {
	r := bufio.NewReaderSize(p.in, 1<<16)
	for {
		line, err := r.ReadBytes(0)
		if err != nil {
			p.fail(err)
			return
		}
		line = line[:len(line)-1]
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var msg struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  *cdpError       `json:"error"`
		}
		if json.Unmarshal(line, &msg) != nil {
			continue
		}
		if msg.ID != 0 {
			p.mu.Lock()
			ch := p.pending[msg.ID]
			p.mu.Unlock()
			if ch != nil {
				reply := cdpReply{result: msg.Result}
				if msg.Error != nil {
					reply.err = msg.Error
				}
				ch <- reply
			}
			continue
		}
		if msg.Method == "" {
			continue
		}
		p.mu.Lock()
		handlers := append([]func(string, json.RawMessage){}, p.handlers...)
		p.mu.Unlock()
		for _, fn := range handlers {
			go fn(msg.Method, msg.Params)
		}
	}
}

func (p *pipeConn) fail(err error) {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.err = err
	}
	p.mu.Unlock()
	p.closeOnce.Do(func() { close(p.done) })
}

func (p *pipeConn) closedErr() error {
	p.mu.Lock()
	err := p.err
	stderr := ""
	if p.stderr != nil {
		stderr = p.stderr.String()
	}
	p.mu.Unlock()
	switch {
	case err != nil && stderr != "":
		return fmt.Errorf("browser: %w: %v (%s)", errTransport, err, stderr)
	case err != nil:
		return fmt.Errorf("browser: %w: %v", errTransport, err)
	default:
		return fmt.Errorf("browser: %w", errTransport)
	}
}

// startPipe launches Chromium and attaches to its first page target.
func startPipe(ctx context.Context, opts Options) (conn, error) {
	exe := opts.Executable
	if exe == "" {
		exe = "chromium"
	}
	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--remote-debugging-pipe",
		"--user-data-dir=" + opts.UserDataDir,
	}
	if opts.ProxyServer != "" {
		args = append(args, "--proxy-server="+opts.ProxyServer, "--ignore-certificate-errors")
	}

	toChildR, toChildW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("browser: launch: %w", err)
	}
	fromChildR, fromChildW, err := os.Pipe()
	if err != nil {
		toChildR.Close()
		toChildW.Close()
		return nil, fmt.Errorf("browser: launch: %w", err)
	}

	// The browser reads CDP on fd 3 and writes on fd 4; ExtraFiles maps the
	// two child ends to exactly those descriptors.
	cmd := exec.Command(exe, args...)
	cmd.ExtraFiles = []*os.File{toChildR, fromChildW}
	stderr := &tailBuffer{max: 4096}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		toChildR.Close()
		toChildW.Close()
		fromChildR.Close()
		fromChildW.Close()
		return nil, fmt.Errorf("browser: launch %s: %w", exe, err)
	}
	toChildR.Close()
	fromChildW.Close()

	p := newPipeConn(toChildW, fromChildR, stderr)
	p.cmd = cmd
	go func() { p.fail(cmd.Wait()) }()
	if err := p.attach(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// attach finds the initial page target and opens a flattened session on it.
// Browser-level commands go out without a session; everything after this
// carries the page session.
func (p *pipeConn) attach(ctx context.Context) error {
	raw, err := p.send(ctx, "Target.getTargets", nil, "")
	if err != nil {
		return fmt.Errorf("browser: launch: %w", err)
	}
	var targets struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(raw, &targets); err != nil {
		return fmt.Errorf("browser: launch: %w", err)
	}
	targetID := ""
	for _, target := range targets.TargetInfos {
		if target.Type == "page" {
			targetID = target.TargetID
			break
		}
	}
	if targetID == "" {
		raw, err = p.send(ctx, "Target.createTarget", map[string]any{"url": "about:blank"}, "")
		if err != nil {
			return fmt.Errorf("browser: launch: %w", err)
		}
		var created struct {
			TargetID string `json:"targetId"`
		}
		if err := json.Unmarshal(raw, &created); err != nil {
			return fmt.Errorf("browser: launch: %w", err)
		}
		targetID = created.TargetID
	}
	raw, err = p.send(ctx, "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true}, "")
	if err != nil {
		return fmt.Errorf("browser: launch: %w", err)
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(raw, &attached); err != nil {
		return fmt.Errorf("browser: launch: %w", err)
	}
	if attached.SessionID == "" {
		return fmt.Errorf("browser: launch: no page session")
	}
	p.setSession(attached.SessionID)
	return nil
}

// tailBuffer keeps the last max bytes of browser stderr, so a launch that dies
// says why instead of only "connection lost".
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.buf))
}

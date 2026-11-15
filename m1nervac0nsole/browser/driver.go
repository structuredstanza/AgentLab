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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
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
	// ProxyServer is the recording proxy address, without credentials. When
	// set, certificate errors are ignored because the proxy presents its own CA.
	ProxyServer string
	// ProxyUser and ProxyPass answer a proxy authentication challenge. Chromium
	// ignores credentials embedded in --proxy-server, so they are supplied over
	// CDP and never reach the command line.
	ProxyUser string
	ProxyPass string
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
	proxyUser    string
	proxyPass    string
	blocked      []string
	blockedSeen  map[string]bool
	popups       []string
	popupAt      map[string]int

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
	d.proxyUser = opts.ProxyUser
	d.proxyPass = opts.ProxyPass
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
// (re)launch: console capture always, interception and downloads when asked,
// and auto-attach, which is what puts interception on a target created later.
func (d *Driver) enableCapabilities(ctx context.Context, c conn) error {
	if _, err := c.Send(ctx, "Runtime.enable", nil); err != nil {
		return err
	}
	if err := d.enableFetch(ctx, c); err != nil {
		return err
	}
	if err := d.watchTargets(ctx, c); err != nil {
		return err
	}
	// A browser-level auto-attach does not hand over a page's out-of-process
	// frames, so the page the driver drives arms it on its own session too.
	if ps, ok := c.(pageSessioner); ok {
		if err := d.watchTargets(ctx, targetConn{conn: c, session: ps.PageSession()}); err != nil {
			return err
		}
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

// sendIn speaks CDP on one target session; the empty session is the driver's
// own page. A session dies with its target, so there is nothing to recover.
func (d *Driver) sendIn(ctx context.Context, session, method string, params any) (json.RawMessage, error) {
	if session == "" {
		return d.Send(ctx, method, params)
	}
	d.mu.Lock()
	c := d.c
	d.mu.Unlock()
	if sc, ok := c.(sessionSender); ok {
		return sc.SendSession(ctx, session, method, params)
	}
	return d.Send(ctx, method, params)
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
		d.requestPaused("", params)
	case "Fetch.authRequired":
		d.authRequired("", params)
	case "Target.attachedToTarget":
		d.targetAttached(params)
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

// watchTargets arms auto-attach, so a target created after the session starts
// is handed to the driver before it runs. waitForDebuggerOnStart is what makes
// "before" true: the target stays paused until the driver has installed its
// interception and released it.
func (d *Driver) watchTargets(ctx context.Context, c conn) error {
	_, err := sendBrowser(ctx, c, "Target.setAutoAttach", map[string]any{
		"autoAttach":             true,
		"waitForDebuggerOnStart": true,
		"flatten":                true,
	})
	return err
}

// attachedTarget is one target the browser auto-attached: a popup, a frame, a
// worker, or anything else a page created after the session started.
type attachedTarget struct {
	SessionID string
	TargetID  string
	Type      string
	URL       string
}

func parseAttachedTarget(params json.RawMessage) (attachedTarget, bool) {
	var ev struct {
		SessionID  string `json:"sessionId"`
		TargetInfo struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			URL      string `json:"url"`
		} `json:"targetInfo"`
	}
	if json.Unmarshal(params, &ev) != nil || ev.SessionID == "" {
		return attachedTarget{}, false
	}
	return attachedTarget{
		SessionID: ev.SessionID,
		TargetID:  ev.TargetInfo.TargetID,
		Type:      ev.TargetInfo.Type,
		URL:       ev.TargetInfo.URL,
	}, true
}

// targetAttached handles a target the browser attached after the session
// started: a popup, a frame, a worker, or anything else a page creates. The
// target is paused until this returns, so the interception is in place before
// its first request leaves the browser.
func (d *Driver) targetAttached(params json.RawMessage) {
	target, ok := parseAttachedTarget(params)
	if !ok {
		return
	}
	d.mu.Lock()
	c := d.c
	allow := d.allowRequest
	d.mu.Unlock()
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchReplyTimeout)
	defer cancel()

	switch target.Type {
	case "page":
		d.attachPopup(ctx, c, allow, target)
	case "iframe", "worker", "shared_worker", "service_worker":
		// A frame or a worker makes requests of its own, so it gets the page's
		// interception before it runs. It is not a popup: nothing reports it.
		if d.setupTarget(ctx, c, target) {
			_, _ = d.sendIn(ctx, target.SessionID, "Runtime.runIfWaitingForDebugger", nil)
		}
	default:
		// A target this package cannot drive is released at once: a paused
		// target would leave the page that created it waiting on a debugger
		// nobody releases.
		_, _ = d.sendIn(ctx, target.SessionID, "Runtime.runIfWaitingForDebugger", nil)
	}
}

// attachPopup arms a page target created after launch. A paused popup usually
// reports no destination yet, so this only refuses a target whose destination
// the browser already knows; the interception judges the request the popup
// actually makes.
func (d *Driver) attachPopup(ctx context.Context, c conn, allow func(string) error, target attachedTarget) {
	if allow != nil && target.URL != "" {
		if err := allow(target.URL); err != nil {
			// The popup is paused before it runs, so closing it is the refusal:
			// it never reaches the network, and the host is reported.
			d.recordBlocked(target.URL)
			_, _ = sendBrowser(ctx, c, "Target.closeTarget", map[string]any{"targetId": target.TargetID})
			return
		}
	}
	if !d.setupTarget(ctx, c, target) {
		return
	}
	// The entry exists before the popup runs: its first request is judged in
	// requestPaused, which names the popup from that entry.
	d.recordPopup(target.SessionID, target.URL)
	_, _ = d.sendIn(ctx, target.SessionID, "Runtime.runIfWaitingForDebugger", nil)
}

// setupTarget installs nested auto-attach and interception on one attached
// session before it runs, and reports whether the target may be resumed. A
// target that cannot be intercepted is closed rather than released: it would be
// a hole the page's own interception cannot see.
func (d *Driver) setupTarget(ctx context.Context, c conn, target attachedTarget) bool {
	session := targetConn{conn: c, session: target.SessionID}
	// Nested auto-attach is what puts interception on a target this one
	// creates: an out-of-process frame, or a worker's own worker. A type
	// Chromium will not auto-attach from keeps the interception below, which is
	// the part that judges requests.
	if err := d.watchTargets(ctx, session); err != nil && !methodUnsupported(err) {
		d.refuseTarget(ctx, c, target)
		return false
	}
	// The session's handlers exist before interception can raise an event on
	// it, so no paused request is left unanswered.
	d.watchSession(c, target.SessionID)
	// A driver with neither a scope nor a credential installs nothing: it
	// attaches and releases the target rather than inventing a scope.
	if err := d.enableFetch(ctx, session); err != nil {
		if methodUnsupported(err) {
			// Chromium has no interception for this target type. Releasing it is
			// the documented browser limit: the gateway still refuses a request
			// that carries no session credential, and the real-Chromium test is
			// what proves the excluded origin sees no contact.
			return true
		}
		d.refuseTarget(ctx, c, target)
		return false
	}
	return true
}

// refuseTarget stops a paused target that could not be intercepted. Closing is
// the refusal; a type the browser cannot close is detached instead, so it never
// stays paused. The host is reported, so the refusal is visible in the tool
// result rather than silent.
func (d *Driver) refuseTarget(ctx context.Context, c conn, target attachedTarget) {
	if target.URL != "" {
		d.recordBlocked(target.URL)
	}
	if _, err := sendBrowser(ctx, c, "Target.closeTarget", map[string]any{"targetId": target.TargetID}); err == nil {
		return
	}
	_, _ = sendBrowser(ctx, c, "Target.detachFromTarget", map[string]any{"sessionId": target.SessionID})
}

// methodUnsupported reports whether Chromium refused a command because the
// target type does not implement it. That is a browser limit, not a failure to
// set the target up.
func methodUnsupported(err error) bool {
	var cdp *cdpError
	if !errors.As(err, &cdp) {
		return false
	}
	if cdp.Code == -32601 {
		return true
	}
	msg := strings.ToLower(cdp.Message + " " + cdp.Data)
	return strings.Contains(msg, "not supported") || strings.Contains(msg, "not implemented")
}

// recordPopup notes a page target the driver attached. A paused popup reports
// no destination, so the entry is named from the popup's first document
// request.
func (d *Driver) recordPopup(session, rawURL string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.popupAt == nil {
		d.popupAt = map[string]int{}
	}
	d.popupAt[session] = len(d.popups)
	d.popups = append(d.popups, rawURL)
}

// popupPlaceholder reports whether a popup entry still holds what the browser
// reported before it knew where the popup was going.
func popupPlaceholder(rawURL string) bool {
	switch strings.TrimSpace(rawURL) {
	case "", "about:blank":
		return true
	}
	return false
}

// namePopup fills in where a popup is actually going, which the browser does
// not say when it hands the popup over. Only the popup's own document request
// names it: a subresource it loads is not its destination.
func (d *Driver) namePopup(session, rawURL string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if i, ok := d.popupAt[session]; ok && popupPlaceholder(d.popups[i]) {
		d.popups[i] = rawURL
	}
}

// watchSession answers one target session's interception events on that
// session: a request paused in a popup can only be continued from the session
// that paused it.
func (d *Driver) watchSession(c conn, session string) {
	sc, ok := c.(sessionSender)
	if !ok {
		return
	}
	sc.OnSession(session, func(method string, params json.RawMessage) {
		switch method {
		case "Fetch.requestPaused":
			d.requestPaused(session, params)
		case "Fetch.authRequired":
			d.authRequired(session, params)
		case "Target.attachedToTarget":
			// A session with handlers of its own does not also reach the page
			// handlers, so a popup's own popup, or a worker's nested worker, is
			// only seen here. Left unhandled it would stay paused forever.
			d.targetAttached(params)
		}
	})
}

// Popups returns the page targets attached since the previous call and clears
// the list, so one tool result reports each popup once. A popup is named by the
// document it asked for, so one that never navigated keeps the placeholder the
// browser reported ("about:blank" or empty). A popup the scope refused is
// reported by BlockedRequests instead: it never ran.
func (d *Driver) Popups() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.popups
	d.popups = nil
	d.popupAt = nil
	return out
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
// NUL-terminated, with flattened sessions: one for the page the driver drives
// and one for every target auto-attach hands it.
type pipeConn struct {
	out    io.WriteCloser
	in     io.ReadCloser
	cmd    browserProc
	stderr *tailBuffer

	writeMu         sync.Mutex
	mu              sync.Mutex
	nextID          int64
	pending         map[int64]chan cdpReply
	handlers        []func(string, json.RawMessage)
	sessionHandlers map[string][]func(string, json.RawMessage)
	session         string
	pageTarget      string
	closed          bool
	err             error
	done            chan struct{}

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

// sessionSender is a conn that can address one target session and route that
// session's events. A popup's interception is useless unless its events are
// answered on the session that raised them. The fake does not need it: it has
// one session.
type sessionSender interface {
	SendSession(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error)
	OnSession(sessionID string, fn func(method string, params json.RawMessage))
}

// pageSessioner is a conn that names the session of the page it drives, so that
// page can arm auto-attach for its own out-of-process frames.
type pageSessioner interface {
	PageSession() string
}

// targetConn is one attached target session seen as a conn, so the interception
// installed on the page is installed on a popup by the same code.
type targetConn struct {
	conn
	session string
}

func (t targetConn) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if sc, ok := t.conn.(sessionSender); ok {
		return sc.SendSession(ctx, t.session, method, params)
	}
	return t.conn.Send(ctx, method, params)
}

// On registers an event handler. Each event runs in its own goroutine so a
// handler may itself send a command (the dialog policy does).
func (p *pipeConn) On(fn func(method string, params json.RawMessage)) {
	p.mu.Lock()
	p.handlers = append(p.handlers, fn)
	p.mu.Unlock()
}

// SendSession speaks CDP on one attached target session.
func (p *pipeConn) SendSession(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	return p.send(ctx, method, params, sessionID)
}

// OnSession registers a handler for one target session's events.
func (p *pipeConn) OnSession(sessionID string, fn func(method string, params json.RawMessage)) {
	p.mu.Lock()
	if p.sessionHandlers == nil {
		p.sessionHandlers = map[string][]func(string, json.RawMessage){}
	}
	p.sessionHandlers[sessionID] = append(p.sessionHandlers[sessionID], fn)
	p.mu.Unlock()
}

// Close drops the pipes and kills the process.
func (p *pipeConn) Close() error {
	p.fail(nil)
	p.out.Close()
	p.in.Close()
	if p.cmd != nil {
		_ = p.cmd.Kill()
	}
	return nil
}

func (p *pipeConn) sessionID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.session
}

// PageSession names the session of the page the driver drives.
func (p *pipeConn) PageSession() string { return p.sessionID() }

func (p *pipeConn) setAttached(targetID, sessionID string) {
	p.mu.Lock()
	p.pageTarget = targetID
	p.session = sessionID
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
			ID        int64           `json:"id"`
			Method    string          `json:"method"`
			Params    json.RawMessage `json:"params"`
			Result    json.RawMessage `json:"result"`
			Error     *cdpError       `json:"error"`
			SessionID string          `json:"sessionId"`
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
		if scoped := p.sessionHandlers[msg.SessionID]; len(scoped) > 0 {
			// A session with handlers of its own does not also reach the page
			// handlers: a popup's navigation must not move the page the driver
			// drives.
			handlers = append([]func(string, json.RawMessage){}, scoped...)
		}
		pageTarget := p.pageTarget
		p.mu.Unlock()
		if msg.Method == "Target.attachedToTarget" && pageTarget != "" && attachedTargetID(msg.Params) == pageTarget {
			// The page the driver attached at launch is not a new target.
			continue
		}
		for _, fn := range handlers {
			go fn(msg.Method, msg.Params)
		}
	}
}

// attachedTargetID is the target an attachedToTarget event names.
func attachedTargetID(params json.RawMessage) string {
	var ev struct {
		TargetInfo struct {
			TargetID string `json:"targetId"`
		} `json:"targetInfo"`
	}
	if json.Unmarshal(params, &ev) != nil {
		return ""
	}
	return ev.TargetInfo.TargetID
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

// launchArgs is the Chromium command line. The proxy address goes out bare:
// Chromium ignores credentials embedded in --proxy-server, so the driver answers
// the proxy's authentication challenge over CDP instead.
func launchArgs(opts Options) []string {
	exe := opts.Executable
	if exe == "" {
		exe = "chromium"
	}
	args := []string{
		exe,
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--remote-debugging-pipe",
		"--user-data-dir=" + opts.UserDataDir,
	}
	if opts.ProxyServer != "" {
		args = append(args, "--proxy-server="+opts.ProxyServer, "--ignore-certificate-errors")
	}
	return args
}

// startPipe launches Chromium and attaches to its first page target.
func startPipe(ctx context.Context, opts Options) (conn, error) {
	argv := launchArgs(opts)
	exe := argv[0]

	// The browser is a tool process: it runs inside the task's session, so its
	// traffic is subject to the same packet boundary as every other tool. A
	// host without an installed client gets the capability error instead of a
	// browser outside the boundary.
	client, ok := execbox.Installed()
	if !ok {
		return nil, fmt.Errorf("browser: launch: %w", execbox.ErrUnavailable)
	}
	sess, err := execbox.RequireSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("browser: launch: %w", err)
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

	// The browser reads CDP on fd 3 and writes on fd 4; the session supervisor
	// maps the two child ends to exactly those descriptors.
	stderr := &tailBuffer{max: 4096}
	writable := []string{}
	if opts.DownloadDir != "" {
		writable = append(writable, opts.DownloadDir)
	}
	rwc, err := execbox.RunFiles(client, ctx, sess, execbox.Spec{
		Argv:        argv,
		Dir:         opts.UserDataDir,
		Writable:    writable,
		ExtraFiles:  2,
		MergeStderr: false,
	}, []*os.File{toChildR, fromChildW})
	if err != nil {
		toChildR.Close()
		toChildW.Close()
		fromChildR.Close()
		fromChildW.Close()
		return nil, fmt.Errorf("browser: launch %s: %w", exe, err)
	}
	toChildR.Close()
	fromChildW.Close()

	proc, ok := execbox.ProcessOf(rwc)
	if !ok {
		toChildW.Close()
		fromChildR.Close()
		return nil, fmt.Errorf("browser: launch: session has no process control")
	}
	if st := proc.Stderr(); st != nil {
		go func() { _, _ = io.Copy(stderr, st) }()
	}
	// CDP rides fd 3 and 4, so stdout only carries log noise. It still has to be
	// drained: the client writes every frame to its stream, and an unread one
	// stalls the CDP pipe with it.
	go func() { _, _ = io.Copy(io.Discard, rwc) }()
	p := newPipeConn(toChildW, fromChildR, stderr)
	p.cmd = sessionProc{p: proc}
	go func() { p.fail(p.cmd.Wait()) }()
	if err := p.attach(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// browserProc is the process control the driver needs. The session adapter
// keeps the driver independent of the supervisor's types.
type browserProc interface {
	Wait() error
	Kill() error
}

type sessionProc struct{ p execbox.Process }

func (s sessionProc) Wait() error { _, err := s.p.Wait(); return err }
func (s sessionProc) Kill() error { return s.p.Kill() }

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
	p.setAttached(targetID, attached.SessionID)
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

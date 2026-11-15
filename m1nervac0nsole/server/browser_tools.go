package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
	actool "github.com/structuredstanza/norma/tool"
)

// browserToolKeys is the native browser surface: the only testing browser. Scope
// is enforced on navigation and every request goes through the recording proxy.
// Research - public documentation, repositories, advisories - is Obscura's job.
var browserToolKeys = []string{
	"browser_open", "browser_navigate", "browser_snapshot", "browser_click",
	"browser_type", "browser_press", "browser_select", "browser_wait",
	"browser_screenshot", "browser_upload", "browser_log", "browser_close",
}

// browserToolAgents are the agents that drive a browser: the executor roles, not
// the planner, the reporter or the chat agents.
var browserToolAgents = []string{"auto", "pentest", "worker"}

// browserTools returns the native browser tools. They are host tools, so the
// binding rows keep them off every agent that is not in browserToolAgents.
func (s *Server) browserTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.browserOpenTool(),
		s.browserNavigateTool(),
		s.browserSnapshotTool(),
		s.browserClickTool(),
		s.browserTypeTool(),
		s.browserPressTool(),
		s.browserSelectTool(),
		s.browserWaitTool(),
		s.browserScreenshotTool(),
		s.browserUploadTool(),
		s.browserLogTool(),
		s.browserCloseTool(),
	}
}

// seedBrowserTools binds the native tools to the executor agents.
func (s *Server) seedBrowserTools() {
	bindings, _ := json.Marshal(browserToolAgents)
	for _, t := range s.browserTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			log.Printf("[browser] failed to seed %s: %v", t.Name(), err)
		}
	}
}

// pageLine is the one-line page state every mutating tool returns, so the model
// knows it must snapshot again instead of assuming the page did not move.
func pageLine(url, title string) string {
	// The scope guard reads "- Page URL:" out of a tool result to judge where the
	// page landed, so the native tools speak the same format as the MCP one.
	return fmt.Sprintf("- Page URL: %s\n- Page Title: %s\nsnapshot again before the next action", url, title)
}

// operatorHolds is the refusal while an operator drives the live view. The
// agent's click would race theirs, so the call stops before it reaches CDP.
const operatorHolds = "the operator has the page: they are driving it from the live view; wait or ask them to release it"

// browserToolDriver is the driver surface the tools use. It is an interface so
// the tool layer can be exercised without Chromium.
type browserToolDriver interface {
	Navigate(ctx context.Context, url string) (browser.PageState, error)
	Snapshot(ctx context.Context) (*browser.Snapshot, error)
	SnapshotSubtree(ctx context.Context, ref string, maxLines int) (browser.Snapshot, error)
	Click(ctx context.Context, ref string) (browser.PageState, error)
	Type(ctx context.Context, ref, text string) (browser.PageState, error)
	Press(ctx context.Context, key string) (browser.PageState, error)
	Select(ctx context.Context, ref string, values ...string) (browser.PageState, error)
	Wait(ctx context.Context, text string, timeout time.Duration) error
	Screenshot(ctx context.Context, fullPage bool) ([]byte, error)
	Upload(ctx context.Context, ref string, paths []string) (browser.PageState, error)
	URL() string
	Title() string
	BlockedRequests() []string
	Popups() []string
	Downloads() []string
	Console(since int64, limit int) []browser.ConsoleEntry
	ConsoleSeq() int64
}

// browserToolFor returns the task's browser for a tool call, launching it when
// there is none. It is a package variable so tests can substitute a driver;
// production reads the registry.
var browserToolFor = func(s *Server, ctx context.Context, taskID string) (browserToolDriver, error) {
	return s.browserFor(ctx, taskID)
}

// browserToolExisting returns the task's running browser without launching one:
// polling the log must not start Chromium.
var browserToolExisting = func(s *Server, taskID string) browserToolDriver {
	s.browsers.mu.Lock()
	defer s.browsers.mu.Unlock()
	sess := s.browsers.byID[taskID]
	if sess == nil {
		return nil
	}
	sess.lastUsed = time.Now()
	return sess.drv
}

// browserText is the result every tool that touched the driver returns: the
// tool's own text plus what the driver collected since the previous call. Every
// list drains on read, so a blocked host, an attached popup or a finished
// download is reported exactly once, by whichever tool call notices it.
func browserText(d browserToolDriver, text string) actool.Result {
	if d == nil {
		return actool.Text(text)
	}
	if hosts := d.BlockedRequests(); len(hosts) > 0 {
		text += fmt.Sprintf("\nblocked %d out-of-scope requests: %s", len(hosts), strings.Join(hosts, ", "))
	}
	for _, popup := range d.Popups() {
		if popup == "" {
			popup = "(destination not reported by the browser)"
		}
		text += "\npopup opened: " + popup
	}
	for _, path := range d.Downloads() {
		text += "\ndownloaded: " + path
	}
	return actool.Text(text)
}

func (s *Server) browserOpenTool() actool.CoreTool {
	return wrTool("browser_open",
		"Open an http(s) URL in this task's browser and return the page as an accessibility snapshot. The URL must be inside the task's scope. Use this first; use browser_snapshot to re-read the page after an action.",
		objSchema(map[string]any{"url": strParam("absolute http(s) URL to open")}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			if liveHolder(taskID) != "" {
				return actool.Errorf("Error: " + operatorHolds), nil
			}
			drv, err := browserToolFor(s, ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			state, err := drv.Navigate(ctx, a.URL)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			snap, err := drv.Snapshot(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return browserText(drv, pageLine(state.URL, state.Title)+"\n\n"+snap.Tree), nil
		})
}

func (s *Server) browserNavigateTool() actool.CoreTool {
	return wrTool("browser_navigate",
		"Navigate the current page to another http(s) URL inside the task's scope. Returns the page as an accessibility snapshot; refs from before the navigation are stale.",
		objSchema(map[string]any{"url": strParam("absolute http(s) URL")}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			if liveHolder(taskID) != "" {
				return actool.Errorf("Error: " + operatorHolds), nil
			}
			drv, err := browserToolFor(s, ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			state, err := drv.Navigate(ctx, a.URL)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			snap, err := drv.Snapshot(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return browserText(drv, pageLine(state.URL, state.Title)+"\n\n"+snap.Tree), nil
		})
}

func (s *Server) browserSnapshotTool() actool.CoreTool {
	return roTool("browser_snapshot",
		"Read the current page as an accessibility tree: one line per element, `- role \"name\" [ref=gNeM]`, with value, checked and disabled when present. Pass ref to read only that element's subtree, and max_lines to bound it (default 2000, cap 4000). Refs are only valid until the next top-level navigation; a stale ref fails with \"stale reference, take a new snapshot\".",
		objSchema(map[string]any{
			"ref":       strParam("ref from the last snapshot; only its subtree is returned"),
			"max_lines": map[string]any{"type": "integer", "description": "line budget for a ref snapshot (default 2000, cap 4000)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Ref      string `json:"ref"`
				MaxLines int    `json:"max_lines"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := browserToolFor(s, ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			var tree string
			if a.Ref != "" {
				sub, err := drv.SnapshotSubtree(ctx, a.Ref, a.MaxLines)
				if err != nil {
					return actool.Errorf("Error: " + err.Error()), nil
				}
				tree = sub.Tree
			} else {
				snap, err := drv.Snapshot(ctx)
				if err != nil {
					return actool.Errorf("Error: " + err.Error()), nil
				}
				tree = snap.Tree
			}
			return browserText(drv, pageLine(drv.URL(), drv.Title())+"\n\n"+tree), nil
		})
}

// browserRefAction is the shape every ref-driven tool shares.
func (s *Server) browserRefAction(ctx context.Context, act func(context.Context, browserToolDriver) (browser.PageState, error)) (actool.Result, error) {
	taskID, err := s.browserTaskID(ctx)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	if liveHolder(taskID) != "" {
		return actool.Errorf("Error: " + operatorHolds), nil
	}
	drv, err := browserToolFor(s, ctx, taskID)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	state, err := act(ctx, drv)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	return browserText(drv, pageLine(state.URL, state.Title)), nil
}

func (s *Server) browserClickTool() actool.CoreTool {
	return wrTool("browser_click",
		"Click the element a snapshot ref names. Returns the URL and title afterwards; take a new snapshot.",
		objSchema(map[string]any{"ref": strParam("ref from the last snapshot, e.g. g1e17")}, "ref"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Ref string `json:"ref"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			return s.browserRefAction(ctx, func(ctx context.Context, d browserToolDriver) (browser.PageState, error) {
				return d.Click(ctx, a.Ref)
			})
		})
}

func (s *Server) browserTypeTool() actool.CoreTool {
	return wrTool("browser_type",
		"Focus the element a ref names, type text into it, and optionally submit with Enter. Returns the URL and title; take a new snapshot.",
		objSchema(map[string]any{
			"ref":    strParam("ref from the last snapshot"),
			"text":   strParam("text to type"),
			"submit": map[string]any{"type": "boolean", "description": "press Enter after typing (default false)"},
		}, "ref", "text"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Ref    string `json:"ref"`
				Text   string `json:"text"`
				Submit bool   `json:"submit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			return s.browserRefAction(ctx, func(ctx context.Context, d browserToolDriver) (browser.PageState, error) {
				state, err := d.Type(ctx, a.Ref, a.Text)
				if err != nil || !a.Submit {
					return state, err
				}
				return d.Press(ctx, "Enter")
			})
		})
}

func (s *Server) browserPressTool() actool.CoreTool {
	return wrTool("browser_press",
		"Press one key on the focused element (Enter, Tab, Escape, ArrowDown, ...). Returns the URL and title.",
		objSchema(map[string]any{"key": strParam("key name, e.g. Enter or Tab")}, "key"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			return s.browserRefAction(ctx, func(ctx context.Context, d browserToolDriver) (browser.PageState, error) {
				return d.Press(ctx, a.Key)
			})
		})
}

func (s *Server) browserSelectTool() actool.CoreTool {
	return wrTool("browser_select",
		"Choose one or more options in a <select> the ref names. Returns the URL and title.",
		objSchema(map[string]any{
			"ref":    strParam("ref of the select element"),
			"values": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "option values to select"},
		}, "ref", "values"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Ref    string   `json:"ref"`
				Values []string `json:"values"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			return s.browserRefAction(ctx, func(ctx context.Context, d browserToolDriver) (browser.PageState, error) {
				return d.Select(ctx, a.Ref, a.Values...)
			})
		})
}

func (s *Server) browserWaitTool() actool.CoreTool {
	return roTool("browser_wait",
		"Wait until the page's accessibility text contains a string, or until the timeout. Use it after an action that loads something.",
		objSchema(map[string]any{
			"text":       strParam("text to wait for in the page"),
			"timeout_ms": map[string]any{"type": "integer", "description": "maximum wait in milliseconds (default 10000, cap 60000)"},
		}, "text"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Text      string `json:"text"`
				TimeoutMS int    `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			timeout := time.Duration(a.TimeoutMS) * time.Millisecond
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			if timeout > time.Minute {
				timeout = time.Minute
			}
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := browserToolFor(s, ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			if err := drv.Wait(ctx, a.Text, timeout); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return browserText(drv, fmt.Sprintf("found %q after waiting", a.Text)), nil
		})
}

func (s *Server) browserScreenshotTool() actool.CoreTool {
	return roTool("browser_screenshot",
		"Save a PNG of the current page into the task workspace and return its path. Use it as evidence for a finding, or hand it to the operator with ask_operator.",
		objSchema(map[string]any{
			"full_page": map[string]any{"type": "boolean", "description": "capture the whole scrollable page (default false)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FullPage bool `json:"full_page"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := browserToolFor(s, ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			png, err := drv.Screenshot(ctx, a.FullPage)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			dir := filepath.Join(s.m.dir, "tasks", taskID, "screenshots")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			name := fmt.Sprintf("%s.png", time.Now().Format("20060102-150405.000"))
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, png, 0o644); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			rel := filepath.Join("tasks", taskID, "screenshots", name)
			return browserText(drv, fmt.Sprintf("screenshot saved: %s (%d bytes)", rel, len(png))), nil
		})
}

func (s *Server) browserUploadTool() actool.CoreTool {
	return wrTool("browser_upload",
		"Set a file input the ref names to one or more files from the task workspace. Returns the URL and title.",
		objSchema(map[string]any{
			"ref":   strParam("ref of the file input"),
			"paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "workspace-relative paths, e.g. uploads/wordlist.txt"},
		}, "ref", "paths"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Ref   string   `json:"ref"`
				Paths []string `json:"paths"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			abs, err := s.browserUploadPaths(taskID, a.Paths)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := browserToolFor(s, ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			state, err := drv.Upload(ctx, a.Ref, abs)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return browserText(drv, pageLine(state.URL, state.Title)), nil
		})
}

// errBrowserUploadPath is the refusal for a path that leaves the task workspace.
// It names the accepted shape so the model retries instead of giving up.
const errBrowserUploadPath = "is outside the task workspace; pass a path relative to it, e.g. uploads/wordlist.txt"

// browserUploadPaths resolves upload paths inside the current task's workspace.
// The old check joined the shared work dir instead, so an absolute path was
// silently re-rooted there and a symlink planted in the workspace was followed to
// another task's file. CDP takes absolute paths, so each one is resolved and then
// proved contained with a rooted open: os.Root refuses a symlink that leaves the
// root, which no lexical check can.
// shortcut: Chromium re-opens the path it is handed, so a symlink swapped in after
// this check is only caught by the next upload; upgrade if CDP gains fd input.
func (s *Server) browserUploadPaths(taskID string, paths []string) ([]string, error) {
	dir := filepath.Join(s.m.dir, "tasks", taskID)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("the task workspace is not available: %w", err)
	}
	defer root.Close()
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("the task workspace is not available: %w", err)
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		name := strings.TrimSpace(p)
		if name == "" || filepath.IsAbs(name) {
			return nil, fmt.Errorf("%q %s", p, errBrowserUploadPath)
		}
		clean := filepath.Clean(name)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%q %s", p, errBrowserUploadPath)
		}
		target, err := filepath.EvalSymlinks(filepath.Join(dir, clean))
		if err != nil {
			return nil, fmt.Errorf("%q is not a file in the task workspace: %w", p, err)
		}
		rel, err := filepath.Rel(realDir, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%q %s", p, errBrowserUploadPath)
		}
		f, err := root.Open(rel)
		if err != nil {
			return nil, fmt.Errorf("%q %s", p, errBrowserUploadPath)
		}
		fi, statErr := f.Stat()
		f.Close()
		if statErr != nil || fi.IsDir() {
			return nil, fmt.Errorf("%q is not a file in the task workspace", p)
		}
		out = append(out, target)
	}
	return out, nil
}

// consoleLine is one browser_log entry with the short keys a model reads.
type consoleLine struct {
	Seq   int64  `json:"seq"`
	Level string `json:"level"`
	Text  string `json:"text"`
	URL   string `json:"url"`
	Line  int    `json:"line"`
}

func consoleLines(entries []browser.ConsoleEntry) []consoleLine {
	out := make([]consoleLine, len(entries))
	for i, e := range entries {
		out[i] = consoleLine{e.Seq, e.Level, e.Text, e.URL, e.Line}
	}
	return out
}

func (s *Server) browserLogTool() actool.CoreTool {
	return roTool("browser_log",
		"Read console messages and uncaught JS errors since a cursor. Pass next from the previous result as since; next is the cursor for the following call. A page that renders empty usually says why here.",
		objSchema(map[string]any{
			"since": map[string]any{"type": "integer", "description": "cursor from the previous result's next (default 0)"},
			"limit": map[string]any{"type": "integer", "description": "maximum entries (default 50, cap 200)"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Since int64 `json:"since"`
				Limit int   `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv := browserToolExisting(s, taskID)
			if drv == nil {
				return actool.Text(`{"entries":[],"next":0}`), nil
			}
			out, err := json.Marshal(struct {
				Entries []consoleLine `json:"entries"`
				Next    int64         `json:"next"`
			}{consoleLines(drv.Console(a.Since, a.Limit)), drv.ConsoleSeq()})
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return browserText(drv, string(out)), nil
		})
}

func (s *Server) browserCloseTool() actool.CoreTool {
	return wrTool("browser_close",
		"Close this task's browser. Cookies stay in the task's profile, so a later browser_open is still signed in; the next browser tool starts a fresh tab. Idempotent.",
		objSchema(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			taskID, err := s.browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			s.browsers.mu.Lock()
			open := s.browsers.byID[taskID] != nil
			s.browsers.mu.Unlock()
			if !open {
				return actool.Text("no session"), nil
			}
			s.closeBrowser(taskID)
			return actool.Text("closed"), nil
		})
}

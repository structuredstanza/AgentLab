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

// browserToolKeys is the native browser surface. It replaces the Playwright MCP
// when the operator flips browser_driver to native: the same snapshot/ref
// contract, but scope is enforced on navigation and every request goes through
// the recording proxy.
var browserToolKeys = []string{
	"browser_open", "browser_navigate", "browser_snapshot", "browser_click",
	"browser_type", "browser_press", "browser_select", "browser_wait",
	"browser_screenshot", "browser_upload",
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
			taskID, _ := browserTaskID(ctx)
			drv, err := s.browserFor(ctx, taskID)
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
			return actool.Text(pageLine(state.URL, state.Title) + "\n\n" + snap.Tree), nil
		})
}

func (s *Server) browserNavigateTool() actool.CoreTool {
	return wrTool("browser_navigate",
		"Navigate the current page to another http(s) URL inside the task's scope. Returns the new URL and title; take a snapshot before acting.",
		objSchema(map[string]any{"url": strParam("absolute http(s) URL")}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			taskID, _ := browserTaskID(ctx)
			drv, err := s.browserFor(ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			state, err := drv.Navigate(ctx, a.URL)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return actool.Text(pageLine(state.URL, state.Title)), nil
		})
}

func (s *Server) browserSnapshotTool() actool.CoreTool {
	return roTool("browser_snapshot",
		"Read the current page as an accessibility tree: one line per element, `- role \"name\" [ref=gNeM]`, with value, checked and disabled when present. Refs are only valid until the next top-level navigation; a stale ref fails with \"stale reference, take a new snapshot\".",
		objSchema(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			taskID, err := browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := s.browserFor(ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			snap, err := drv.Snapshot(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return actool.Text(pageLine(drv.URL(), drv.Title()) + "\n\n" + snap.Tree), nil
		})
}

// browserRefAction is the shape every ref-driven tool shares.
func (s *Server) browserRefAction(ctx context.Context, act func(context.Context, *browser.Driver) (browser.PageState, error)) (actool.Result, error) {
	taskID, err := browserTaskID(ctx)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	drv, err := s.browserFor(ctx, taskID)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	state, err := act(ctx, drv)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	return actool.Text(pageLine(state.URL, state.Title)), nil
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
			return s.browserRefAction(ctx, func(ctx context.Context, d *browser.Driver) (browser.PageState, error) {
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
			return s.browserRefAction(ctx, func(ctx context.Context, d *browser.Driver) (browser.PageState, error) {
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
			return s.browserRefAction(ctx, func(ctx context.Context, d *browser.Driver) (browser.PageState, error) {
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
			return s.browserRefAction(ctx, func(ctx context.Context, d *browser.Driver) (browser.PageState, error) {
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
			taskID, err := browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := s.browserFor(ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			if err := drv.Wait(ctx, a.Text, timeout); err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("found %q after waiting", a.Text)), nil
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
			taskID, err := browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			drv, err := s.browserFor(ctx, taskID)
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
			return actool.Text(fmt.Sprintf("screenshot saved: %s (%d bytes)", rel, len(png))), nil
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
			taskID, err := browserTaskID(ctx)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			abs := make([]string, 0, len(a.Paths))
			for _, p := range a.Paths {
				clean := filepath.Clean(strings.TrimPrefix(p, "/"))
				if strings.HasPrefix(clean, "..") {
					return actool.Errorf(fmt.Sprintf("Error: %q is outside the workspace", p)), nil
				}
				abs = append(abs, filepath.Join(s.m.dir, clean))
			}
			drv, err := s.browserFor(ctx, taskID)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			state, err := drv.Upload(ctx, a.Ref, abs)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			return actool.Text(pageLine(state.URL, state.Title)), nil
		})
}

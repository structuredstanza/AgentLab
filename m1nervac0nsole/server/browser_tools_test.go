package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

// The native tools are host tools, so only the binding rows keep them off the
// planner, the reporter and the chat agents.
func TestNativeBrowserToolsAreBoundToExecutors(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_PG_DSN") == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	m, s, _ := memoryTestServer(t)
	s.seedBrowserTools()

	for _, key := range browserToolKeys {
		row, err := m.pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("%s was not seeded: %v", key, err)
		}
		agents := row.Agents
		if len(agents) != len(browserToolAgents) {
			t.Fatalf("%s bound to %v, want %v", key, agents, browserToolAgents)
		}
		for _, a := range agents {
			if a == "planner" || a == "mainagent" || a == "curator" || a == "drafter" {
				t.Fatalf("%s reached %s", key, a)
			}
		}
	}
}

// The native driver is the only testing browser: no setting selects a surface,
// so a leftover browser_driver row changes nothing.
func TestNativeBrowserToolsAreAssembledWithoutASetting(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_PG_DSN") == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	m, s, _ := memoryTestServer(t)
	if err := m.pg.SetSetting("browser_driver", "mcp"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM settings WHERE key='browser_driver'`) })

	tools, _ := s.hostTools()
	for _, tool := range tools {
		if tool.Name() == "browser_open" {
			return
		}
	}
	t.Fatal("the testing browser was not assembled")
}

// The native tools take the same boundary as the MCP ones: the guard must wrap
// them by name, refuse an out-of-scope navigation before the driver runs, and
// refuse a page that landed off-scope.
func TestNativeBrowserToolsAreScopeGuarded(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_PG_DSN") == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	m, _, _ := memoryTestServer(t)
	task, err := m.CreateTaskWithOptions("native scope", "boundary", db.TaskCreateOptions{Name: "native scope"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Exec(`INSERT INTO task_scope(task_id, kind, domain, effect, source)
VALUES ($1,'root_domain','blocked.invalid','exclude','manual')`, task.ID); err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})

	called := false
	inner := fakeNavTool("browser_open", &called)
	guarded := scopeGuardTool(m.pg.Assets(), inner)
	res, err := guarded.Call(ctx, json.RawMessage(`{"url":"https://blocked.invalid/login"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || called {
		t.Fatalf("an out-of-scope navigation reached the driver (isError=%v called=%v)", res.IsError, called)
	}
	if !strings.Contains(resultText(res), "out of scope") {
		t.Fatalf("refusal text = %q", resultText(res))
	}

	// An in-scope navigation passes and the landing page is judged too.
	called = false
	res, err = guarded.Call(ctx, json.RawMessage(`{"url":"https://allowed.invalid/"}`), nil)
	if err != nil || res.IsError || !called {
		t.Fatalf("an in-scope navigation was refused: %v %v", err, resultText(res))
	}
}

func TestNativeBrowserPrefixIsWrapped(t *testing.T) {
	inner := fakeNavTool("browser_snapshot", new(bool))
	if got := scopeGuardTool(nil, inner); got == actool.CoreTool(inner) {
		t.Fatal("a native browser tool was not wrapped")
	}
	other := fakeNavTool("run_tool", new(bool))
	if got := scopeGuardTool(nil, other); got != actool.CoreTool(other) {
		t.Fatal("a non-browser tool was wrapped")
	}
}

// fakeToolDriver stands in for a Chromium driver: these tests exercise the tool
// layer, not the browser.
type fakeToolDriver struct {
	navURL     string
	tree       string
	subtreeRef string
	subtreeMax int
	console    []browser.ConsoleEntry
	seq        int64
	since      int64
	limit      int
	blocked    []string
	popups     []string
	downloads  []string
	uploaded   []string
	calls      int
	lookups    int
}

func (f *fakeToolDriver) Navigate(_ context.Context, url string) (browser.PageState, error) {
	f.calls++
	f.navURL = url
	return browser.PageState{URL: url, Title: "Example"}, nil
}

func (f *fakeToolDriver) Snapshot(context.Context) (*browser.Snapshot, error) {
	f.calls++
	return &browser.Snapshot{Tree: f.tree}, nil
}

func (f *fakeToolDriver) SnapshotSubtree(_ context.Context, ref string, maxLines int) (browser.Snapshot, error) {
	f.calls++
	f.subtreeRef, f.subtreeMax = ref, maxLines
	return browser.Snapshot{Tree: f.tree}, nil
}

func (f *fakeToolDriver) Click(context.Context, string) (browser.PageState, error) {
	f.calls++
	return browser.PageState{URL: "https://example.test/", Title: "Example"}, nil
}

func (f *fakeToolDriver) Type(context.Context, string, string) (browser.PageState, error) {
	f.calls++
	return browser.PageState{}, nil
}

func (f *fakeToolDriver) Press(context.Context, string) (browser.PageState, error) {
	f.calls++
	return browser.PageState{}, nil
}

func (f *fakeToolDriver) Select(context.Context, string, ...string) (browser.PageState, error) {
	f.calls++
	return browser.PageState{}, nil
}

func (f *fakeToolDriver) Wait(context.Context, string, time.Duration) error {
	f.calls++
	return nil
}

func (f *fakeToolDriver) Screenshot(context.Context, bool) ([]byte, error) {
	f.calls++
	return nil, nil
}

func (f *fakeToolDriver) Upload(_ context.Context, _ string, paths []string) (browser.PageState, error) {
	f.calls++
	f.uploaded = append(f.uploaded, paths...)
	return browser.PageState{}, nil
}

func (f *fakeToolDriver) URL() string   { return "https://example.test/" }
func (f *fakeToolDriver) Title() string { return "Example" }

func (f *fakeToolDriver) BlockedRequests() []string {
	out := f.blocked
	f.blocked = nil
	return out
}

func (f *fakeToolDriver) Popups() []string {
	out := f.popups
	f.popups = nil
	return out
}

func (f *fakeToolDriver) Downloads() []string {
	out := f.downloads
	f.downloads = nil
	return out
}

func (f *fakeToolDriver) Console(since int64, limit int) []browser.ConsoleEntry {
	f.since, f.limit = since, limit
	var out []browser.ConsoleEntry
	for _, e := range f.console {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeToolDriver) ConsoleSeq() int64 { return f.seq }

// toolTestServer is a Server with only the fields the tools touch, and a fake
// driver behind the package seam, so no Chromium is launched.
func toolTestServer(t *testing.T, drv *fakeToolDriver) *Server {
	t.Helper()
	prevFor, prevExisting := browserToolFor, browserToolExisting
	browserToolFor = func(*Server, context.Context, string) (browserToolDriver, error) {
		drv.lookups++
		return drv, nil
	}
	browserToolExisting = func(*Server, string) browserToolDriver {
		drv.lookups++
		return drv
	}
	t.Cleanup(func() { browserToolFor, browserToolExisting = prevFor, prevExisting })
	return &Server{browsers: browserSessions{byID: map[string]*browserSession{}}}
}

func toolTestContext() context.Context {
	return agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7})
}

// H4: one navigation returns the page line and the tree, so the agent does not
// need a second call.
func TestBrowserNavigateReturnsSnapshot(t *testing.T) {
	drv := &fakeToolDriver{tree: "- role \"heading\" [ref=g1e1]"}
	s := toolTestServer(t, drv)
	res, err := s.browserNavigateTool().Call(toolTestContext(), json.RawMessage(`{"url":"https://example.test/login"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	text := resultText(res)
	if res.IsError || !strings.Contains(text, "- Page URL: https://example.test/login") || !strings.Contains(text, "- role \"heading\"") {
		t.Fatalf("navigate result = %q", text)
	}
	if drv.navURL != "https://example.test/login" {
		t.Fatalf("navigated to %q", drv.navURL)
	}
}

// H8: a ref reads only that subtree with the caller's line budget; without a
// ref the whole page is read.
func TestBrowserSnapshotWithRefReadsSubtree(t *testing.T) {
	drv := &fakeToolDriver{tree: "- role \"form\" [ref=g1e1]"}
	s := toolTestServer(t, drv)
	ctx := toolTestContext()

	res, err := s.browserSnapshotTool().Call(ctx, json.RawMessage(`{}`), nil)
	if err != nil || res.IsError || drv.subtreeRef != "" {
		t.Fatalf("a snapshot without a ref took the subtree path: ref=%q result=%q", drv.subtreeRef, resultText(res))
	}

	res, err = s.browserSnapshotTool().Call(ctx, json.RawMessage(`{"ref":"g1e2","max_lines":40}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("snapshot: %v %q", err, resultText(res))
	}
	if drv.subtreeRef != "g1e2" || drv.subtreeMax != 40 {
		t.Fatalf("subtree ref=%q max=%d, want g1e2/40", drv.subtreeRef, drv.subtreeMax)
	}
	if !strings.Contains(resultText(res), "- role \"form\"") {
		t.Fatalf("subtree missing from %q", resultText(res))
	}
}

// H6: browser_log passes the cursor and limit through and returns the next one.
func TestBrowserLogMapsCursorAndLimit(t *testing.T) {
	drv := &fakeToolDriver{
		console: []browser.ConsoleEntry{
			{Seq: 1, Level: "log", Text: "ready", URL: "https://example.test/", Line: 1},
			{Seq: 2, Level: "error", Text: "boom", URL: "https://example.test/app.js", Line: 9},
		},
		seq: 2,
	}
	s := toolTestServer(t, drv)
	res, err := s.browserLogTool().Call(toolTestContext(), json.RawMessage(`{"since":1,"limit":10}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if drv.since != 1 || drv.limit != 10 {
		t.Fatalf("Console(since=%d, limit=%d), want (1, 10)", drv.since, drv.limit)
	}
	var got struct {
		Entries []consoleLine `json:"entries"`
		Next    int64         `json:"next"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &got); err != nil {
		t.Fatalf("browser_log result %q: %v", resultText(res), err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Text != "boom" || got.Entries[0].Level != "error" {
		t.Fatalf("entries = %+v, want only the error", got.Entries)
	}
	if got.Next != 2 {
		t.Fatalf("next = %d, want 2", got.Next)
	}
}

// H3: close ends the session and a second close is a no-op, not an error.
func TestBrowserCloseIsIdempotent(t *testing.T) {
	s := toolTestServer(t, &fakeToolDriver{})
	addBrowserSession(s, "7", time.Now())
	ctx := toolTestContext()

	res, err := s.browserCloseTool().Call(ctx, nil, nil)
	if err != nil || res.IsError || resultText(res) != "closed" {
		t.Fatalf("first close = %q (isError=%v err=%v)", resultText(res), res.IsError, err)
	}
	res, err = s.browserCloseTool().Call(ctx, nil, nil)
	if err != nil || res.IsError || resultText(res) != "no session" {
		t.Fatalf("second close = %q (isError=%v err=%v)", resultText(res), res.IsError, err)
	}
}

// H5: a blocked host is named by the tool call that notices it, once.
func TestBrowserToolReportsBlockedHostsOnce(t *testing.T) {
	drv := &fakeToolDriver{tree: "- role \"main\"", blocked: []string{"cdn.thirdparty.example"}}
	s := toolTestServer(t, drv)
	ctx := toolTestContext()

	res, err := s.browserSnapshotTool().Call(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if text := resultText(res); !strings.Contains(text, "blocked 1 out-of-scope requests: cdn.thirdparty.example") {
		t.Fatalf("blocked line missing from %q", text)
	}
	res, err = s.browserSnapshotTool().Call(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if text := resultText(res); strings.Contains(text, "blocked") {
		t.Fatalf("blocked line reported twice: %q", text)
	}
}

// H7: a completed download is named in the next tool result.
func TestBrowserToolReportsDownloads(t *testing.T) {
	drv := &fakeToolDriver{tree: "- role \"main\"", downloads: []string{"tasks/7/downloads/export.csv"}}
	s := toolTestServer(t, drv)
	res, err := s.browserSnapshotTool().Call(toolTestContext(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if text := resultText(res); !strings.Contains(text, "downloaded: tasks/7/downloads/export.csv") {
		t.Fatalf("download line missing from %q", text)
	}
}

// H10: while an operator holds the slot the agent's actions are refused before
// the driver is looked up, so nothing reaches CDP; releasing allows them.
func TestBrowserToolsRefuseWhileOperatorHolds(t *testing.T) {
	drv := &fakeToolDriver{tree: "- role \"main\""}
	s := toolTestServer(t, drv)
	if !liveClaim("7", "operator", func() {}, nil) {
		t.Fatal("could not take the operator slot")
	}
	t.Cleanup(func() { liveRelease("7", "operator") })
	ctx := toolTestContext()
	calls := []struct {
		name string
		tool actool.CoreTool
		in   string
	}{
		{"browser_open", s.browserOpenTool(), `{"url":"https://example.test/"}`},
		{"browser_navigate", s.browserNavigateTool(), `{"url":"https://example.test/"}`},
		{"browser_click", s.browserClickTool(), `{"ref":"g1e1"}`},
	}
	for _, c := range calls {
		res, err := c.tool.Call(ctx, json.RawMessage(c.in), nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !res.IsError || !strings.Contains(resultText(res), "the operator has the page") {
			t.Fatalf("%s was not refused: %q", c.name, resultText(res))
		}
	}
	if drv.calls != 0 || drv.lookups != 0 {
		t.Fatalf("the refusal reached the driver: calls=%d lookups=%d", drv.calls, drv.lookups)
	}

	liveRelease("7", "operator")
	res, err := s.browserClickTool().Call(ctx, json.RawMessage(`{"ref":"g1e1"}`), nil)
	if err != nil || res.IsError || drv.calls != 1 {
		t.Fatalf("a released slot still refused: %v %q calls=%d", err, resultText(res), drv.calls)
	}
}

// Uploads are rooted in the current task's workspace. The old check joined the
// shared work dir and cleaned the string, so a sibling task's file, an absolute
// path and a symlink planted in the workspace all reached CDP.
func TestBrowserUploadStaysInTaskWorkspace(t *testing.T) {
	drv := &fakeToolDriver{}
	s := toolTestServer(t, drv)
	dir := t.TempDir()
	s.m = &Manager{dir: dir}
	own := filepath.Join(dir, "tasks", "7", "uploads")
	other := filepath.Join(dir, "tasks", "8")
	for _, d := range []string{own, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wordlist := filepath.Join(own, "wordlist.txt")
	secret := filepath.Join(other, "secret.txt")
	for _, f := range []string{wordlist, secret} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secret, filepath.Join(own, "link.txt")); err != nil {
		t.Fatal(err)
	}

	call := func(path string) actool.Result {
		t.Helper()
		in, err := json.Marshal(map[string]any{"ref": "f1", "paths": []string{path}})
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.browserUploadTool().Call(toolTestContext(), in, nil)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return res
	}

	for _, path := range []string{secret, "uploads/link.txt", "../8/secret.txt"} {
		res := call(path)
		if !res.IsError {
			t.Fatalf("%q reached the driver instead of being refused: %q", path, resultText(res))
		}
		if text := resultText(res); !strings.Contains(text, "task workspace") {
			t.Fatalf("%q refusal must name the task workspace: %q", path, text)
		}
	}
	if drv.calls != 0 {
		t.Fatalf("a refused path reached the driver: %d calls", drv.calls)
	}

	if res := call("uploads/wordlist.txt"); res.IsError {
		t.Fatalf("legitimate upload refused: %q", resultText(res))
	}
	if len(drv.uploaded) != 1 || drv.uploaded[0] != wordlist {
		t.Fatalf("upload paths = %v, want [%s]", drv.uploaded, wordlist)
	}
}

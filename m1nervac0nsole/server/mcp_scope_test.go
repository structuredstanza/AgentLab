package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/norma/skill"
	actool "github.com/structuredstanza/norma/tool"
)

// fakeNavTool stands in for an MCP browser tool and records whether it ran.
func fakeNavTool(name string, called *bool) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:   name,
		Schema: map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			*called = true
			return actool.Text("navigated"), nil
		},
	})
}

func navCall(t *testing.T, tool actool.CoreTool, ctx context.Context, url string) actool.Result {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"url": url})
	if err != nil {
		t.Fatal(err)
	}
	res, err := tool.Call(ctx, raw, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("call returned error: %v", err)
	}
	return res
}

// An in-scope URL is not refused: an exclusion elsewhere in the task must not
// become a blanket block.
func TestMCPScopeGuardAllowsInScopeNavigation(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) - skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { pg.Close() })

	task, err := pg.CreateTask("browser scope allow", "verify in-scope navigation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	excluded := fmt.Sprintf("blocked-%d.invalid", task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "root_domain", excluded, "excluded by test", "manual", "exclude"); err != nil {
		t.Fatalf("record exclusion: %v", err)
	}

	called := false
	tool := scopeGuardTool(pg.Assets(), fakeNavTool("mcp__browser__browser_navigate", &called))
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	res := navCall(t, tool, ctx, fmt.Sprintf("https://allowed-%d.invalid/login", task.ID))
	if res.IsError {
		t.Fatalf("an in-scope URL was refused: %s", resultText(res))
	}
	if !called {
		t.Fatal("the navigation tool was not called for an in-scope URL")
	}
}

// An excluded host is refused before the MCP server is asked to open it, and the
// message names the host so the worker can record the boundary.
func TestMCPScopeGuardRefusesExcludedHost(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) - skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { pg.Close() })

	task, err := pg.CreateTask("browser scope refuse", "verify out-of-scope navigation is refused", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	apex := fmt.Sprintf("blocked-%d.invalid", task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "root_domain", apex, "excluded by test", "manual", "exclude"); err != nil {
		t.Fatalf("record exclusion: %v", err)
	}
	if _, err := pg.Assets().AddAgentScope(task.ID, "cidr", "203.0.113.0/24", "excluded by test", "manual", "exclude"); err != nil {
		t.Fatalf("record network exclusion: %v", err)
	}

	called := false
	tool := scopeGuardTool(pg.Assets(), fakeNavTool("mcp__browser__browser_navigate", &called))
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	for _, target := range []string{
		"https://api." + apex + "/admin",
		// Userinfo must not hide the host from the checker.
		"http://user:pass@api." + apex + "/admin",
	} {
		res := navCall(t, tool, ctx, target)
		if !res.IsError {
			t.Errorf("%q was allowed", target)
			continue
		}
		if got := resultText(res); !strings.Contains(got, "api."+apex) {
			t.Errorf("%q was refused without naming the host; result was %q", target, got)
		}
	}
	// Chromium's IDNA host parser maps the Unicode full stop to ".", so this
	// reaches the excluded apex while Go reports the literal Unicode host.
	unicodeApex := strings.Replace(apex, ".", "\u3002", 1)
	if res := navCall(t, tool, ctx, "http://"+unicodeApex+"/"); !res.IsError {
		t.Errorf("%q was allowed", unicodeApex)
	}
	// WHATWG reads decimal and hex IPv4 forms, so these reach 203.0.113.5 while
	// Go reports the literal string and the CIDR exclusion would miss it.
	for _, target := range []string{"http://3405803781/", "http://0xcb.0x0.0x71.0x5/"} {
		if res := navCall(t, tool, ctx, target); !res.IsError {
			t.Errorf("%q was allowed", target)
		}
	}
	if called {
		t.Fatal("the navigation tool ran for an excluded host")
	}
}

// Non-http(s) schemes are refused outright: file: reads the container, chrome:
// reaches browser internals, data: is not a boundary at all. Backslashes are
// refused because Chromium and Go disagree about what they separate.
func TestMCPScopeGuardRefusesUnsafeURLs(t *testing.T) {
	called := false
	tool := scopeGuardTool(nil, fakeNavTool("mcp__browser__navigate", &called))
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7})
	for _, tc := range []struct{ url, want string }{
		{"file:///etc/passwd", "only absolute http(s) URLs"},
		{"chrome://settings", "only absolute http(s) URLs"},
		{"data:text/html,<h1>x</h1>", "only absolute http(s) URLs"},
		// Chromium reads the backslash as a path separator; Go rejects it today,
		// but the shape is refused outright rather than relying on that.
		{`http://evil.example\@allowed.example/`, "backslashes"},
	} {
		res := navCall(t, tool, ctx, tc.url)
		if !res.IsError {
			t.Errorf("%q was allowed", tc.url)
			continue
		}
		if got := resultText(res); !strings.Contains(got, tc.want) {
			t.Errorf("%q was refused for the wrong reason: %q", tc.url, got)
		}
	}
	if called {
		t.Fatal("the navigation tool ran for an unsafe URL")
	}
}

// A tool from another MCP server is returned untouched: only the browser server
// carries pages that cross the boundary.
func TestMCPScopeGuardPassesThroughOtherTools(t *testing.T) {
	called := false
	inner := fakeNavTool("mcp__other__snapshot", &called)
	got := scopeGuardTool(nil, inner)
	if got != inner {
		t.Fatal("a non-browser MCP tool was wrapped")
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7})
	if res := navCall(t, got, ctx, "not a url at all"); res.IsError {
		t.Fatalf("a non-browser tool was refused: %s", resultText(res))
	}
	if !called {
		t.Fatal("the non-browser tool did not run")
	}
}

// A browser tool that is not a navigation is still wrapped: the page it reports
// is judged, because a click can navigate.
func TestMCPScopeGuardJudgesTheLandingPage(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) - skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { pg.Close() })

	task, err := pg.CreateTask("browser landing scope", "verify the landing page is judged", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	excluded := fmt.Sprintf("blocked-%d.invalid", task.ID)
	if _, err := pg.Assets().AddAgentScope(task.ID, "root_domain", excluded, "excluded by test", "manual", "exclude"); err != nil {
		t.Fatalf("record exclusion: %v", err)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})

	// A click whose result reports an excluded page is refused even though the
	// click itself carries no url to judge.
	for _, name := range []string{"mcp__browser__browser_click", "mcp__browser__browser_navigate"} {
		called := false
		tool := scopeGuardTool(pg.Assets(), pageTool(name, fmt.Sprintf("https://%s/admin", excluded), &called))
		res := navCall(t, tool, ctx, fmt.Sprintf("https://allowed-%d.invalid/", task.ID))
		if !res.IsError {
			t.Errorf("%s: an off-scope landing page was allowed", name)
			continue
		}
		if got := resultText(res); !strings.Contains(got, "landed on an out-of-scope page") {
			t.Errorf("%s: refused for the wrong reason: %q", name, got)
		}
		if !called {
			t.Errorf("%s: the tool did not run before the landing check", name)
		}
	}

	// The same tool landing in scope passes through.
	called := false
	tool := scopeGuardTool(pg.Assets(), pageTool("mcp__browser__browser_click", fmt.Sprintf("https://allowed-%d.invalid/home", task.ID), &called))
	if res := navCall(t, tool, ctx, fmt.Sprintf("https://allowed-%d.invalid/", task.ID)); res.IsError {
		t.Fatalf("an in-scope landing page was refused: %s", resultText(res))
	}
}

// pageTool fakes a browser tool whose result reports the page it landed on, the
// way Playwright prints it.
func pageTool(name, pageURL string, called *bool) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:   name,
		Schema: map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			*called = true
			return actool.Text("### Page\n- Page URL: " + pageURL + "\n- Page Title: fixture"), nil
		},
	})
}

// The main agent and chat have no task, so there is no boundary to enforce.
func TestMCPScopeGuardPassesThroughWithoutTask(t *testing.T) {
	called := false
	tool := scopeGuardTool(nil, fakeNavTool("mcp__browser__browser_navigate", &called))
	res := navCall(t, tool, context.Background(), "https://anything.invalid/")
	if res.IsError {
		t.Fatalf("a task-less run was refused: %s", resultText(res))
	}
	if !called {
		t.Fatal("a task-less navigation did not run")
	}
}

// A task with no readable boundary is refused: "I could not check" is not
// "allowed" for a boundary.
func TestMCPScopeGuardRefusesWhenCheckerIsNil(t *testing.T) {
	called := false
	tool := scopeGuardTool(nil, fakeNavTool("mcp__browser__browser_navigate", &called))
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7})
	res := navCall(t, tool, ctx, "https://allowed.invalid/")
	if !res.IsError {
		t.Fatal("a navigation with no scope checker was allowed")
	}
	if got := resultText(res); !strings.Contains(got, "cannot be checked") {
		t.Errorf("the refusal does not explain the missing checker: %q", got)
	}
	if called {
		t.Fatal("the navigation tool ran without a scope check")
	}
}

// The skill gate only connects a server named in a visible skill's `mcps` field,
// so the frontmatter is load-bearing: without it the browser tools never reach
// the agents the visibility map binds the skill to.
func TestBrowserSkillDeclaresBrowserMCP(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("LoadDir on shipped skills: %v", err)
	}
	for _, s := range reg.List() {
		if filepath.Base(s.Dir) != "browser" {
			continue
		}
		if len(s.MCPs) != 1 || s.MCPs[0] != "browser" {
			t.Fatalf("browser skill declares mcps %v, want [browser]", s.MCPs)
		}
		return
	}
	t.Fatal("browser skill not found in skills/")
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
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
	tool := scopeGuardTool(pg.Assets(), fakeNavTool("browser_navigate", &called))
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
	tool := scopeGuardTool(pg.Assets(), fakeNavTool("browser_navigate", &called))
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
	tool := scopeGuardTool(nil, fakeNavTool("browser_navigate", &called))
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
	for _, name := range []string{"browser_click", "browser_navigate"} {
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
	tool := scopeGuardTool(pg.Assets(), pageTool("browser_click", fmt.Sprintf("https://allowed-%d.invalid/home", task.ID), &called))
	if res := navCall(t, tool, ctx, fmt.Sprintf("https://allowed-%d.invalid/", task.ID)); res.IsError {
		t.Fatalf("an in-scope landing page was refused: %s", resultText(res))
	}
}

// pageTool fakes a browser tool whose result reports the page it landed on, the
// way the native tools print it.
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
	tool := scopeGuardTool(nil, fakeNavTool("browser_navigate", &called))
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
	tool := scopeGuardTool(nil, fakeNavTool("browser_navigate", &called))
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

// The browser skill is guidance, not a gate: a skill-gated MCP server was listed
// in the prompt but never unlocked in two measured runs, so the worker never used
// the browser. The native driver's tools are host tools, bound directly.
func TestBrowserSkillDoesNotGateAServer(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("LoadDir on shipped skills: %v", err)
	}
	for _, s := range reg.List() {
		if filepath.Base(s.Dir) != "browser" {
			continue
		}
		if len(s.MCPs) != 0 {
			t.Fatalf("browser skill declares mcps %v; the server must be bound directly", s.MCPs)
		}
		return
	}
	t.Fatal("browser skill not found in skills/")
}

// researchFixture opens the database, creates a task with one operator-approved
// include rule, and returns the authorizer plus the pattern research must refuse.
func researchFixture(t *testing.T) (*netpolicy.Store, string) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) - skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { pg.Close() })

	task, err := pg.CreateTask("research boundary", "verify research cannot read a target", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	target := fmt.Sprintf("target-%d.example", task.ID)
	ruleID, err := pg.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: target, Note: "operator authorized this engagement",
	}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.SetPolicyRuleAuthorized(t.Context(), task.ID, ruleID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	return netpolicy.NewAuthorizer(pg), target
}

// The research browser is the only browser a run without a task can drive, so its
// boundary is the research policy: an engagement target, a private address and a
// metadata endpoint are refused before obscura loads them, and a public page is
// allowed with no task at all.
func TestResearchGuardRefusesTargetsAndPrivateAddresses(t *testing.T) {
	auth, target := researchFixture(t)

	called := false
	tool := researchGuardTool(auth, fakeNavTool("mcp__obscura__browser_navigate", &called))
	ctx := context.Background() // a chat with no task

	for _, tc := range []struct{ url, want string }{
		{"https://" + target + "/advisory", "task target"},
		{"http://127.0.0.1:8080/", "loopback"},
		{"http://10.1.2.3/", "private"},
		{"http://169.254.169.254/latest/meta-data/", "link-local"},
		{"http://[::1]/", "loopback"},
	} {
		res := navCall(t, tool, ctx, tc.url)
		if !res.IsError {
			t.Errorf("%q was allowed for research", tc.url)
			continue
		}
		if got := resultText(res); !strings.Contains(got, tc.want) {
			t.Errorf("%q was refused for the wrong reason: %q", tc.url, got)
		}
	}
	if called {
		t.Fatal("the research browser ran for a refused destination")
	}

	res := navCall(t, tool, ctx, "https://example.com/docs")
	if res.IsError {
		t.Fatalf("a public page was refused: %s", resultText(res))
	}
	if !called {
		t.Fatal("the research browser did not run for a public page")
	}
}

// A redirect is judged on where it landed: obscura reports the final URL in the
// navigation result, so a public page that redirects onto a target or into a
// private address is refused after the fact.
func TestResearchGuardRefusesRedirectToTarget(t *testing.T) {
	auth, target := researchFixture(t)

	for _, landed := range []string{"https://" + target + "/admin", "http://127.0.0.1:9000/"} {
		called := false
		inner := actool.Build(actool.Spec{
			Name:   "mcp__obscura__browser_navigate",
			Schema: map[string]any{"type": "object"},
			Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
				called = true
				return actool.Text("Navigated to " + landed + " \u2014 \"Admin\""), nil
			},
		})
		res := navCall(t, researchGuardTool(auth, inner), context.Background(), "https://docs.example.com/")
		if !res.IsError {
			t.Errorf("a redirect to %q was allowed", landed)
			continue
		}
		if got := resultText(res); !strings.Contains(got, "landed on") {
			t.Errorf("the redirect to %q was refused for the wrong reason: %q", landed, got)
		}
		if !called {
			t.Errorf("the navigation did not run before the landing check for %q", landed)
		}
	}
}

// The research browser exposes reading and extraction only: evaluate, cookies,
// storage, fill, click and a second tab are never assembled, while every other
// MCP server keeps its whole surface.
func TestResearchAllowListHidesInteractiveTools(t *testing.T) {
	for _, name := range []string{
		"browser_navigate", "browser_markdown", "browser_links", "browser_extract",
		"browser_snapshot", "browser_search", "browser_back", "browser_forward",
		"browser_reload", "browser_wait_for_text", "browser_close",
	} {
		if !researchToolAllowed("obscura", "mcp__obscura__"+name) {
			t.Errorf("%s is not exposed", name)
		}
	}
	for _, name := range []string{
		"browser_evaluate", "browser_wait_for_function", "browser_get_cookies",
		"browser_set_cookie", "browser_clear_cookies", "browser_storage_state",
		"browser_set_storage_state", "browser_fill", "browser_click", "browser_tab_new",
	} {
		if researchToolAllowed("obscura", "mcp__obscura__"+name) {
			t.Errorf("%s is exposed by the research browser", name)
		}
	}
	if !researchToolAllowed("rea", "mcp__rea__anything") {
		t.Fatal("a non-browser MCP server lost a tool")
	}
}

// An unbound chat has no testing browser - there is no task to scope it to - and
// the refusal names the research browser, which needs none.
func TestBrowserTaskIDRefusesUnboundChat(t *testing.T) {
	s := &Server{}
	_, err := s.browserTaskID(context.Background())
	if err == nil {
		t.Fatal("an unbound chat was given a testing browser")
	}
	if !strings.Contains(err.Error(), "research browser") {
		t.Fatalf("the refusal does not point at research: %v", err)
	}
}

// A chat bound to a task uses that task's browser. The binding is read from the
// conversation row, so a model cannot name another engagement.
func TestBrowserTaskIDUsesTheConversationsTask(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_PG_DSN") == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	m, s, _ := memoryTestServer(t)
	task, err := m.pg.CreateTask("bound chat", "browser binding", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })

	conv, err := m.pg.CreateConversationForTask("mainagent", "bound chat", nil, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteConversation(conv.ID) })

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: fmt.Sprintf("conv-%d", conv.ID)})
	got, err := s.browserTaskID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := strconv.FormatInt(task.ID, 10); got != want {
		t.Fatalf("browser task = %q, want the conversation's task %q", got, want)
	}

	// The same chat with no binding is refused.
	unbound, err := m.pg.CreateConversation("mainagent", "unbound chat", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteConversation(unbound.ID) })
	ctx = agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: fmt.Sprintf("conv-%d", unbound.ID)})
	if _, err := s.browserTaskID(ctx); err == nil {
		t.Fatal("an unbound conversation was given a testing browser")
	}
}

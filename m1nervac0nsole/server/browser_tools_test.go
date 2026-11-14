package server

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
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

// The recorder returns a full URL and the global proxy may be a bare host:port;
// prefixing a full URL again is what produced ERR_NO_SUPPORTED_PROXIES.
func TestProxyURL(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8788": "http://127.0.0.1:8788",
		"127.0.0.1:8788":        "http://127.0.0.1:8788",
		"socks5://127.0.0.1:1":  "socks5://127.0.0.1:1",
	}
	for in, want := range cases {
		if got := proxyURL(in); got != want {
			t.Errorf("proxyURL(%q) = %q, want %q", in, got, want)
		}
	}
}

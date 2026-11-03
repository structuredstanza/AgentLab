package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/tool"
)

func toolPolicyFixture(t *testing.T) (*db.DB, *intercept.Interceptor) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools) })
	priorConfig := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(priorConfig) })
	return d, ic
}

func TestChatToolAliasesEnforceCanonicalPolicy(t *testing.T) {
	d, ic := toolPolicyFixture(t)
	if err := ic.SetEnabledTools([]string{"Bash", "mcp__Alpha__Probe"}); err != nil {
		t.Fatal(err)
	}
	rule, err := d.CreateInterceptRule("alias policy regression", "tool_name", "regex", "^(Bash|mcp__Alpha__Probe)$", "deny", "blocked by canonical policy", 1000000, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteInterceptRule(rule.ID) })
	ic.Invalidate()
	oldResolve, oldAugment := ToolResolve, ToolAugment
	t.Cleanup(func() { ToolResolve, ToolAugment = oldResolve, oldAugment })
	ToolAugment = nil
	for _, tc := range []struct {
		name      string
		collision bool
		wantCalls int
	}{
		{name: "Bash"},
		{name: "bash"},
		{name: "BASH"},
		{name: "bash", collision: true, wantCalls: 1},
		{name: "mcp__Alpha__Probe"},
		{name: "mcp__alpha__probe", wantCalls: 1},
	} {
		t.Run(tc.name+map[bool]string{true: "_real_tool"}[tc.collision], func(t *testing.T) {
			calls, turn := 0, 0
			probe := func(name string) tool.CoreTool {
				return tool.Build(tool.Spec{Name: name, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
					calls++
					return tool.Text("executed"), nil
				}})
			}
			ToolResolve = func(context.Context, string, []tool.CoreTool) []tool.CoreTool {
				tools := []tool.CoreTool{probe("Bash"), probe("mcp__Alpha__Probe"), probe("mcp__alpha__probe")}
				if tc.collision {
					tools = append(tools, probe("bash"))
				}
				return tools
			}
			provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
				turn++
				events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
				if turn == 1 {
					events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "policy-call", ToolName: tc.name}, {Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
				}
				for _, event := range events {
					if !yield(event, nil) {
						return
					}
				}
			}}
			chat := NewChatAgent(provider, "test-model", t.TempDir(), nil, 0)
			chat.SetGuard(guard.NewWithInterceptor(ic))
			if _, err := chat.Chat(t.Context(), "policy-test", "alias-test", "check policy", 2, 0, false, nil); err != nil {
				t.Fatal(err)
			}
			if calls != tc.wantCalls {
				t.Fatalf("%s handler executed %d times, want %d", tc.name, calls, tc.wantCalls)
			}
		})
	}
}

func TestPlannerAndMainAgentEnforceToolApprovals(t *testing.T) {
	d, ic := toolPolicyFixture(t)
	if err := ic.SetEnabledTools([]string{"PolicyProbe"}); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetJudgeConfig(intercept.JudgeConfig{Enabled: true, AskTimeoutSeconds: 5, AskTimeoutAction: "deny"}); err != nil {
		t.Fatal(err)
	}
	oldResolve, oldAugment := ToolResolve, ToolAugment
	t.Cleanup(func() { ToolResolve, ToolAugment = oldResolve, oldAugment })
	ToolAugment = nil
	for _, role := range []string{"planner", "planner_final", "mainagent"} {
		for _, tc := range []struct {
			name, action    string
			approve, cancel bool
			wantCalls       int
		}{
			{name: "deny", action: "deny"},
			{name: "approve", action: "ask", approve: true, wantCalls: 1},
			{name: "reject", action: "ask"},
			{name: "cancel", action: "ask", cancel: true},
		} {
			t.Run(role+"/"+tc.name, func(t *testing.T) {
				expID, err := d.CreateExploration("Isolated tool-policy check", "Require tool approval")
				if err != nil {
					t.Fatal(err)
				}
				const registryTaskID = int64(987654321)
				taskID := fmt.Sprint(registryTaskID)
				t.Cleanup(func() {
					_, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID)
					_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if role == "planner_final" {
					ctx = WithTaskClock(ctx, TaskClock{Final: true, DeadlineUnix: time.Now().Add(time.Hour).Unix()})
				}
				dir := t.TempDir()
				calls, turn, reviews, pending := 0, 0, 0, 0
				ic.SetReviewer(func(_ context.Context, _ int64, _ string, in intercept.ReviewInput) (intercept.Decision, error) {
					reviews++
					if in.Tool != "PolicyProbe" || in.WorkingDir != filepath.Join(dir, "tasks", taskID) {
						t.Errorf("wrong review identity or workspace: %+v", in)
					}
					return intercept.Decision{Action: tc.action, Message: "explicit policy"}, nil
				})
				ToolResolve = func(context.Context, string, []tool.CoreTool) []tool.CoreTool {
					return []tool.CoreTool{tool.Build(tool.Spec{Name: "PolicyProbe", Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
						calls++
						return tool.Text("authorized execution"), nil
					}})}
				}
				provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
					turn++
					events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
					if turn == 1 {
						events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "guarded-call", ToolName: "policy_probe"}, {Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
					}
					for _, event := range events {
						if !yield(event, nil) {
							return
						}
					}
				}}
				emit := func(a db.Activity) {
					if a.Kind != "intercept_request" {
						return
					}
					pending++
					if tc.cancel {
						cancel()
						return
					}
					var detail struct {
						ID int64 `json:"pending_id"`
					}
					if err := json.Unmarshal([]byte(a.Detail), &detail); err != nil {
						t.Error(err)
					} else if err := ic.Decide(detail.ID, tc.approve); err != nil {
						t.Error(err)
					}
				}
				g := guard.NewWithInterceptor(ic)
				if role == "mainagent" {
					main := NewMainAgent(provider, "test-model", dir, nil, 0, 2)
					main.SetGuard(g)
					_, err = main.Chat(ctx, registryTaskID, 7, nil, d.Exploration(expID), "Check policy", "run the probe", emit, nil, nil, nil, nil)
				} else {
					planner := NewPlanner(provider, "test-model", dir, nil, 0, 2)
					planner.SetGuard(g)
					_, _, err = planner.Plan(ctx, registryTaskID, nil, d.Exploration(expID), "Check policy", nil, emit)
				}
				if err != nil && !tc.cancel {
					t.Fatal(err)
				}
				if calls != tc.wantCalls || reviews != 1 || (tc.action == "ask" && pending != 1) {
					t.Fatalf("calls=%d want=%d reviews=%d pending=%d", calls, tc.wantCalls, reviews, pending)
				}
				rows, err := d.ListTaskIntercepts(taskID)
				if err != nil || len(rows) != 1 {
					t.Fatalf("approval rows=%d err=%v", len(rows), err)
				}
				wantAgent := role
				if role == "planner_final" {
					wantAgent = "planner"
				}
				row := rows[0]
				// Cancellation can return before the SDK's tool goroutine finishes its DB cleanup.
				until := time.Now().Add(5 * time.Second)
				for tc.cancel && row.Status == "pending" && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
					rows, err = d.ListTaskIntercepts(taskID)
					if err != nil || len(rows) != 1 {
						t.Fatalf("approval cleanup rows=%d err=%v", len(rows), err)
					}
					row = rows[0]
				}
				if row.AgentName != wantAgent || row.ToolName != "policy_probe" || row.Status == "pending" {
					t.Fatalf("wrong approval identity or unresolved approval: %+v", row)
				}
				detail, err := d.GetInterceptDetail(row.ID)
				if err != nil || detail.Audit == nil || detail.Audit.ToolUseID != "guarded-call" {
					t.Fatalf("lost requested-call correlation: detail=%+v err=%v", detail, err)
				}
			})
		}
	}
}

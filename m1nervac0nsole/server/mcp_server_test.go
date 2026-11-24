package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mcpPost issues one JSON-RPC request against the real handler chain.
func mcpPost(t *testing.T, s *Server, bearer, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("response is not JSON: %v (%s)", err, rec.Body)
		}
	}
	return rec.Code, out
}

// mcpToolResult pulls the single text block out of a tools/call result.
func mcpToolResult(t *testing.T, out map[string]any) (string, bool) {
	t.Helper()
	result, _ := out["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("unexpected tools/call result: %v", out)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	isErr, _ := result["isError"].(bool)
	return text, isErr
}

func mcpToolCall(t *testing.T, s *Server, bearer, name, args string) (string, bool) {
	t.Helper()
	code, out := mcpPost(t, s, bearer,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args))
	if code != 200 {
		t.Fatalf("%s: HTTP %d %v", name, code, out)
	}
	return mcpToolResult(t, out)
}

// mcpAsset inserts one task-scoped asset and registers its cleanup.
func mcpAsset(t *testing.T, m *Manager, tid int64, domain string) int64 {
	t.Helper()
	var id int64
	err := m.pg.QueryRow(`INSERT INTO assets(type, task_ids, domain, root_domain)
VALUES ('root_domain', ARRAY[$1]::bigint[], $2, $2) RETURNING id`, tid, domain).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.pg.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	return id
}

type mcpRig struct {
	s     *Server
	m     *Manager
	own   int64
	other int64
	token string
	jwt   string
	// ownDomain is the asset value list_assets/get_asset must return; otherDomain
	// belongs to the other task and must never appear.
	ownDomain   string
	otherDomain string
	ownAsset    int64
	otherAsset  int64
}

// mcpRigFor builds two tasks, one finding each, one asset each, a scope row and a
// scope rule on the token's task, and mints a token for that task.
func mcpRigFor(t *testing.T) *mcpRig {
	t.Helper()
	m, s, jwt := memoryTestServer(t)
	ctx := context.Background()
	rig := &mcpRig{m: m, s: s, jwt: jwt}
	rig.own = apiTokenTask(t, m, "mcp own task")
	rig.other = apiTokenTask(t, m, "mcp other task")

	if _, err := m.pg.AddFinding(rig.own, 0, "xss", "own finding", "high", strings.Repeat("s", 600), "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.AddFinding(rig.other, 0, "sqli", "other finding", "critical", "other summary", "", "", nil); err != nil {
		t.Fatal(err)
	}

	rig.ownDomain = fmt.Sprintf("mcp-own-%d.example", rig.own)
	rig.otherDomain = fmt.Sprintf("mcp-other-%d.example", rig.other)
	rig.ownAsset = mcpAsset(t, m, rig.own, rig.ownDomain)
	rig.otherAsset = mcpAsset(t, m, rig.other, rig.otherDomain)

	if _, err := m.pg.Exec(`INSERT INTO task_scope(task_id, kind, domain, source) VALUES($1,'root_domain',$2,'manual')`,
		rig.own, rig.ownDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Assets().AddTaskScopeRule(rig.own, "include", "api."+rig.ownDomain, "operator note"); err != nil {
		t.Fatal(err)
	}

	plain, _, err := m.pg.CreateAPIToken(ctx, "harness", rig.own, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rig.token = plain
	return rig
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	rig := mcpRigFor(t)

	code, out := mcpPost(t, rig.s, rig.token, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if code != 200 {
		t.Fatalf("initialize: HTTP %d %v", code, out)
	}
	result, _ := out["result"].(map[string]any)
	if result["protocolVersion"] != mcpProtocolVersion {
		t.Fatalf("protocolVersion: %v", result["protocolVersion"])
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("capabilities.tools missing: %v", caps)
	}
	info, _ := result["serverInfo"].(map[string]any)
	if info["name"] != "m1nervac0nsole" || info["version"] == nil || info["version"] == "" {
		t.Fatalf("serverInfo: %v", info)
	}

	code, out = mcpPost(t, rig.s, rig.token, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if code != 200 {
		t.Fatalf("tools/list: HTTP %d %v", code, out)
	}
	result, _ = out["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	want := []string{"list_assets", "get_asset", "list_findings", "list_scope", "get_remediation_report"}
	if len(tools) != len(want) {
		t.Fatalf("tools/list returned %d tools, want %d: %v", len(tools), len(want), tools)
	}
	for i, name := range want {
		entry, _ := tools[i].(map[string]any)
		if entry["name"] != name {
			t.Fatalf("tool %d is %v, want %s", i, entry["name"], name)
		}
		if entry["description"] == "" || entry["inputSchema"] == nil {
			t.Fatalf("tool %s is missing description or inputSchema: %v", name, entry)
		}
	}
}

func TestMCPToolsScopedToTokenTask(t *testing.T) {
	rig := mcpRigFor(t)

	// list_findings: only this token's task, summary capped at 500 chars.
	text, isErr := mcpToolCall(t, rig.s, rig.token, "list_findings", `{}`)
	if isErr {
		t.Fatalf("list_findings failed: %s", text)
	}
	var findings struct {
		Findings []struct {
			ID      int64  `json:"id"`
			Name    string `json:"name"`
			Summary string `json:"summary"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text), &findings); err != nil {
		t.Fatalf("list_findings payload: %v (%s)", err, text)
	}
	if len(findings.Findings) != 1 || findings.Findings[0].Name != "own finding" {
		t.Fatalf("list_findings leaked or missed rows: %s", text)
	}
	if n := len([]rune(findings.Findings[0].Summary)); n != mcpSummaryChars {
		t.Fatalf("summary was not truncated to %d runes: %d", mcpSummaryChars, n)
	}

	// Naming another task returns nothing rather than an error that proves it exists.
	text, isErr = mcpToolCall(t, rig.s, rig.token, "list_findings", fmt.Sprintf(`{"task_id":%d}`, rig.other))
	if isErr {
		t.Fatalf("cross-task list_findings errored: %s", text)
	}
	findings.Findings = nil
	if err := json.Unmarshal([]byte(text), &findings); err != nil {
		t.Fatalf("cross-task payload: %v (%s)", err, text)
	}
	if len(findings.Findings) != 0 {
		t.Fatalf("cross-task list_findings returned rows: %s", text)
	}

	// list_assets: only this token's task.
	text, isErr = mcpToolCall(t, rig.s, rig.token, "list_assets", `{}`)
	if isErr {
		t.Fatalf("list_assets failed: %s", text)
	}
	var assets struct {
		Assets []struct {
			ID    int64  `json:"id"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"assets"`
	}
	if err := json.Unmarshal([]byte(text), &assets); err != nil {
		t.Fatalf("list_assets payload: %v (%s)", err, text)
	}
	if len(assets.Assets) != 1 || assets.Assets[0].ID != rig.ownAsset || assets.Assets[0].Value != rig.ownDomain {
		t.Fatalf("list_assets leaked or missed rows: %s", text)
	}

	// get_asset: own asset resolves, another task's asset is indistinguishable from
	// a missing one.
	text, isErr = mcpToolCall(t, rig.s, rig.token, "get_asset", fmt.Sprintf(`{"id":%d}`, rig.ownAsset))
	if isErr || !strings.Contains(text, rig.ownDomain) {
		t.Fatalf("get_asset own: %v %s", isErr, text)
	}
	text, isErr = mcpToolCall(t, rig.s, rig.token, "get_asset", fmt.Sprintf(`{"id":%d}`, rig.otherAsset))
	if isErr {
		t.Fatalf("get_asset cross-task errored: %s", text)
	}
	if !strings.Contains(text, `"asset":null`) {
		t.Fatalf("get_asset cross-task returned a row: %s", text)
	}

	// list_scope: the task's own scope rows and rules.
	text, isErr = mcpToolCall(t, rig.s, rig.token, "list_scope", `{}`)
	if isErr {
		t.Fatalf("list_scope failed: %s", text)
	}
	var scope struct {
		Scope []struct {
			TaskID int64  `json:"task_id"`
			Domain string `json:"domain"`
		} `json:"scope"`
		Rules []struct {
			Pattern string `json:"pattern"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(text), &scope); err != nil {
		t.Fatalf("list_scope payload: %v (%s)", err, text)
	}
	if len(scope.Scope) != 1 || scope.Scope[0].Domain != rig.ownDomain || scope.Scope[0].TaskID != rig.own {
		t.Fatalf("list_scope rows: %s", text)
	}
	if len(scope.Rules) != 1 || !strings.Contains(scope.Rules[0].Pattern, rig.ownDomain) {
		t.Fatalf("list_scope rules: %s", text)
	}
}

func TestMCPRemediationReportScopedToTokenTask(t *testing.T) {
	rig := mcpRigFor(t)
	if _, err := rig.m.pg.Exec(`UPDATE tasks SET completed_at=now(), status='done',
remediation_for=now(), remediation_report='{"state":"ready","items":[]}'::jsonb
WHERE id IN ($1, $2)`, rig.own, rig.other); err != nil {
		t.Fatal(err)
	}

	const tool = "get_remediation_report"
	for _, tc := range []struct {
		name       string
		args       string
		wantReport bool
	}{
		{"default task", `{}`, true},
		{"explicit token task", fmt.Sprintf(`{"task_id":%d}`, rig.own), true},
		{"other task", fmt.Sprintf(`{"task_id":%d}`, rig.other), false},
		{"missing task", `{"task_id":-1}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, isErr := mcpToolCall(t, rig.s, rig.token, tool, tc.args)
			if isErr {
				t.Fatalf("%s failed: %s", tool, text)
			}
			if tc.wantReport {
				var report struct {
					State  string `json:"state"`
					TaskID int64  `json:"task_id"`
				}
				if err := json.Unmarshal([]byte(text), &report); err != nil {
					t.Fatalf("remediation report: %v (%s)", err, text)
				}
				if report.State != "ready" || report.TaskID != rig.own {
					t.Fatalf("expected ready report for task %d, got %s", rig.own, text)
				}
			} else if text != "{}" {
				t.Fatalf("mismatched task returned %s, want {}", text)
			}

			var count int
			if err := rig.m.pg.QueryRow(`SELECT count(*) FROM mcp_audit a
JOIN api_tokens t ON t.id=a.token_id
WHERE t.task_id=$1 AND a.tool=$2 AND a.args=$3::jsonb`, rig.own, tool, tc.args).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("audit rows for %s with %s: got %d, want 1", tool, tc.args, count)
			}
		})
	}
}

func TestMCPUnknownToolAndJWTRejected(t *testing.T) {
	rig := mcpRigFor(t)

	code, out := mcpPost(t, rig.s, rig.token,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_task","arguments":{}}}`)
	if code != 200 {
		t.Fatalf("unknown tool: HTTP %d %v", code, out)
	}
	rpcErr, _ := out["error"].(map[string]any)
	if rpcErr == nil || int(rpcErr["code"].(float64)) != rpcInvalidParams {
		t.Fatalf("unknown tool was not -32602: %v", out)
	}

	code, out = mcpPost(t, rig.s, rig.token, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	rpcErr, _ = out["error"].(map[string]any)
	if code != 200 || rpcErr == nil || int(rpcErr["code"].(float64)) != rpcMethodNotFound {
		t.Fatalf("unknown method was not -32601: %d %v", code, out)
	}

	// A valid admin JWT is not an API token.
	code, out = mcpPost(t, rig.s, rig.jwt, `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}`)
	if code != 401 {
		t.Fatalf("JWT was accepted: HTTP %d %v", code, out)
	}
	rpcErr, _ = out["error"].(map[string]any)
	if rpcErr == nil || int(rpcErr["code"].(float64)) != rpcUnauthorized {
		t.Fatalf("JWT refusal was not -32001: %v", out)
	}
}

func TestMCPAuditsEveryCall(t *testing.T) {
	rig := mcpRigFor(t)
	ctx := context.Background()

	var tokenID int64
	if err := rig.m.pg.QueryRow(`SELECT id FROM api_tokens WHERE task_id=$1`, rig.own).Scan(&tokenID); err != nil {
		t.Fatal(err)
	}
	before := mcpAuditCount(t, rig, tokenID)

	mcpPost(t, rig.s, rig.token, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if _, isErr := mcpToolCall(t, rig.s, rig.token, "list_assets", `{}`); isErr {
		t.Fatal("list_assets failed")
	}
	if _, isErr := mcpToolCall(t, rig.s, rig.token, "list_scope", `{}`); isErr {
		t.Fatal("list_scope failed")
	}

	if got := mcpAuditCount(t, rig, tokenID) - before; got != 2 {
		t.Fatalf("audit rows for two tools/call: %d", got)
	}
	rows, err := rig.m.pg.QueryContext(ctx, `SELECT tool, args::text FROM mcp_audit WHERE token_id=$1 ORDER BY id`, tokenID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tools []string
	for rows.Next() {
		var tool, args string
		if err := rows.Scan(&tool, &args); err != nil {
			t.Fatal(err)
		}
		tools = append(tools, tool)
		if args != "{}" {
			t.Fatalf("audit args for %s: %s", tool, args)
		}
	}
	if strings.Join(tools, ",") != "list_assets,list_scope" {
		t.Fatalf("audited tools: %v", tools)
	}
}

func mcpAuditCount(t *testing.T, rig *mcpRig, tokenID int64) int {
	t.Helper()
	var n int
	if err := rig.m.pg.QueryRow(`SELECT count(*) FROM mcp_audit WHERE token_id=$1`, tokenID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The limiter is per token and per minute: the 121st call inside the window is
// refused, and another token is unaffected.
func TestMCPRateLimiter(t *testing.T) {
	const a, b = int64(-901), int64(-902)
	for i := 0; i < mcpRateLimit; i++ {
		if !mcpAllow(a) {
			t.Fatalf("call %d was refused inside the window", i+1)
		}
	}
	if mcpAllow(a) {
		t.Fatal("the call past the limit was allowed")
	}
	if !mcpAllow(b) {
		t.Fatal("another token was refused because of the first")
	}
}

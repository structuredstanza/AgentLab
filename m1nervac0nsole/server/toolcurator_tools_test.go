package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	actool "github.com/structuredstanza/norma/tool"
)

// toolCuratorTool looks one tool curator tool up by name.
func toolCuratorTool(t *testing.T, s *Server, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range s.toolCuratorTools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("tool curator tool %s is not defined", name)
	return nil
}

// TestToolCuratorAgentSeededAndChatCapable proves the tool curator is a real
// built-in agent: its row is seeded, its prompt is the editable code default,
// and the generic conversation API accepts it as a chat agent.
func TestToolCuratorAgentSeededAndChatCapable(t *testing.T) {
	m, s, token := memoryTestServer(t)

	a, err := m.pg.GetAgentByKey(toolCuratorAgent)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("toolcurator agent is missing after seeding")
	}
	if a.Name != "Tool Curator" || a.Role != "assistant" || !a.Enabled {
		t.Errorf("toolcurator must be the enabled assistant \"Tool Curator\", got name=%q role=%q enabled=%v", a.Name, a.Role, a.Enabled)
	}
	markers := []string{"Tool Curator", "toolbox_list", "toolbox_validate", "toolbox_propose_template", "toolbox_propose_tool", "operator", "[install]", "[limits]"}
	want := agent.BuiltinPromptSeeds()[toolCuratorAgent]
	for _, marker := range markers {
		if !strings.Contains(want, marker) {
			t.Errorf("toolcurator code default prompt lost the %q contract marker", marker)
		}
	}
	got, err := m.pg.CurrentPrompt(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) == "" {
		t.Fatal("toolcurator has no prompt body: the agents screen would open an empty editor")
	}
	if !strings.Contains(got, "Tool Curator") || !strings.Contains(got, "toolbox_propose_template") {
		t.Errorf("stored toolcurator prompt is not the tool curation prompt: %.200q", got)
	}

	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/conversations", `{"agent_key":"toolcurator"}`)
	if code != http.StatusOK {
		t.Fatalf("starting a toolcurator conversation status=%d body=%v", code, out)
	}
	if out["agent_key"] != "toolcurator" {
		t.Fatalf("conversation did not resolve to the toolcurator: %v", out)
	}
	if id, _ := out["id"].(float64); id > 0 {
		t.Cleanup(func() { _ = m.pg.DeleteConversation(int64(id)) })
	}
}

// TestToolCuratorPromptRendersManifestPlaceholders: prompt bodies are Go
// templates, and the prompt teaches the manifest syntax ({{ params.x }}), so the
// default must render to the literal text instead of failing or evaluating it.
func TestToolCuratorPromptRendersManifestPlaceholders(t *testing.T) {
	out, err := renderPrompt(agent.BuiltinPromptSeeds()[toolCuratorAgent], nil, nil)
	if err != nil {
		t.Fatalf("toolcurator prompt does not render as a template: %v", err)
	}
	for _, lit := range []string{"{{ params.x }}", "{{ params.x | -flag }}", "{{ target.value }}", "{{ useragent }}", "{{ record.x? }}"} {
		if !strings.Contains(out, lit) {
			t.Errorf("rendered toolcurator prompt lost the literal %q", lit)
		}
	}
}

// TestToolCuratorToolsBoundOnlyToToolCurator is the security boundary of this
// slice: the tools are host tools added to EVERY agent's base list, so only the
// tools-table binding keeps them off every other agent. A host tool with no row
// passes through ToolResolve unfiltered, which is why the missing-row case fails
// the test too.
func TestToolCuratorToolsBoundOnlyToToolCurator(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	wireTools(m.pg, nil) // deterministic ToolResolve regardless of test order
	t.Cleanup(func() { agent.ToolResolve = nil })
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")
	ctx := context.Background()

	// SeedTool never rewrites an existing row's bindings (they are operator
	// state), so re-seed from scratch to read the bindings this code seeds.
	for _, key := range toolCuratorToolKeys {
		if _, err := m.pg.Exec(`DELETE FROM tools WHERE key=$1`, key); err != nil {
			t.Fatalf("clear %s: %v", key, err)
		}
	}
	s.seedToolCuratorTools()
	for _, key := range toolCuratorToolKeys {
		row, err := m.pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("tool curator tool %s has no tools row (a host tool with no row bypasses ToolResolve): %v", key, err)
		}
		if len(row.Agents) != 1 || row.Agents[0] != toolCuratorAgent {
			t.Fatalf("%s is bound to %v, want toolcurator alone", key, row.Agents)
		}
	}

	// hostTools() hands these to every agent; the binding must do the filtering.
	base := s.toolCuratorTools()
	if len(base) != len(toolCuratorToolKeys) {
		t.Fatalf("tool curator tool set has %d tools, want %d", len(base), len(toolCuratorToolKeys))
	}
	curator := toolNames(agent.ToolResolve(ctx, toolCuratorAgent, base))
	for _, key := range toolCuratorToolKeys {
		if !curator[key] {
			t.Errorf("toolcurator cannot call %s", key)
		}
	}
	for _, agentKey := range []string{"curator", "drafter", "auto", "worker", "planner", "pentest", "mainagent"} {
		got := toolNames(agent.ToolResolve(ctx, agentKey, base))
		for _, key := range toolCuratorToolKeys {
			if got[key] {
				t.Errorf("%s can call %s: the tools-table binding is the only thing keeping toolbox curation off other agents", agentKey, key)
			}
		}
	}
}

// TestToolboxProposeToolRejectsLikeTheHTTPHandler proves toolbox_propose_tool
// runs the same validation as POST /api/tools/custom: both go through
// createCustomTool, so a proposal can never store what the editor refuses. Every
// case returns before a database read, so no database is needed.
func TestToolboxProposeToolRejectsLikeTheHTTPHandler(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"bad-key", `{"key":"BadKey","description":"d","kind":"command","exec":{"command":"true"}}`, errCustomToolKeyFormat},
		{"bad-kind", `{"key":"goodkey","description":"d","kind":"bogus","exec":{"command":"true"}}`, errCustomToolKindInvalid},
		{"http-no-schema", `{"key":"goodkey","description":"d","kind":"http","exec":{"method":"GET","url":"http://x/{q}"}}`, errCustomToolHTTPSchemaRequired},
		{"http-empty-properties", `{"key":"goodkey","description":"d","kind":"http","exec":{"url":"http://x"},"schema":{"type":"object","properties":{}}}`, errCustomToolHTTPSchemaRequired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCustomToolServer()
			text, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_propose_tool"), c.body)
			if !isErr || !strings.Contains(text, c.want) {
				t.Fatalf("propose tool: isErr=%v text=%q, want an error containing %q", isErr, text, c.want)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/tools/custom", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			s.pgCreateCustomTool(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
				t.Fatalf("HTTP handler: status=%d body=%q, want 400 containing %q", rec.Code, rec.Body.String(), c.want)
			}
		})
	}

	// An absent exec is refused by the tool itself before the shared core.
	s := newCustomToolServer()
	text, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_propose_tool"), `{"key":"goodkey","description":"d","kind":"command"}`)
	if !isErr || !strings.Contains(text, "exec is required") {
		t.Fatalf("missing exec: isErr=%v text=%q", isErr, text)
	}
}

// TestToolboxProposeToolCreatesUnboundEnabledRow proves a successful proposal
// is a custom row (system=false), enabled, bound to no agent, and that a second
// proposal for the same key is refused.
func TestToolboxProposeToolCreatesUnboundEnabledRow(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	const key = "ctest_toolcurator_echo"
	cleanup := func() { _, _ = m.pg.Exec(`DELETE FROM tools WHERE key=$1`, key) }
	cleanup()
	t.Cleanup(cleanup)

	propose := toolCuratorTool(t, s, "toolbox_propose_tool")
	in := `{"key":"` + key + `","description":"ctest echo","kind":"command","exec":{"command":"echo {msg}"},` +
		`"schema":{"type":"object","properties":{"msg":{"type":"string"}}}}`
	if text, isErr := callCuratorTool(t, propose, in); isErr {
		t.Fatalf("proposal refused: %s", text)
	}
	row, err := m.pg.GetTool(key)
	if err != nil || row == nil {
		t.Fatalf("proposed tool row missing: %v", err)
	}
	if row.System || !row.Enabled || row.Kind != "command" {
		t.Errorf("proposed row system=%v enabled=%v kind=%q, want a custom enabled command tool", row.System, row.Enabled, row.Kind)
	}
	if row.Agents == nil || len(row.Agents) != 0 {
		t.Errorf("proposed tool is bound to %v, want no agent until the operator binds it", row.Agents)
	}
	if text, isErr := callCuratorTool(t, propose, in); !isErr || !strings.Contains(text, errCustomToolKeyExists) {
		t.Errorf("duplicate key: isErr=%v text=%q, want %q", isErr, text, errCustomToolKeyExists)
	}

	// The read tools see it: list by query, read in full.
	list, _ := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_list"), `{"q":"ctest echo"}`)
	if !strings.Contains(list, key) {
		t.Errorf("toolbox_list does not show the proposed tool: %s", list)
	}
	read, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_read"), `{"id":"`+key+`"}`)
	if isErr || !strings.Contains(read, "echo {msg}") {
		t.Errorf("toolbox_read of the proposed tool: isErr=%v %s", isErr, read)
	}
}

// TestToolboxValidateReportsWithoutSaving: toolbox_validate is the read-only
// dry run. A shipped manifest passes and shows its argv; broken TOML comes back
// as ok=false with the reason, not as a tool error. It needs no database.
func TestToolboxValidateReportsWithoutSaving(t *testing.T) {
	s := newCustomToolServer()
	validate := toolCuratorTool(t, s, "toolbox_validate")

	src, ok := manifest.BuiltinSource("httpx")
	if !ok {
		t.Fatal("no built-in httpx manifest to validate")
	}
	in, _ := json.Marshal(map[string]string{"toml": src})
	text, isErr := callCuratorTool(t, validate, string(in))
	if isErr {
		t.Fatalf("validate errored: %s", text)
	}
	var good struct {
		OK      bool     `json:"ok"`
		ID      string   `json:"id"`
		Program string   `json:"program"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal([]byte(text), &good); err != nil {
		t.Fatalf("validate reply is not JSON: %v: %s", err, text)
	}
	if !good.OK || good.ID != "httpx" || good.Program != "httpx" || len(good.Args) == 0 {
		t.Errorf("valid manifest reported as %+v", good)
	}

	text, isErr = callCuratorTool(t, validate, `{"toml":"id = \"x\"\nbogus_key = 1"}`)
	if isErr {
		t.Fatalf("invalid manifest must be reported in the reply, not as a tool error: %s", text)
	}
	var bad struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(text), &bad); err != nil {
		t.Fatalf("validate reply is not JSON: %v: %s", err, text)
	}
	if bad.OK || bad.Error == "" {
		t.Errorf("invalid manifest reported as %+v", bad)
	}
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

// drafterTool looks one drafter tool up by name.
func drafterTool(t *testing.T, s *Server, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range s.drafterTools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("drafter tool %s is not defined", name)
	return nil
}

// TestDrafterToolsBoundOnlyToDrafter is the security boundary of this slice:
// the drafter tools are host tools added to EVERY agent's base list, so only
// the tools-table binding keeps plan_context and propose_plan off worker,
// planner, auto and every other agent. A host tool with no row passes through
// ToolResolve unfiltered and reaches everyone, which is why the missing-row
// case fails the test too.
//
// list_tools is the exception: it is the manifest catalog the worker and the
// planner already hold, so the drafter is added to that binding instead of
// replacing it. A drafter-only row would take the manifest ids away from the
// agents that run them.
func TestDrafterToolsBoundOnlyToDrafter(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	wireTools(m.pg, nil) // deterministic ToolResolve regardless of test order
	t.Cleanup(func() { agent.ToolResolve = nil })
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")
	ctx := context.Background()

	// The agent row and its prompt are what let the chat page start a drafter
	// conversation at all; without them the tools would be unreachable.
	a, err := m.pg.GetAgentByKey("drafter")
	if err != nil || a == nil {
		t.Fatalf("drafter agent is missing after seeding: %v", err)
	}
	if a.Role != "assistant" || !a.Enabled {
		t.Errorf("drafter must be an enabled assistant, got role=%q enabled=%v", a.Role, a.Enabled)
	}
	for _, marker := range []string{"Plan drafter", "plan_context", "list_tools", "propose_plan", "inclusion"} {
		if !strings.Contains(agent.BuiltinPromptSeeds()["drafter"], marker) {
			t.Errorf("drafter code default prompt lost the %q contract marker", marker)
		}
	}

	// SeedTool never rewrites an existing row's bindings (they are operator
	// state), so re-seed from scratch: the assertion must read the bindings this
	// code seeds, not whatever an earlier run or a peer left in the shared DB.
	for _, key := range []string{"plan_context", "propose_plan"} {
		if _, err := m.pg.Exec(`DELETE FROM tools WHERE key=$1`, key); err != nil {
			t.Fatalf("clear %s: %v", key, err)
		}
	}
	s.seedDrafterTools()
	for _, key := range []string{"plan_context", "propose_plan"} {
		row, err := m.pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("drafter tool %s has no tools row (a host tool with no row bypasses ToolResolve): %v", key, err)
		}
		if len(row.Agents) != 1 || row.Agents[0] != "drafter" {
			t.Fatalf("%s is bound to %v, want drafter alone", key, row.Agents)
		}
	}
	row, err := m.pg.GetTool("list_tools")
	if err != nil || row == nil {
		t.Fatalf("list_tools has no tools row: %v", err)
	}
	if !contains(row.Agents, "drafter") {
		t.Fatalf("list_tools is bound to %v, want drafter among them", row.Agents)
	}

	// hostTools() hands these to every agent; the binding must do the filtering.
	base := s.drafterTools()
	if len(base) != len(drafterToolKeys) {
		t.Fatalf("drafter tool set has %d tools, want %d", len(base), len(drafterToolKeys))
	}

	drafter := toolNames(agent.ToolResolve(ctx, "drafter", base))
	for _, key := range drafterToolKeys {
		if !drafter[key] {
			t.Errorf("drafter cannot call %s", key)
		}
	}
	for _, agentKey := range []string{"worker", "planner", "auto", "pentest", "mainagent", "curator"} {
		got := toolNames(agent.ToolResolve(ctx, agentKey, base))
		for _, key := range []string{"plan_context", "propose_plan"} {
			if got[key] {
				t.Errorf("%s can call %s: the tools-table binding is the only thing keeping plan drafting off other agents", agentKey, key)
			}
		}
	}
}

// TestProposePlanRejectsInvalidProposal proves the validator is the gate: every
// problem comes back in one reply (so the model corrects them in one retry) and
// nothing is stored, because a draft row is what the operator would review.
func TestProposePlanRejectsInvalidProposal(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	task, err := m.pg.CreateTask("draft a plan", "gain admin", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })

	in := fmt.Sprintf(`{"task_id":%d,"proposal":{
		"summary":"",
		"goals":[{"ref":"g1","text":""}],
		"intents":[{"ref":"i1","summary":"","goal":"missing","asset_ids":[999999999]}],
		"hints":[{"text":""}],
		"scope":[{"effect":"maybe","kind":"nope","value":""}]}}`, task.ID)
	out, isErr := callCuratorTool(t, drafterTool(t, s, "propose_plan"), in)
	if !isErr {
		t.Fatalf("an invalid proposal was accepted: %s", out)
	}
	for _, want := range []string{
		"summary is empty",
		"goals[0].text is empty",
		"intents[0].summary is empty",
		`intents[0].goal "missing" is not a goal of this proposal`,
		"999999999, which is not an asset of this task",
		"hints[0].text is empty",
		`scope[0].effect is "maybe"`,
		`scope[0].kind is "nope"`,
		"scope[0].value is empty",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validation reply lost %q: %s", want, out)
		}
	}
	var n int
	if err := m.pg.QueryRow(`SELECT count(*) FROM plan_drafts WHERE task_id=$1`, task.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an invalid proposal stored %d drafts", n)
	}
}

// TestProposePlanStoresDraftAndFlagsInclude proves the write path: a valid
// proposal lands as the task's pending draft, an inclusion is flagged for the
// operator's approval, and no graph node is created - applying is the
// operator's action, not the assistant's.
func TestProposePlanStoresDraftAndFlagsInclude(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	ctx := context.Background()
	task, err := m.pg.CreateTask("draft a plan", "gain admin on the web tier", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })

	// plan_context is the read half: it must show the task, its scope, its
	// assets and the goals that already exist, so the draft avoids repeating
	// them and anchors intents to real asset ids.
	if _, err := m.pg.Exec(`INSERT INTO task_scope(task_id, kind, domain, source)
		VALUES ($1,'root_domain','plan-context.example','manual')`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: "plan-context.example", TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Assets().DeleteByHost("plan-context.example") })
	if _, err := m.pg.Exploration(task.ExplorationID).
		AddNode(db.KindGoal, map[string]any{"text": "existing goal"}, 0, "open", "human", nil); err != nil {
		t.Fatal(err)
	}
	out, isErr := callCuratorTool(t, drafterTool(t, s, "plan_context"), fmt.Sprintf(`{"task_id":%d}`, task.ID))
	if isErr {
		t.Fatalf("plan_context refused the task: %s", out)
	}
	for _, want := range []string{"gain admin on the web tier", "draft a plan", "plan-context.example", "existing goal"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan_context lost %q: %s", want, out)
		}
	}

	assets, err := m.pg.Assets().QueryByTask(task.ID, "", 10, 0)
	if err != nil || len(assets) == 0 {
		t.Fatalf("the task has no asset to anchor an intent to: %v", err)
	}
	var before int
	if err := m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, task.ExplorationID).Scan(&before); err != nil {
		t.Fatal(err)
	}

	in := fmt.Sprintf(`{"task_id":%d,"proposal":{
		"summary":"Map the web tier, then test the login.",
		"goals":[{"ref":"g1","text":"Map every HTTP service"},{"ref":"g2","text":"Prove SQL injection in the login"}],
		"intents":[
			{"ref":"i1","summary":"Fingerprint the web tier","goal":"g1","asset_ids":[%d]},
			{"ref":"i2","summary":"Test the login form","goal":"g2","depends_on":["i1"]}],
		"hints":[{"text":"Stay under 5 requests per second","rule":true}],
		"scope":[{"effect":"include","kind":"root_domain","value":"vendor.example","note":"new vendor domain"}]}}`,
		task.ID, assets[0].ID)
	out, isErr = callCuratorTool(t, drafterTool(t, s, "propose_plan"), in)
	if isErr {
		t.Fatalf("a valid proposal was refused: %s", out)
	}
	var reply struct {
		DraftID      int64  `json:"draft_id"`
		Summary      string `json:"summary"`
		Goals        int    `json:"goals"`
		Intents      int    `json:"intents"`
		Hints        int    `json:"hints"`
		Scope        int    `json:"scope"`
		NeedsInclude bool   `json:"needs_include_approval"`
	}
	if err := json.Unmarshal([]byte(out), &reply); err != nil {
		t.Fatalf("reply is not JSON: %v (%s)", err, out)
	}
	if reply.DraftID <= 0 || reply.Summary == "" ||
		reply.Goals != 2 || reply.Intents != 2 || reply.Hints != 1 || reply.Scope != 1 {
		t.Fatalf("reply = %+v", reply)
	}
	if !reply.NeedsInclude {
		t.Fatalf("a scope inclusion did not set needs_include_approval: %s", out)
	}
	draft, err := m.pg.GetPlanDraft(ctx, reply.DraftID)
	if err != nil || draft == nil {
		t.Fatalf("draft %d was not stored: %v", reply.DraftID, err)
	}
	if draft.TaskID != task.ID || draft.Status != "draft" || draft.Summary != "Map the web tier, then test the login." {
		t.Fatalf("stored draft = %+v", draft)
	}
	var after int
	if err := m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, task.ExplorationID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("propose_plan wrote %d graph nodes; it must only store the draft", after-before)
	}
}

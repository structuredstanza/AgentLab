package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

// callCuratorTool runs one host tool and returns its text plus the error flag.
func callCuratorTool(t *testing.T, tool actool.CoreTool, in string) (string, bool) {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(in), nil)
	if err != nil {
		t.Fatalf("%s returned a Go error: %v", tool.Name(), err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
	}
	return b.String(), res.IsError
}

// curatorTool looks one curator tool up by name.
func curatorTool(t *testing.T, s *Server, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range s.curatorTools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("curator tool %s is not defined", name)
	return nil
}

func toolNames(tools []actool.CoreTool) map[string]bool {
	out := make(map[string]bool, len(tools))
	for _, t := range tools {
		out[t.Name()] = true
	}
	return out
}

// TestCuratorAgentSeededAndChatCapable proves the curator is a real built-in
// agent: its row is seeded, its prompt is the editable code default, and the
// generic conversation API accepts it as a chat agent.
func TestCuratorAgentSeededAndChatCapable(t *testing.T) {
	m, s, token := memoryTestServer(t)

	a, err := m.pg.GetAgentByKey("curator")
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("curator agent is missing after seeding")
	}
	if a.Role != "assistant" || !a.Enabled {
		t.Errorf("curator must be an enabled assistant, got role=%q enabled=%v", a.Role, a.Enabled)
	}
	// The prompt body is operator-editable, so equality with the code default is
	// the wrong invariant on a database an operator may have edited. What must
	// hold is that the curator has a body of its own that states the job.
	want := agent.BuiltinPromptSeeds()["curator"]
	if want == "" {
		t.Fatal("no curator prompt is seeded by the code default")
	}
	for _, marker := range []string{"Curator", "memory_propose", "operator"} {
		if !strings.Contains(want, marker) {
			t.Errorf("curator code default prompt lost the %q contract marker", marker)
		}
	}
	got, err := m.pg.CurrentPrompt(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) == "" {
		t.Fatal("curator has no prompt body: the agents screen would open an empty editor")
	}
	for _, marker := range []string{"Curator", "memory_propose"} {
		if !strings.Contains(got, marker) {
			t.Errorf("stored curator prompt is not the curation prompt (missing %q): %.200q", marker, got)
		}
	}

	code, out := memoryAPI(t, s, token, http.MethodPost, "/api/conversations", `{"agent_key":"curator"}`)
	if code != http.StatusOK {
		t.Fatalf("starting a curator conversation status=%d body=%v", code, out)
	}
	if out["agent_key"] != "curator" {
		t.Fatalf("conversation did not resolve to the curator: %v", out)
	}
	if id, _ := out["id"].(float64); id > 0 {
		t.Cleanup(func() { _ = m.pg.DeleteConversation(int64(id)) })
	}
}

// TestCuratorToolsBoundOnlyToCurator is the security boundary of this slice:
// the curator tools are host tools added to EVERY agent's base list, so only the
// tools-table binding keeps them off worker, planner, auto and every other
// agent. A host tool with no row passes through ToolResolve unfiltered and
// reaches everyone, which is why the missing-row case fails the test too.
func TestCuratorToolsBoundOnlyToCurator(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	wireTools(m.pg, nil) // deterministic ToolResolve regardless of test order
	t.Cleanup(func() { agent.ToolResolve = nil })
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")
	ctx := context.Background()

	// SeedTool never rewrites an existing row's bindings (they are operator
	// state), so re-seed from scratch: the assertion must read the bindings this
	// code seeds, not whatever an earlier run or a peer left in the shared DB.
	for _, key := range curatorToolKeys {
		if _, err := m.pg.Exec(`DELETE FROM tools WHERE key=$1`, key); err != nil {
			t.Fatalf("clear %s: %v", key, err)
		}
	}
	s.seedCuratorTools()
	for _, key := range curatorToolKeys {
		row, err := m.pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("curator tool %s has no tools row (a host tool with no row bypasses ToolResolve): %v", key, err)
		}
		if len(row.Agents) != 1 || row.Agents[0] != "curator" {
			t.Fatalf("%s is bound to %v, want curator alone", key, row.Agents)
		}
	}

	// hostTools() hands these to every agent; the binding must do the filtering.
	base := s.curatorTools()
	if len(base) != len(curatorToolKeys) {
		t.Fatalf("curator tool set has %d tools, want %d", len(base), len(curatorToolKeys))
	}

	curator := toolNames(agent.ToolResolve(ctx, "curator", base))
	for _, key := range curatorToolKeys {
		if !curator[key] {
			t.Errorf("curator cannot call %s", key)
		}
	}
	for _, agentKey := range []string{"worker", "planner", "auto", "pentest", "mainagent"} {
		got := toolNames(agent.ToolResolve(ctx, agentKey, base))
		for _, key := range curatorToolKeys {
			if got[key] {
				t.Errorf("%s can call %s: the tools-table binding is the only thing keeping curation off other agents", agentKey, key)
			}
		}
	}
}

// TestMemoryProposeWritesTaskCandidateOnly proves the write path: a proposal
// lands as a task-scoped candidate with source "agent" (so it is scrubbed and
// generalised like an agent write), and every wider or stronger write is
// refused with a message that tells the model to let the operator promote.
func TestMemoryProposeWritesTaskCandidateOnly(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'ctest%'`) }()

	task, err := m.CreateTaskWithOptions("ctest curator propose", "curate operational memory", db.TaskCreateOptions{Name: "ctest propose"})
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()

	propose := curatorTool(t, s, "memory_propose")
	text, isErr := callCuratorTool(t, propose, `{"task_id":`+task.ID+
		`,"kind":"technique","title":"ctest path traversal in a file-download servlet",`+
		`"body":"The servlet passes a request path to the filesystem without canonicalisation, so ../ reads outside the web root.","tags":["web"]}`)
	if isErr {
		t.Fatalf("proposal refused: %s", text)
	}
	var out struct {
		Entry struct {
			ID      int64  `json:"id"`
			Scope   string `json:"scope"`
			Status  string `json:"status"`
			Source  string `json:"source"`
			TaskID  int64  `json:"task_id"`
			Title   string `json:"title"`
			Version string `json:"-"`
		} `json:"entry"`
		Redactions int `json:"redactions"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("proposal reply is not JSON (%v): %s", err, text)
	}
	if out.Entry.Scope != "task" || out.Entry.Status != "candidate" || out.Entry.Source != "agent" {
		t.Errorf("proposal must be a task candidate written by an agent, got scope=%q status=%q source=%q",
			out.Entry.Scope, out.Entry.Status, out.Entry.Source)
	}
	if out.Entry.TaskID != taskID {
		t.Errorf("candidate task_id=%d want %d", out.Entry.TaskID, taskID)
	}

	for _, bad := range []struct{ name, in, want string }{
		{"global scope", `{"task_id":` + task.ID + `,"kind":"technique","title":"ctest global attempt","body":"b","scope":"global"}`, "task-scoped candidates only"},
		{"adopted status", `{"task_id":` + task.ID + `,"kind":"technique","title":"ctest adopted attempt","body":"b","status":"adopted"}`, "candidates only"},
	} {
		msg, isErr := callCuratorTool(t, propose, bad.in)
		if !isErr {
			t.Errorf("%s was accepted: %s", bad.name, msg)
			continue
		}
		if !strings.Contains(msg, bad.want) || !strings.Contains(msg, "operator") {
			t.Errorf("%s refusal should explain that the operator promotes: %q", bad.name, msg)
		}
	}
	var leaked int
	if err := m.pg.QueryRow(`SELECT count(*) FROM knowledge_entries WHERE title LIKE 'ctest%attempt'`).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Errorf("a refused proposal was written anyway (%d rows)", leaked)
	}
}

// TestMemorySearchWithoutTaskContext proves the curator reads across tasks: a
// task-less chat has no task id, which is precisely what the task-bound agent
// memory tools refuse on (agent/tools_memory.go memGuard). The operator-wide
// search sees every task's candidates; the task lens sees only what that task
// may see.
func TestMemorySearchWithoutTaskContext(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'ctest%'`) }()
	ctx := context.Background()

	taskA, err := m.CreateTaskWithOptions("ctest curator search a", "probe the invoice upload", db.TaskCreateOptions{Name: "ctest alpha"})
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := strconv.ParseInt(taskA.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(aID) }()
	taskB, err := m.CreateTaskWithOptions("ctest curator search b", "probe the invoice upload", db.TaskCreateOptions{Name: "ctest beta"})
	if err != nil {
		t.Fatal(err)
	}
	bID, _ := strconv.ParseInt(taskB.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(bID) }()

	for _, in := range []db.KnowledgeInput{
		{Scope: "global", Kind: "technique", Title: "ctest global adopted rule", Body: "an adopted rule every task sees", Source: "operator", Status: "adopted"},
		{Scope: "task", TaskID: aID, Kind: "technique", Title: "ctest alpha candidate", Body: "learned in task alpha", Source: "agent"},
		{Scope: "task", TaskID: bID, Kind: "technique", Title: "ctest beta candidate", Body: "learned in task beta", Source: "agent"},
	} {
		if _, _, err := m.pg.AddKnowledge(ctx, in); err != nil {
			t.Fatalf("seed %s: %v", in.Title, err)
		}
	}

	search := curatorTool(t, s, "memory_search")
	wide, isErr := callCuratorTool(t, search, `{"q":"ctest"}`)
	if isErr {
		t.Fatalf("task-less search refused: %s", wide)
	}
	for _, want := range []string{"ctest global adopted rule", "ctest alpha candidate", "ctest beta candidate"} {
		if !strings.Contains(wide, want) {
			t.Errorf("operator-wide search missed %q: %s", want, wide)
		}
	}

	lens, isErr := callCuratorTool(t, search, `{"q":"ctest","task_id":`+taskA.ID+`}`)
	if isErr {
		t.Fatalf("task-lens search refused: %s", lens)
	}
	if !strings.Contains(lens, "ctest alpha candidate") {
		t.Errorf("task lens missed the task's own candidate: %s", lens)
	}
	if strings.Contains(lens, "ctest beta candidate") {
		t.Errorf("another task's candidate leaked through the task lens: %s", lens)
	}

	// The contrast: the task-bound agent memory tool cannot run here at all.
	ts := agent.NewToolSet(nil, "curator-test")
	ts.SetMemory(m.pg)
	var recall actool.CoreTool
	for _, tool := range ts.WorkerTools() {
		if tool.Name() == "recall" {
			recall = tool
		}
	}
	if recall == nil {
		t.Fatal("worker tool set no longer carries recall")
	}
	msg, isErr := callCuratorTool(t, recall, `{"query":"ctest"}`)
	if !isErr || !strings.Contains(msg, "task context") {
		t.Errorf("recall without a task should refuse with a task-context message, got isErr=%v %q", isErr, msg)
	}
}

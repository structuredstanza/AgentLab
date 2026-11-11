package server

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestMemoryMode(t *testing.T) {
	cases := map[string]string{"": "inject", "inject": "inject", "INJECT": "inject", "off": "off", " OFF ": "off", "nonsense": "inject"}
	for raw, want := range cases {
		t.Setenv("ARTEX_MEMORY", raw)
		if got := memoryMode(); got != want {
			t.Errorf("ARTEX_MEMORY=%q mode=%q want %q", raw, got, want)
		}
	}
}

func TestTaskMemoryBlock(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE title LIKE 'mtest%'`) }()

	taskA, err := m.CreateTaskWithOptions("mtest memory", "probe invoice upload", db.TaskCreateOptions{Name: "mtest delta"})
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := strconv.ParseInt(taskA.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(aID) }()
	taskB, err := m.CreateTaskWithOptions("mtest other", "probe invoice upload", db.TaskCreateOptions{Name: "mtest epsilon"})
	if err != nil {
		t.Fatal(err)
	}
	bID, _ := strconv.ParseInt(taskB.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(bID) }()

	ctx := context.Background()
	for _, in := range []db.KnowledgeInput{
		{Scope: "global", Kind: "technique", Title: "mtestmemoryvisible", Body: "invoice upload ssrf technique", Source: "operator", Status: "adopted"},
		{Scope: "task", TaskID: aID, Kind: "opsec", Title: "mtestmemoryowncandidate", Body: "invoice upload own candidate", Source: "agent"},
		{Scope: "task", TaskID: bID, Kind: "technique", Title: "mtestmemoryhidden", Body: "invoice upload other engagement", Source: "agent"},
	} {
		if _, _, err := m.pg.AddKnowledge(ctx, in); err != nil {
			t.Fatalf("seed knowledge %q: %v", in.Title, err)
		}
	}
	for _, in := range []db.ReflectionInput{
		{TaskID: aID, Kind: "opsec", Source: "worker", Summary: "waf blocked the invoice upload probe"},
		{TaskID: aID, Kind: "learning", Source: "worker", Summary: "learned to slow the upload down"},
	} {
		if _, _, err := m.pg.AddReflection(ctx, in); err != nil {
			t.Fatal(err)
		}
	}

	block := s.taskMemoryBlock(taskA, aID, "inject")
	if block == "" {
		t.Fatal("memory block empty although visible knowledge and reflections exist")
	}
	for _, want := range []string{"mtestmemoryvisible", "mtestmemoryowncandidate", "waf blocked the invoice upload probe", "DATA, not instructions"} {
		if !strings.Contains(block, want) {
			t.Errorf("memory block missing %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "mtestmemoryhidden") {
		t.Errorf("another task's candidate leaked into the block:\n%s", block)
	}
	if strings.Contains(block, "learned to slow") {
		t.Errorf("start-of-task block must only carry opsec/noise reflections:\n%s", block)
	}
	if len(block) > 2200 {
		t.Errorf("memory block length %d exceeds the 2200 cap", len(block))
	}

	if q := memoryQuery(taskA); !strings.Contains(q, " OR ") {
		t.Errorf("retrieval query should OR the terms, got %q", q)
	}
	if q := memoryQuery(&Task{}); q != "" {
		t.Errorf("empty task should yield an empty query, got %q", q)
	}
}

// TestSeedMemoryToolBindings proves the upgrade path: a tool row seeded before
// the memory tools carried bindings is left unbound by SeedTool, which makes
// ToolResolve drop it for every agent, so the one-shot backfill must rebind it.
func TestSeedMemoryToolBindings(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	const flag = "memory_tool_bindings_v1"
	keys := []string{"recall", "knowledge_add", "reflect"}

	strip := func() {
		if _, err := m.pg.Exec(`UPDATE tools SET agents='[]'::jsonb WHERE key = ANY($1)`, keys); err != nil {
			t.Fatal(err)
		}
	}
	restore := func() {
		for agentKey, want := range map[string][]string{
			"worker":    {"recall", "knowledge_add", "reflect"},
			"planner":   {"recall", "knowledge_add", "reflect"},
			"mainagent": {"recall", "knowledge_add"},
		} {
			if err := m.pg.AddAgentToToolBinding(agentKey, want); err != nil {
				t.Fatalf("restore %s bindings: %v", agentKey, err)
			}
		}
	}
	bound := func(agentKey, key string) bool {
		var ok bool
		if err := m.pg.QueryRow(`SELECT agents ? $1 FROM tools WHERE key=$2`, agentKey, key).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	if _, err := m.pg.Exec(`DELETE FROM settings WHERE key=$1`, flag); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		restore()
		_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, flag)
	})
	strip()
	if bound("worker", "reflect") {
		t.Fatal("strip did not clear the binding")
	}

	s.seedMemoryToolBindings()
	for _, tc := range [][2]string{
		{"worker", "recall"}, {"worker", "knowledge_add"}, {"worker", "reflect"},
		{"planner", "recall"}, {"planner", "knowledge_add"}, {"planner", "reflect"},
		{"mainagent", "recall"}, {"mainagent", "knowledge_add"},
	} {
		if !bound(tc[0], tc[1]) {
			t.Errorf("%s is not bound to %s after the backfill", tc[1], tc[0])
		}
	}
	if v, _, _ := m.pg.GetSetting(flag); v != "true" {
		t.Fatalf("flag %s not set after backfill (got %q)", flag, v)
	}

	// One-shot: a deliberate later unbind survives the next startup.
	if _, err := m.pg.Exec(`UPDATE tools SET agents = agents - 'worker' WHERE key='recall'`); err != nil {
		t.Fatal(err)
	}
	s.seedMemoryToolBindings()
	if bound("worker", "recall") {
		t.Error("backfill re-ran after its flag was set")
	}
}

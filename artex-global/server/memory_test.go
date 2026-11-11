package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/artex-global/db"
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

// TestEnvironmentKnowledgeAlwaysInBlock: an adopted environment entry describes
// the platform, not the target, so it reaches a task whose name and goal share
// no term with it.
func TestEnvironmentKnowledgeAlwaysInBlock(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	task, err := m.CreateTaskWithOptions("mtestenv task", "audit the billing portal",
		db.TaskCreateOptions{Name: "mtestenv zeta"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(id) }()

	ctx := context.Background()
	entry, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{
		Scope: "environment", Kind: "opsec", Source: "operator", Status: "adopted",
		Title: "proxy answers CONNECT before dialling",
		Body:  "a port-open reading through a proxy is an artefact of a 200 reply",
		Tags:  []string{"env:test-deployment"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, entry.ID) }()

	// The fixture must be term-disjoint from the task, or the test would pass
	// for the wrong reason.
	taskTerms := map[string]bool{}
	for _, term := range db.MemoryTokens(task.Name + " " + task.Goal) {
		taskTerms[term] = true
	}
	for _, term := range db.MemoryTokens(entry.Title + " " + entry.Body) {
		if taskTerms[term] {
			t.Fatalf("environment fixture shares the term %q with the task query %q", term, memoryQuery(task))
		}
	}

	block := s.taskMemoryBlock(task, id, "inject")
	if !strings.Contains(block, entry.Title) {
		t.Fatalf("adopted environment entry missing from the start-of-task block:\n%s", block)
	}
	if !strings.Contains(block, "env:test-deployment") {
		t.Errorf("environment tag missing from the block:\n%s", block)
	}
	if len(block) > memoryStartMaxChars {
		t.Errorf("block length %d exceeds the %d cap", len(block), memoryStartMaxChars)
	}
}

// TestRoundMemoryProviderRefreshesKnowledge: the per-round provider re-selects
// the task's knowledge, so a lesson written mid-task reaches the next round
// instead of waiting for the next task.
func TestRoundMemoryProviderRefreshesKnowledge(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	task, err := m.CreateTaskWithOptions("mtestround task", "audit the billing portal",
		db.TaskCreateOptions{Name: "mtestround zeta"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(id) }()

	ctx := context.Background()
	provider := s.memoryProvider(task, id)
	if block := provider(ctx); strings.Contains(block, "session key rotation") {
		t.Fatalf("knowledge appeared before it was written:\n%s", block)
	}

	if _, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{
		TaskID: id, Kind: "technique", Source: "agent",
		Title: "session key rotation on logout",
		Body:  "the logout handler rotates the session key without invalidating the old one",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.pg.AddReflection(ctx, db.ReflectionInput{
		TaskID: id, Kind: "lookfor", Source: "worker",
		Summary: "try the password reset token twice",
	}); err != nil {
		t.Fatal(err)
	}

	block := provider(ctx)
	if !strings.Contains(block, "session key rotation") {
		t.Fatalf("knowledge written mid-task did not reach the round block:\n%s", block)
	}
	if !strings.Contains(block, "try the password reset token twice") {
		t.Fatalf("reflection missing from the round block:\n%s", block)
	}
	if max := memoryRoundKnowledgeChars + memoryRoundReflectionChars + 2; len(block) > max {
		t.Errorf("round block length %d exceeds the %d budget", len(block), max)
	}
}

// usageCount runs one count query against the ledger.
func usageCount(t *testing.T, m *Manager, query string, args ...any) int {
	t.Helper()
	var n int
	if err := m.pg.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// memoryPreviewTask seeds one task with a visible knowledge entry and one
// reflection, both matching the task's wording, and returns the ids.
func memoryPreviewTask(t *testing.T, m *Manager) (*Task, int64, int64) {
	t.Helper()
	task, err := m.CreateTaskWithOptions("mtestusage task", "audit the billing portal",
		db.TaskCreateOptions{Name: "mtestusage zeta"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(id) })

	ctx := context.Background()
	entry, _, err := m.pg.AddKnowledge(ctx, db.KnowledgeInput{
		TaskID: id, Kind: "technique", Source: "agent",
		Title: "billing portal replay lesson",
		Body:  "replay the billing portal upload slowly, one request per round",
	})
	if err != nil {
		t.Fatal(err)
	}
	refl, _, err := m.pg.AddReflection(ctx, db.ReflectionInput{
		TaskID: id, Kind: "opsec", Source: "worker",
		Summary: "the billing portal waf blocked the fast replay",
	})
	if err != nil {
		t.Fatal(err)
	}
	return task, entry.ID, refl.ID
}

// The two prompt-build read paths write their own surface into the ledger, with
// one row per knowledge entry they showed.
func TestMemoryBlocksRecordUsage(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	task, entryID, _ := memoryPreviewTask(t, m)
	id, _ := strconv.ParseInt(task.ID, 10, 64)

	if block := s.taskMemoryBlock(task, id, "inject"); !strings.Contains(block, "billing portal replay lesson") {
		t.Fatalf("start block missing the seeded lesson:\n%s", block)
	}
	if n := usageCount(t, m, `SELECT count(*) FROM knowledge_usage
		WHERE task_id=$1 AND surface='task_start' AND knowledge_id=$2`, id, entryID); n != 1 {
		t.Errorf("task_start rows for the seeded entry = %d, want 1", n)
	}

	ctx := context.Background()
	if block := s.memoryProvider(task, id)(ctx); !strings.Contains(block, "billing portal replay lesson") {
		t.Fatalf("round block missing the seeded lesson:\n%s", block)
	}
	if n := usageCount(t, m, `SELECT count(*) FROM knowledge_usage
		WHERE task_id=$1 AND surface='round' AND knowledge_id=$2`, id, entryID); n != 1 {
		t.Errorf("round rows for the seeded entry = %d, want 1", n)
	}

	var recorded int64
	if err := m.pg.QueryRow(`SELECT knowledge_id FROM knowledge_usage
		WHERE task_id=$1 AND surface='task_start'`, id).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != entryID {
		t.Errorf("task_start row names entry %d, want %d", recorded, entryID)
	}

	// A ledger write that fails (unknown entry: FK violation) is swallowed;
	// the prompt build that follows still renders.
	s.recordKnowledgeUsage(ctx, id, "round", []db.KnowledgeHit{{KnowledgeEntry: db.KnowledgeEntry{ID: 1 << 50}}})
	if block := s.taskMemoryBlock(task, id, "inject"); block == "" {
		t.Fatal("a failed ledger write broke the prompt build")
	}
}

// The operator preview renders what the task would be injected with and writes
// no ledger rows: looking is not reading.
func TestMemoryPreviewRendersWithoutUsage(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	task, entryID, reflID := memoryPreviewTask(t, m)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Setenv("ARTEX_MEMORY", "inject")

	req := httptest.NewRequest(http.MethodGet, "/api/memory/preview?task_id="+task.ID, nil)
	rec := httptest.NewRecorder()
	s.memoryPreview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Mode          string  `json:"mode"`
		StartBlock    string  `json:"start_block"`
		RoundBlock    string  `json:"round_block"`
		KnowledgeIDs  []int64 `json:"knowledge_ids"`
		ReflectionIDs []int64 `json:"reflection_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	if out.Mode != "inject" {
		t.Errorf("mode = %q, want inject", out.Mode)
	}
	if !strings.Contains(out.StartBlock, "billing portal replay lesson") {
		t.Errorf("start block missing the seeded lesson:\n%s", out.StartBlock)
	}
	if !strings.Contains(out.RoundBlock, "billing portal replay lesson") {
		t.Errorf("round block missing the seeded lesson:\n%s", out.RoundBlock)
	}
	if len(out.KnowledgeIDs) == 0 || out.KnowledgeIDs[0] != entryID {
		t.Errorf("knowledge_ids = %v, want the seeded entry %d", out.KnowledgeIDs, entryID)
	}
	if len(out.ReflectionIDs) == 0 || out.ReflectionIDs[0] != reflID {
		t.Errorf("reflection_ids = %v, want the seeded reflection %d", out.ReflectionIDs, reflID)
	}
	if n := usageCount(t, m, `SELECT count(*) FROM knowledge_usage WHERE task_id=$1`, id); n != 0 {
		t.Fatalf("preview wrote %d usage rows, want none", n)
	}

	// With injection off nothing is injected, so the preview shows nothing and
	// still records nothing.
	t.Setenv("ARTEX_MEMORY", "off")
	rec = httptest.NewRecorder()
	s.memoryPreview(rec, httptest.NewRequest(http.MethodGet, "/api/memory/preview?task_id="+task.ID, nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	if out.Mode != "off" || out.StartBlock != "" || out.RoundBlock != "" || len(out.KnowledgeIDs) != 0 {
		t.Errorf("off preview = %+v, want empty blocks and ids", out)
	}
	if n := usageCount(t, m, `SELECT count(*) FROM knowledge_usage WHERE task_id=$1`, id); n != 0 {
		t.Fatalf("preview with injection off wrote %d usage rows, want none", n)
	}
}

// The usage endpoint reports one entry's hit count, last read and newest rows.
func TestKnowledgeUsageEndpoint(t *testing.T) {
	m, s, _ := memoryTestServer(t)
	task, entryID, _ := memoryPreviewTask(t, m)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if err := m.pg.RecordKnowledgeUsage(context.Background(), id, "recall", []int64{entryID}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/knowledge/"+strconv.FormatInt(entryID, 10)+"/usage", nil)
	req.SetPathValue("id", strconv.FormatInt(entryID, 10))
	rec := httptest.NewRecorder()
	s.knowledgeUsage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("usage status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Hits     int    `json:"hits"`
		LastUsed string `json:"last_used"`
		Usage    []struct {
			TaskID  int64  `json:"task_id"`
			Surface string `json:"surface"`
			ShownAt string `json:"shown_at"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	if out.Hits != 1 || len(out.Usage) != 1 {
		t.Fatalf("usage = %+v, want one hit and one row", out)
	}
	if _, err := time.Parse(time.RFC3339, out.LastUsed); err != nil {
		t.Errorf("last_used = %q, want RFC3339: %v", out.LastUsed, err)
	}
	if out.Usage[0].Surface != "recall" || out.Usage[0].TaskID != id {
		t.Errorf("usage row = %+v, want recall on task %d", out.Usage[0], id)
	}
	if _, err := time.Parse(time.RFC3339, out.Usage[0].ShownAt); err != nil {
		t.Errorf("shown_at = %q, want RFC3339: %v", out.Usage[0].ShownAt, err)
	}

	// An entry nothing has read reports an empty last_used, not a zero time.
	unread, _, err := m.pg.AddKnowledge(context.Background(), db.KnowledgeInput{
		TaskID: id, Kind: "note", Title: "unread usage entry", Body: "never shown", Source: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/knowledge/"+strconv.FormatInt(unread.ID, 10)+"/usage", nil)
	req.SetPathValue("id", strconv.FormatInt(unread.ID, 10))
	rec = httptest.NewRecorder()
	s.knowledgeUsage(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	if out.Hits != 0 || out.LastUsed != "" || len(out.Usage) != 0 {
		t.Errorf("unread usage = %+v, want zero hits and empty last_used", out)
	}
}

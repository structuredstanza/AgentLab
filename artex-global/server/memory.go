package server

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/artex-global/agent"
	"github.com/structuredstanza/AgentLab/artex-global/db"
)

// Memory block budgets. The start-of-task block is the big one; the per-round
// block is refreshed every round, so it is smaller and split between the
// knowledge half and the reflections half.
const (
	memoryStartMaxChars = 2200
	// memoryRoundKnowledgeChars / memoryRoundReflectionChars split the
	// per-round budget, so the knowledge half cannot squeeze the reflections
	// out.
	memoryRoundKnowledgeChars  = 700
	memoryRoundReflectionChars = 500
	// memoryTargetHits is how many name/goal matches the start block shows.
	memoryTargetHits = 4
	// memoryEnvironmentHits caps adopted environment entries so they cannot
	// crowd out target knowledge, and memoryEnvironmentBodyRunes bounds one.
	memoryEnvironmentHits      = 2
	memoryEnvironmentBodyRunes = 400
	// memoryRoundOwnHits / memoryRoundBodyRunes bound the per-round knowledge
	// half: the task's newest entries, clipped to leave room for reflections.
	memoryRoundOwnHits   = 2
	memoryRoundBodyRunes = 250
)

// memoryMode reads the knowledge/reflection injection switch:
//
//	off     no selection, no prompt change
//	inject  select, log, and append the rendered block (default)
//
// Like rsiLessonsMode it is read per task-bundle build, so changing it needs a
// new task or a task-agent invalidation, not a restart.
func memoryMode() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ARTEX_MEMORY")), "off") {
		return "off"
	}
	return "inject"
}

// bindTaskMemory attaches the memory store and, unless injection is off, the
// per-round memory provider to one task's planner and worker. Both are bound
// per task because the provider only ever reads that task's memory: it never
// crosses an engagement boundary. The store is bound even with injection off,
// so the recall/knowledge_add/reflect tools stay available.
func (s *Server) bindTaskMemory(t *Task, wk *agent.Worker, pl *agent.Planner, mode string) {
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return
	}
	pg := s.m.PG()
	wk.SetMemory(pg)
	pl.SetMemory(pg)
	if mode == "off" {
		return
	}
	provider := s.memoryProvider(t, taskID)
	wk.SetReflectionsProvider(provider)
	pl.SetReflectionsProvider(provider)
}

// memoryProvider is the per-round memory block, on the same provider hook that
// used to carry reflections alone: the task's newest knowledge plus the latest
// reflections, so a lesson written mid-task reaches the next round instead of
// waiting for the next task. Environment and goal-matched knowledge are stable
// and already in the start-of-task block, so they are not repeated here.
func (s *Server) memoryProvider(t *Task, taskID int64) func(context.Context) string {
	pg := s.m.PG()
	return func(ctx context.Context) string {
		refl, err := pg.ListReflections(ctx, taskID, nil, 6)
		if err != nil {
			log.Printf("[memory] reflections provider failed for task %s: %v", t.ID, err)
			refl = nil
		}
		parts := make([]string, 0, 2)
		if block := db.RenderMemory(s.roundKnowledge(ctx, t, taskID), nil, memoryRoundKnowledgeChars); block != "" {
			parts = append(parts, block)
		}
		if block := db.RenderReflections(refl, memoryRoundReflectionChars); block != "" {
			parts = append(parts, block)
		}
		return strings.Join(parts, "\n")
	}
}

// roundKnowledge is the knowledge half of the per-round block: the task's own
// newest entries, whatever their wording, so a lesson the agent just wrote is
// shown again. Bodies are clipped because the per-round budget is small.
func (s *Server) roundKnowledge(ctx context.Context, t *Task, taskID int64) []db.KnowledgeHit {
	entries, err := s.m.PG().ListKnowledge(ctx, db.KnowledgeFilter{
		TaskID: taskID, Scope: "task", Limit: memoryRoundOwnHits,
	})
	if err != nil {
		log.Printf("[memory] round knowledge selection failed for task %s: %v", t.ID, err)
		return nil
	}
	hits := make([]db.KnowledgeHit, 0, len(entries))
	for _, e := range entries {
		if r := []rune(e.Body); len(r) > memoryRoundBodyRunes {
			e.Body = string(r[:memoryRoundBodyRunes])
		}
		hits = append(hits, db.KnowledgeHit{KnowledgeEntry: e})
	}
	return hits
}

// taskMemoryBlock builds the start-of-task memory block: the knowledge visible
// to the task plus its latest 4 opsec/noise reflections from earlier runs and
// resumes. It is data from earlier work, never instructions, and the whole
// block is capped.
func (s *Server) taskMemoryBlock(t *Task, taskID int64, mode string) string {
	ctx := context.Background()
	hits := s.memoryHits(ctx, t, taskID)
	refl, err := s.m.PG().ListReflections(ctx, taskID, []string{"opsec", "noise"}, 4)
	if err != nil {
		log.Printf("[memory] reflection selection failed for task %s: %v", t.ID, err)
		refl = nil
	}
	block := db.RenderMemory(hits, refl, memoryStartMaxChars)
	log.Printf("[memory] task %s: %d knowledge hits, %d reflections (mode %s)",
		t.ID, len(hits), len(refl), mode)
	return block
}

// memoryHits selects the knowledge a task sees at start: every adopted
// environment entry first (platform facts such as proxy behaviour, true for
// every task here and independent of the target), then the entries matching the
// task's name and goal. Environment entries are always included, whatever the
// task is about, but get their own small cap and a clipped body so they cannot
// crowd out target knowledge.
func (s *Server) memoryHits(ctx context.Context, t *Task, taskID int64) []db.KnowledgeHit {
	pg := s.m.PG()
	env, err := pg.ListKnowledge(ctx, db.KnowledgeFilter{
		TaskID: taskID, Scope: "environment", Status: "adopted", Limit: memoryEnvironmentHits,
	})
	if err != nil {
		log.Printf("[memory] environment selection failed for task %s: %v", t.ID, err)
		env = nil
	}
	hits := make([]db.KnowledgeHit, 0, len(env)+memoryTargetHits)
	seen := make(map[int64]bool, len(env))
	for _, e := range env {
		if r := []rune(e.Body); len(r) > memoryEnvironmentBodyRunes {
			e.Body = string(r[:memoryEnvironmentBodyRunes])
		}
		seen[e.ID] = true
		hits = append(hits, db.KnowledgeHit{KnowledgeEntry: e})
	}
	// The search sees environment entries too (they are visible to every task);
	// asking for a few extra slots keeps the target matches at memoryTargetHits
	// after the duplicates are dropped.
	target, err := pg.SearchKnowledge(ctx, taskID, memoryQuery(t), nil, memoryTargetHits+len(env))
	if err != nil {
		log.Printf("[memory] knowledge search failed for task %s: %v", t.ID, err)
		return hits
	}
	added := 0
	for _, h := range target {
		if seen[h.ID] {
			continue
		}
		hits = append(hits, h)
		added++
		if added == memoryTargetHits {
			break
		}
	}
	return hits
}

// memoryQuery is the retrieval query: the task's name and goal, tokenised and
// ORed by db.MemorySearchTerms so one entry need not mention the whole task.
func memoryQuery(t *Task) string {
	return db.MemorySearchTerms(t.Name + " " + t.Goal)
}

// seedMemoryToolBindings gives the memory tools their default agent bindings on
// databases whose tool rows predate them ONCE (guarded by a settings flag).
// SeedTool is first-insert-only for the `agents` column, so a row seeded before
// the bindings existed stays unbound, and ToolResolve then silently drops the
// tool from every agent. Fresh databases already carry the bindings and this is
// a no-op; one-shot so a deliberate later unbind is not overridden.
func (s *Server) seedMemoryToolBindings() {
	const flag = "memory_tool_bindings_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, binding := range []struct {
		agents []string
		keys   []string
	}{
		{[]string{"worker", "planner", "mainagent"}, []string{"recall", "knowledge_add"}},
		{[]string{"worker", "planner"}, []string{"reflect"}},
	} {
		for _, agentKey := range binding.agents {
			if err := s.m.pg.AddAgentToToolBinding(agentKey, binding.keys); err != nil {
				log.Printf("[memory] failed to backfill %v bindings onto %s: %v", binding.keys, agentKey, err)
				return // leave the flag unset so it retries next startup
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

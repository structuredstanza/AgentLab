package server

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
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
// per-round reflections provider to one task's planner and worker. Both are
// bound per task because the provider only ever reads that task's reflections:
// memory never crosses an engagement boundary. The store is bound even with
// injection off, so the recall/knowledge_add/reflect tools stay available.
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
	provider := func(ctx context.Context) string {
		refl, err := pg.ListReflections(ctx, taskID, nil, 6)
		if err != nil {
			log.Printf("[memory] reflections provider failed for task %s: %v", t.ID, err)
			return ""
		}
		return db.RenderReflections(refl, 1200)
	}
	wk.SetReflectionsProvider(provider)
	pl.SetReflectionsProvider(provider)
}

// taskMemoryBlock builds the start-of-task memory block: visible knowledge
// matched by the task's name and goal (top 4) plus the task's latest 4
// opsec/noise reflections from earlier runs and resumes. It is data from
// earlier work, never instructions, and the whole block is capped.
func (s *Server) taskMemoryBlock(t *Task, taskID int64, mode string) string {
	ctx := context.Background()
	hits, err := s.m.PG().SearchKnowledge(ctx, taskID, memoryQuery(t), nil, 4)
	if err != nil {
		log.Printf("[memory] knowledge search failed for task %s: %v", t.ID, err)
		hits = nil
	}
	refl, err := s.m.PG().ListReflections(ctx, taskID, []string{"opsec", "noise"}, 4)
	if err != nil {
		log.Printf("[memory] reflection selection failed for task %s: %v", t.ID, err)
		refl = nil
	}
	block := db.RenderMemory(hits, refl, 2200)
	log.Printf("[memory] task %s: %d knowledge hits, %d reflections (mode %s)",
		t.ID, len(hits), len(refl), mode)
	return block
}

// memoryQuery is the retrieval query: the task's name and goal. Postgres
// websearch_to_tsquery ANDs space-separated terms, which would demand a single
// entry mention the whole task, so the terms are ORed and ranked by overlap.
func memoryQuery(t *Task) string {
	var terms []string
	seen := map[string]bool{}
	// Keep only letters and digits so no task text can smuggle in tsquery
	// operators (quotes, "-", "or").
	flat := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return ' '
	}, strings.ToLower(t.Name+" "+t.Goal))
	for _, term := range strings.Fields(flat) {
		if len(term) < 3 || term == "or" || seen[term] {
			continue
		}
		seen[term] = true
		terms = append(terms, term)
		if len(terms) == 12 {
			break
		}
	}
	return strings.Join(terms, " OR ")
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

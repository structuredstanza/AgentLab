package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Memory block budgets. The start-of-task block is built once per task bundle;
// the launch block is rebuilt for every worker launch and planner round, so the
// packer inside db owns how its budget is split.
const (
	memoryStartMaxChars  = 2200
	memoryLaunchMaxChars = 2400
	// memoryEnvironmentHits caps adopted environment entries shown in full, so
	// they cannot crowd out the index.
	memoryEnvironmentHits = 2
)

// memoryMode reads the knowledge/reflection injection switch:
//
//	off     no selection, no prompt change
//	inject  select, log, and append the rendered block (default)
//
// Like rsiLessonsMode it is read per task-bundle build, so changing it needs a
// new task or a task-agent invalidation, not a restart.
func memoryMode() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("M1NERVAC0NSOLE_MEMORY")), "off") {
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

// memoryProvider is the per-launch/per-round memory block: one selection of
// prior attempts, reflections and the task's own knowledge index, rebuilt every
// time so a lesson written mid-task reaches the next round. The provider reads
// the worker's intent from ctx (RunInfo); a planner round has none, so the
// selector runs with IntentID 0.
func (s *Server) memoryProvider(t *Task, taskID int64) func(context.Context) string {
	return func(ctx context.Context) string {
		block, shown := s.memoryRoundBlock(ctx, taskID, agent.RunInfoFrom(ctx).IntentID, time.Time{})
		s.recordKnowledgeUsage(ctx, taskID, "round", shown.Knowledge)
		return block
	}
}

// memoryRoundBlock renders the launch/round block and returns the ids it wrote.
// Split from the provider so the operator preview renders the same block
// without writing the usage ledger.
func (s *Server) memoryRoundBlock(ctx context.Context, taskID, intentID int64, before time.Time) (string, db.MemoryShown) {
	sel, err := s.m.PG().SelectMemory(ctx, db.MemoryQuery{TaskID: taskID, IntentID: intentID, Before: before})
	if err != nil {
		log.Printf("[memory] memory selection failed for task %d: %v", taskID, err)
		return "", db.MemoryShown{}
	}
	return db.RenderLaunchBlock(sel, memoryLaunchMaxChars)
}

// taskMemoryBlock builds the start-of-task memory block: adopted environment
// entries in full plus an index line for every other adopted entry the task can
// see. It is data from earlier work, never instructions, and the whole block is
// capped by the packer.
func (s *Server) taskMemoryBlock(t *Task, taskID int64, mode string) string {
	ctx := context.Background()
	block, shown := s.memoryStartBlock(ctx, t, taskID)
	log.Printf("[memory] task %s: %d knowledge entries shown (mode %s)", t.ID, len(shown.Knowledge), mode)
	s.recordKnowledgeUsage(ctx, taskID, "task_start", shown.Knowledge)
	return block
}

// memoryStartBlock renders the start-of-task block and returns the ids it
// wrote. Split from taskMemoryBlock so the operator preview renders the same
// block without writing the usage ledger.
func (s *Server) memoryStartBlock(ctx context.Context, t *Task, taskID int64) (string, db.MemoryShown) {
	pg := s.m.PG()
	env, err := pg.ListKnowledge(ctx, db.KnowledgeFilter{
		TaskID: taskID, Scope: "environment", Status: "adopted", Limit: memoryEnvironmentHits,
	})
	if err != nil {
		log.Printf("[memory] environment selection failed for task %s: %v", t.ID, err)
		env = nil
	}
	exclude := make([]int64, len(env))
	for i, e := range env {
		exclude[i] = e.ID
	}
	index, err := pg.KnowledgeIndex(ctx, taskID, memoryQuery(t), exclude)
	if err != nil {
		log.Printf("[memory] knowledge index failed for task %s: %v", t.ID, err)
		index = nil
	}
	return db.RenderStartBlock(env, index, memoryStartMaxChars)
}

// recordKnowledgeUsage writes the usage ledger for one read path. Telemetry
// only: a failure is logged and dropped, so it can never fail a prompt build
// or a tool call. An empty selection skips the round trip entirely.
func (s *Server) recordKnowledgeUsage(ctx context.Context, taskID int64, surface string, ids []int64) {
	if len(ids) == 0 {
		return
	}
	if err := s.m.PG().RecordKnowledgeUsage(ctx, taskID, surface, ids); err != nil {
		log.Printf("[memory] usage ledger write failed for task %d surface %s: %v", taskID, surface, err)
	}
}

// memoryQuery is the start-block index's ordering query: the task's name and
// goal, passed whole. Postgres parses it and ORs its lexemes, so one entry need
// not mention the whole task and the query means what the index means.
func memoryQuery(t *Task) string {
	return strings.TrimSpace(t.Name + " " + t.Goal)
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

// knowledgeUsage serves GET /api/knowledge/{id}/usage: how often and where one
// entry was read back. last_used is empty for an entry nothing has retrieved.
func (s *Server) knowledgeUsage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid knowledge id")
		return
	}
	limit, ok := parseIDParam(r.URL.Query().Get("limit"))
	if !ok {
		writeErr(w, 400, "invalid limit")
		return
	}
	sum, err := s.m.PG().GetKnowledgeUsage(r.Context(), id, int(limit))
	if err != nil {
		log.Printf("[memory] knowledge usage read failed for %d: %v", id, err)
		writeErr(w, 500, "knowledge usage failed")
		return
	}
	lastUsed := ""
	if !sum.LastUsed.IsZero() {
		lastUsed = sum.LastUsed.UTC().Format(time.RFC3339)
	}
	writeJSON(w, 200, map[string]any{"hits": sum.Hits, "last_used": lastUsed, "usage": sum.Usage})
}

// memoryPreview serves GET /api/memory/preview?task_id=[&intent_id=]: exactly
// what that task would be injected with, rendered through the same selection
// and rendering path the task itself uses. With intent_id, the round block is
// the launch block that worker gets, rendered as of its first activity row.
// It records no usage and mutates nothing - an operator looking is not an agent
// reading.
func (s *Server) memoryPreview(w http.ResponseWriter, r *http.Request) {
	taskID, ok := parseIDParam(r.URL.Query().Get("task_id"))
	if !ok || taskID <= 0 {
		writeErr(w, 400, "invalid task id")
		return
	}
	intentID, ok := parseIDParam(r.URL.Query().Get("intent_id"))
	if !ok || intentID < 0 {
		writeErr(w, 400, "invalid intent id")
		return
	}
	pgTask, err := s.m.PG().GetTask(taskID)
	if err != nil {
		log.Printf("[memory] preview task lookup failed for %d: %v", taskID, err)
		writeErr(w, 500, "task lookup failed")
		return
	}
	if pgTask == nil {
		writeErr(w, 404, "task not found")
		return
	}
	// The memory selection only reads the task's identity, name and goal, so a
	// throwaway handle is enough: the preview must work for a task that is not
	// loaded in memory (finished, or after a restart).
	task := &Task{ID: strconv.FormatInt(taskID, 10), Name: pgTask.Name, Goal: pgTask.Goal}
	mode := memoryMode()
	out := map[string]any{
		"mode": mode, "start_block": "", "round_block": "",
		"knowledge_ids": []int64{}, "reflection_ids": []int64{},
		"intent_id": intentID, "as_of": "",
	}
	ctx := r.Context()
	var before time.Time
	if intentID > 0 {
		belongs, err := s.m.PG().IntentBelongsToTask(ctx, intentID, taskID)
		if err != nil {
			log.Printf("[memory] preview intent lookup failed for %d: %v", intentID, err)
			writeErr(w, 500, "intent lookup failed")
			return
		}
		if !belongs {
			writeErr(w, 400, "intent does not belong to this task")
			return
		}
		before, err = s.m.PG().IntentStartedAt(ctx, intentID)
		if err != nil {
			log.Printf("[memory] preview intent start failed for %d: %v", intentID, err)
			writeErr(w, 500, "intent lookup failed")
			return
		}
		if !before.IsZero() {
			out["as_of"] = before.UTC().Format(time.RFC3339)
		}
	}
	if mode == "inject" {
		start, startShown := s.memoryStartBlock(ctx, task, taskID)
		round, roundShown := s.memoryRoundBlock(ctx, taskID, intentID, before)
		out["start_block"] = start
		out["round_block"] = round
		out["knowledge_ids"] = mergeIDs(startShown.Knowledge, roundShown.Knowledge)
		out["reflection_ids"] = mergeIDs(roundShown.Reflections)
	}
	writeJSON(w, 200, out)
}

// mergeIDs concatenates id groups in first-seen order, so a preview can link
// each rendered row back to the item it came from.
func mergeIDs(groups ...[]int64) []int64 {
	out := make([]int64, 0)
	seen := make(map[int64]bool)
	for _, g := range groups {
		for _, id := range g {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

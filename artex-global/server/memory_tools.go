package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	actool "github.com/structuredstanza/norma/tool"
)

// Curator memory tools: the tool set of the "curator" chat agent, which reads
// the knowledge base and the reflection pool and proposes task-scoped
// candidates for the operator to promote.
//
// They are host tools built against the server's db.DB, like platformTools, and
// not agent.ToolSet memory tools: recall/knowledge_add/reflect are bound to one
// task by contract and refuse at taskID<=0 (agent/tools_memory.go), which a
// task-less chat can never satisfy.
//
// The slice is propose-only. Every read tool reads freely across tasks, because
// curation is an operator-wide job; the only write tool can produce a
// task-scoped candidate and nothing else. Promotion, retirement and deletion
// stay operator actions in the UI, so no call here can move an entry out of its
// task.
//
// Binding is the security boundary: each tool below is seeded into the tools
// table bound to "curator" alone (seedCuratorTools). A host tool with no row is
// unfiltered by ToolResolve and would reach every agent, so the row must exist.

// curatorToolKeys are the tools the curator chat agent is bound to by default.
var curatorToolKeys = []string{
	"memory_search", "memory_read", "memory_propose", "reflection_search", "task_digest",
}

// curatorTools is the curator's tool set.
func (s *Server) curatorTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolMemorySearch(),
		s.toolMemoryRead(),
		s.toolMemoryPropose(),
		s.toolReflectionSearch(),
		s.toolTaskDigest(),
	}
}

// seedCuratorTools seeds each curator tool bound to "curator" only, so
// ToolResolve keeps them off worker, planner, auto and every other agent. Seed
// is first-insert-only, so an operator's later binding edit survives restarts.
func (s *Server) seedCuratorTools() {
	bindings, _ := json.Marshal([]string{"curator"})
	for _, t := range s.curatorTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			log.Printf("[curator] failed to seed %s: %v", t.Name(), err)
		}
	}
}

// knowledgePreview is one search hit without the full body, so a list stays
// inside the model's budget; memory_read carries the whole entry.
func knowledgePreview(e db.KnowledgeEntry) map[string]any {
	out := map[string]any{
		"id":         e.ID,
		"scope":      e.Scope,
		"kind":       e.Kind,
		"status":     e.Status,
		"source":     e.Source,
		"title":      e.Title,
		"body":       clipRunes(e.Body, memoryPreviewBodyRunes),
		"tags":       e.Tags,
		"updated_at": e.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if e.TaskID > 0 {
		out["task_id"] = e.TaskID
	}
	if e.CompanyID > 0 {
		out["company_id"] = e.CompanyID
	}
	return out
}

// memoryPreviewBodyRunes bounds a search preview so a page of hits stays small.
const memoryPreviewBodyRunes = 320

// curatorKnowledgeKinds mirrors the store's kind set so a bad kind is refused
// with the list instead of the store's generic "invalid memory entry".
var curatorKnowledgeKinds = map[string]bool{
	"technique": true, "tool": true, "opsec": true,
	"indicator": true, "playbook": true, "lead": true, "note": true,
}

// clipRunes shortens s to at most n runes, marking the cut with an ellipsis.
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func (s *Server) toolMemorySearch() actool.CoreTool {
	return roTool("memory_search",
		"Search the knowledge base: reusable techniques, tools, opsec rules, indicators and playbooks, with their scope, kind, status and tags. Results are previews; call memory_read for an entry's full body. "+
			"Omit task_id for the operator-wide view of every scope (all candidates, adopted and retired entries, across every task); pass task_id to see exactly what one task may see (its own entries plus adopted global/environment/company knowledge).",
		objSchema(map[string]any{
			"q":       strParam("Full-text query over title and body. Plain words; the store ANDs them first and falls back to OR-ing them when that matches nothing (relaxed=true in the reply). Empty = newest first."),
			"scope":   strParam("Optional: global | environment | company | task"),
			"kind":    strParam("Optional: technique | tool | opsec | indicator | playbook | lead | note"),
			"status":  strParam("Optional: candidate | adopted | retired"),
			"task_id": map[string]any{"type": "integer", "description": "Optional: restrict to what this task may see. Omit for the operator-wide view."},
			"limit":   map[string]any{"type": "integer", "description": "Optional: page size, default 20, max 50."},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q      string `json:"q"`
				Scope  string `json:"scope"`
				Kind   string `json:"kind"`
				Status string `json:"status"`
				TaskID int64  `json:"task_id"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 20
			}
			if limit > 50 {
				limit = 50
			}
			entries, total, relaxed, err := s.m.PG().ListKnowledgeMatch(ctx, db.KnowledgeFilter{
				Scope:  strings.TrimSpace(a.Scope),
				Kind:   strings.TrimSpace(a.Kind),
				Status: strings.TrimSpace(a.Status),
				Query:  strings.TrimSpace(a.Q),
				TaskID: a.TaskID,
				Limit:  limit,
				Ranked: true,
			})
			if err != nil {
				return actool.Errorf("search failed: " + err.Error()), nil
			}
			out := make([]map[string]any, 0, len(entries))
			for _, e := range entries {
				out = append(out, knowledgePreview(e))
			}
			return jsonResult(map[string]any{
				"entries": out, "count": len(out), "total": total, "relaxed": relaxed,
			})
		})
}

func (s *Server) toolMemoryRead() actool.CoreTool {
	return roTool("memory_read",
		"Read one knowledge entry in full (title, complete body, tags, scope, status, source). Use it after memory_search or task_digest to judge an entry before proposing a change.",
		objSchema(map[string]any{
			"id": map[string]any{"type": "integer", "description": "Knowledge entry id (from memory_search or task_digest)."},
		}, "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID int64 `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			if a.ID <= 0 {
				return actool.Errorf("id is required"), nil
			}
			e, err := s.m.PG().GetKnowledge(ctx, a.ID)
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"entry": e})
		})
}

func (s *Server) toolMemoryPropose() actool.CoreTool {
	return wrTool("memory_propose",
		"Propose one knowledge candidate for a task. Read the existing entries first (memory_search) and propose only what is missing or wrong: "+
			"write the condition and the mechanism (what makes it work, when it applies, what it looks like) rather than one box's address or one run's identifiers. "+
			"The entry is stored as a task-scoped candidate with source 'agent': secrets are scrubbed and the task's own identifiers are generalised, so it reads as a rule for the next target. "+
			"You cannot promote, retire, delete or write global/company/environment entries; the operator reviews the candidate in the knowledge UI and promotes it.",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Task the candidate belongs to (from task_digest or the operator). Required: candidates live inside one task until the operator promotes them."},
			"kind":    strParam("technique | tool | opsec | indicator | playbook | lead | note"),
			"title":   strParam("One line naming the reusable rule, not the target (for example \"path traversal in a Java file-download servlet\")."),
			"body":    strParam("The condition and the mechanism, plus how to recognise it and what to try. No credentials, no target-specific addresses."),
			"tags":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional: short topic tags."},
		}, "task_id", "kind", "title", "body"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID int64    `json:"task_id"`
				Kind   string   `json:"kind"`
				Title  string   `json:"title"`
				Body   string   `json:"body"`
				Tags   []string `json:"tags"`
				// Not advertised: a model that reaches for them is refused with
				// the reason instead of being silently narrowed.
				Scope  string `json:"scope"`
				Status string `json:"status"`
			}
			_ = json.Unmarshal(in, &a)
			if sc := strings.TrimSpace(a.Scope); sc != "" && sc != "task" {
				return actool.Errorf(fmt.Sprintf("memory_propose writes task-scoped candidates only; scope %q is not accepted. Propose the candidate for its task and let the operator promote it.", sc)), nil
			}
			if st := strings.TrimSpace(a.Status); st != "" && st != "candidate" {
				return actool.Errorf(fmt.Sprintf("memory_propose writes candidates only; status %q is not accepted. The operator promotes, retires and deletes entries.", st)), nil
			}
			if a.TaskID <= 0 {
				return actool.Errorf("task_id is required: a candidate lives inside one task until the operator promotes it"), nil
			}
			kind := strings.TrimSpace(a.Kind)
			if !curatorKnowledgeKinds[kind] {
				return actool.Errorf("kind must be one of technique|tool|opsec|indicator|playbook|lead|note"), nil
			}
			if task, err := s.m.PG().GetTask(a.TaskID); err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			} else if task == nil {
				return actool.Errorf(fmt.Sprintf("task #%d not found: a candidate must belong to a real task", a.TaskID)), nil
			}
			entry, redactions, err := s.m.PG().AddKnowledge(ctx, db.KnowledgeInput{
				Scope:  "task",
				TaskID: a.TaskID,
				Kind:   kind,
				Title:  a.Title,
				Body:   a.Body,
				Tags:   a.Tags,
				Source: "agent", // curator writes are scrubbed/generalised like an agent's
				Status: "candidate",
			})
			if err != nil {
				if errors.Is(err, db.ErrMemoryCapReached) {
					return actool.Errorf("this task already holds the maximum number of proposed entries; tell the operator which existing candidate to revise instead"), nil
				}
				return actool.Errorf(fmt.Sprintf("proposal refused: %s (the curator proposes task-scoped candidates; the operator promotes them)", err)), nil
			}
			return jsonResult(map[string]any{
				"entry":      entry,
				"redactions": redactions,
				"note":       "Saved as a task-scoped candidate. The operator promotes it in the knowledge UI; it is not visible to other tasks until then.",
			})
		})
}

func (s *Server) toolReflectionSearch() actool.CoreTool {
	return roTool("reflection_search",
		"Read one task's reflection pool: what was noisy, what triggered defences, what to look for next, what worked and what went wrong. Read-only. "+
			"The pool is task-private by design, so task_id is required; the store has no cross-task reflection query yet.",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Task whose reflections to read."},
			"kind":    strParam("Optional: comma-separated kinds: opsec | noise | lookfor | learning | mistake"),
			"q":       strParam("Optional: keep only reflections whose summary or detail contains this text (case-insensitive). Filters the newest rows of that task, not the whole pool."),
			"limit":   map[string]any{"type": "integer", "description": "Optional: how many of the task's newest reflections to scan, default 20, max 50."},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID int64  `json:"task_id"`
				Kind   string `json:"kind"`
				Q      string `json:"q"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if a.TaskID <= 0 {
				return actool.Errorf("task_id is required: the reflection pool is task-private"), nil
			}
			limit := a.Limit
			if limit <= 0 {
				limit = 20
			}
			if limit > 50 {
				limit = 50
			}
			refl, err := s.m.PG().ListReflections(ctx, a.TaskID, splitKinds(a.Kind), limit)
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			needle := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, len(refl))
			for _, r := range refl {
				if needle != "" &&
					!strings.Contains(strings.ToLower(r.Summary), needle) &&
					!strings.Contains(strings.ToLower(r.Detail), needle) {
					continue
				}
				out = append(out, map[string]any{
					"id": r.ID, "task_id": r.TaskID, "kind": r.Kind, "source": r.Source,
					"summary": r.Summary, "detail": r.Detail,
					"created_at": r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
				})
			}
			return jsonResult(map[string]any{"task_id": a.TaskID, "reflections": out, "count": len(out)})
		})
}

// splitKinds turns a comma-separated kind filter into the store's list form.
func splitKinds(raw string) []string {
	out := []string{}
	for _, k := range strings.Split(raw, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func (s *Server) toolTaskDigest() actool.CoreTool {
	return roTool("task_digest",
		"Summarize one past task so this conversation can be pointed at it: name, goal, status, the knowledge it holds, its reflections, and the findings it recorded. Read-only; use it to decide what is worth promoting or correcting. "+
			"Without task_id it lists the newest tasks instead, so you can find the one the operator means.",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Task to summarize. Omit to list the newest tasks with their ids."},
			"limit":   map[string]any{"type": "integer", "description": "Optional: how many knowledge entries and reflections to include, default 10, max 50. When listing, how many tasks."},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID int64 `json:"task_id"`
				Limit  int   `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 10
			}
			if limit > 50 {
				limit = 50
			}
			if a.TaskID <= 0 {
				tasks, err := s.m.PG().ListTasks()
				if err != nil {
					return actool.Errorf("read failed: " + err.Error()), nil
				}
				out := make([]map[string]any, 0, limit)
				for _, t := range tasks {
					if len(out) == limit {
						break
					}
					out = append(out, map[string]any{
						"id": t.ID, "name": t.Name, "goal": clipRunes(t.Goal, 200), "status": t.Status,
					})
				}
				return jsonResult(map[string]any{"tasks": out, "count": len(out), "total": len(tasks)})
			}
			t, err := s.m.PG().GetTask(a.TaskID)
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task #%d not found", a.TaskID)), nil
			}
			kn, err := s.m.PG().ListKnowledge(ctx, db.KnowledgeFilter{TaskID: a.TaskID, Limit: limit})
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			knowledge := make([]map[string]any, 0, len(kn))
			for _, e := range kn {
				knowledge = append(knowledge, knowledgePreview(e))
			}
			refl, err := s.m.PG().ListReflections(ctx, a.TaskID, nil, limit)
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			reflections := make([]map[string]any, 0, len(refl))
			for _, r := range refl {
				reflections = append(reflections, map[string]any{
					"id": r.ID, "kind": r.Kind, "source": r.Source,
					"summary": r.Summary, "detail": clipRunes(r.Detail, memoryPreviewBodyRunes),
				})
			}
			// Findings are evidence of what the task achieved; a count plus the
			// headline rows is enough to decide whether the memory matches it.
			findings, findingTotal, err := s.m.PG().ListFindingsPage(db.FindingFilter{TaskID: strconv.FormatInt(a.TaskID, 10)}, 1, 5)
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			found := make([]map[string]any, 0, len(findings))
			for _, f := range findings {
				found = append(found, map[string]any{
					"id": f.ID, "name": f.Name, "vuln_class": f.VulnClass,
					"severity": f.Severity, "status": f.Status,
				})
			}
			return jsonResult(map[string]any{
				"task": map[string]any{
					"id": t.ID, "name": t.Name, "goal": t.Goal, "description": t.Description,
					"status": t.Status, "created_at": t.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
				},
				"knowledge":        knowledge,
				"knowledge_count":  len(knowledge),
				"reflections":      reflections,
				"reflection_count": len(reflections),
				"findings":         found,
				"finding_total":    findingTotal,
			})
		})
}

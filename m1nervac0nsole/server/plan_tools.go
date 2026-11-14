package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/plan"
	actool "github.com/structuredstanza/norma/tool"
)

// Drafter tools: the tool set of the "drafter" chat agent, which turns an
// operator's plain-language approach into a plan proposal the operator reviews
// and applies.
//
// The slice is propose-only. plan_context and list_tools read; propose_plan and
// propose_scope validate and store a draft row, and nothing here writes to the
// graph. The apply endpoint owns that, so a proposal the validator refuses never
// becomes work, and a stored draft is still only a suggestion. The two write
// tools share one store path and one draft table: propose_scope is propose_plan
// with the scope section filled from a pasted policy.
//
// Binding is the security boundary: plan_context, propose_plan and propose_scope
// are seeded into the tools table bound to "drafter" alone (seedDrafterTools). A host tool
// with no row is unfiltered by ToolResolve and would reach every agent, so the
// row must exist. list_tools is the shared manifest catalog the worker and the
// planner already hold, so the drafter is added to that binding instead of
// replacing it - a drafter-only row would take the manifest ids away from the
// agents that run them.

// drafterToolKeys are the tools the drafter chat agent is bound to by default.
var drafterToolKeys = []string{"plan_context", "list_tools", "propose_plan", "propose_scope"}

// drafterTools is the drafter's tool set.
func (s *Server) drafterTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolPlanContext(),
		s.toolListManifests(),
		s.toolProposePlan(),
		s.toolProposeScope(),
	}
}

// seedDrafterTools seeds the drafter's tools bound to "drafter" only, and adds
// the drafter to list_tools' binding. Seed is first-insert-only, so an
// operator's later binding edit survives restarts.
func (s *Server) seedDrafterTools() {
	bindings, _ := json.Marshal([]string{"drafter"})
	for _, t := range s.drafterTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			log.Printf("[drafter] failed to seed %s: %v", t.Name(), err)
		}
	}
	// list_tools is seeded by the platform tools before this one, so SeedTool
	// cannot add the drafter to its row; without this the prompt names a tool
	// ToolResolve drops for the drafter.
	if err := s.m.PG().AddAgentToToolBinding("drafter", []string{"list_tools"}); err != nil {
		log.Printf("[drafter] failed to bind list_tools: %v", err)
	}
}

// planContextAssetLimit bounds the asset list one context read returns, so a
// large engagement still fits the model's budget.
const planContextAssetLimit = 200

// planContextNodeLimit bounds each existing-node list for the same reason.
const planContextNodeLimit = 200

// planTaskKey carries the task a conversation is bound to into its tools.
//
// The plan tab opens a conversation bound to one task, so the drafter's tools
// take the task from the thread instead of from the model: a model that names
// another task would otherwise store a draft against a real engagement the
// operator never asked about.
type planTaskKey struct{}

func withPlanTask(ctx context.Context, taskID int64) context.Context {
	if taskID <= 0 {
		return ctx
	}
	return context.WithValue(ctx, planTaskKey{}, taskID)
}

func planTaskFrom(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(planTaskKey{}).(int64)
	return id, ok && id > 0
}

// planTaskID resolves the task a tool call may act on: the conversation binding
// wins, and a model-supplied id that disagrees is refused rather than ignored,
// so the model learns why instead of silently drafting for the wrong task.
func planTaskID(ctx context.Context, asked int64) (int64, error) {
	bound, ok := planTaskFrom(ctx)
	if !ok {
		if asked <= 0 {
			return 0, errors.New("task_id is required: this conversation is not bound to a task")
		}
		return asked, nil
	}
	if asked > 0 && asked != bound {
		return 0, fmt.Errorf("this conversation drafts for task %d; task %d is not it", bound, asked)
	}
	return bound, nil
}

func (s *Server) toolPlanContext() actool.CoreTool {
	return roTool("plan_context",
		"Read the engagement a plan is drafted for: its goal and description, its scope rows, up to 200 assets, and the goals, intents and hints it already has (id, text or summary, state). Read it before propose_plan so the draft builds on what exists instead of repeating it. Read-only.",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Task id the plan is for. Omit it when the conversation is bound to a task: the binding wins."},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID int64 `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			taskID, err := planTaskID(ctx, a.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			a.TaskID = taskID
			t, err := s.m.PG().GetTask(a.TaskID)
			if err != nil {
				return actool.Errorf("read task: " + err.Error()), nil
			}
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task %d not found", a.TaskID)), nil
			}
			out := map[string]any{
				"task_id": t.ID, "goal": t.Goal, "description": t.Description,
				"scope": []map[string]any{}, "assets": []map[string]any{},
			}
			if as := s.m.Assets(); as != nil {
				scopes, err := as.ListTaskScope(t.ID)
				if err != nil {
					return actool.Errorf("read scope: " + err.Error()), nil
				}
				scope := make([]map[string]any, 0, len(scopes))
				for _, ts := range scopes {
					scope = append(scope, map[string]any{
						"kind": ts.Kind, "value": scopeRowValue(ts), "effect": ts.Effect, "reason": ts.Reason,
					})
				}
				out["scope"] = scope
				assets, err := as.QueryByTask(t.ID, "", planContextAssetLimit, 0)
				if err != nil {
					return actool.Errorf("read assets: " + err.Error()), nil
				}
				list := make([]map[string]any, 0, len(assets))
				for _, asset := range assets {
					list = append(list, map[string]any{"id": asset.ID, "type": asset.Type, "value": assetLabel(asset)})
				}
				out["assets"] = list
			}
			store := s.m.PG().Exploration(t.ExplorationID)
			goals, err := store.ListByKind(db.KindGoal, planContextNodeLimit)
			if err != nil {
				return actool.Errorf("read goals: " + err.Error()), nil
			}
			out["goals"] = planNodeDigest(goals, "text")
			intents, err := store.ListByKind(db.KindIntent, planContextNodeLimit)
			if err != nil {
				return actool.Errorf("read intents: " + err.Error()), nil
			}
			out["intents"] = planNodeDigest(intents, "summary")
			hints, err := store.ListByKind(db.KindHint, planContextNodeLimit)
			if err != nil {
				return actool.Errorf("read hints: " + err.Error()), nil
			}
			out["hints"] = planNodeDigest(hints, "text")
			return jsonResult(out)
		})
}

// scopeRowValue renders the one field a scope row carries, so a draft reads
// "exclude root_domain vendor.example" instead of three empty columns.
func scopeRowValue(ts db.TaskScope) string {
	switch ts.Kind {
	case "root_domain", "subdomain":
		return ts.Domain
	case "ip", "cidr":
		return ts.Net
	case "company":
		if ts.CompanyName != "" {
			return ts.CompanyName
		}
	}
	return ts.Value
}

// planNodeDigest projects existing graph nodes down to what a draft needs to
// avoid repeating them: id, the one text field the node carries, and its state.
func planNodeDigest(nodes []*db.Node, field string) []map[string]any {
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		var payload map[string]any
		_ = json.Unmarshal(n.Payload, &payload)
		out = append(out, map[string]any{"id": n.ID, field: payload[field], "state": n.State})
	}
	return out
}

func (s *Server) toolProposePlan() actool.CoreTool {
	return wrTool("propose_plan",
		"Validate a plan proposal and store it as the task's one pending draft for the operator to review and apply. Nothing is written to the graph: this stores a draft and nothing else. "+
			"A validation failure returns every problem at once; fix them all and call propose_plan once more. "+
			"A scope inclusion widens the engagement and needs the operator's explicit approval (needs_include_approval=true in the reply); an exclusion only narrows it and does not.",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Task id the plan is for. Omit it when the conversation is bound to a task: the binding wins."},
			"proposal": map[string]any{
				"type": "object",
				"description": "summary (one sentence), goals[{ref,text,vulnclass}], intents[{ref,summary,goal,asset_ids,depends_on}], " +
					"hints[{text,asset_ids,rule}], scope[{effect,kind,value,note}]. Refs are unique across goals and intents.",
			},
		}, "proposal"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID   int64           `json:"task_id"`
				Proposal json.RawMessage `json:"proposal"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			var p plan.Proposal
			if err := json.Unmarshal(a.Proposal, &p); err != nil {
				return actool.Errorf("proposal is not a plan object: " + err.Error()), nil
			}
			return s.storePlanDraft(ctx, "propose_plan", a.TaskID, p, a.Proposal)
		})
}

// toolProposeScope is the pasted-policy entry point: the operator hands over a
// program policy instead of describing an approach, and the model turns its
// boundary statements into the draft's scope section. It is propose_plan with
// goals, intents and hints left empty, so there is one validator, one draft
// table and one apply path.
func (s *Server) toolProposeScope() actool.CoreTool {
	return wrTool("propose_scope",
		"Turn a pasted program policy into the task's scope rules: one rule per line of the policy, an exclusion for everything it puts out of scope, an inclusion only for a host it names as in scope. "+
			"Validates and stores them as the task's one pending draft - the same draft propose_plan writes - so nothing reaches the boundary until the operator applies it. "+
			"A validation failure returns every problem at once; fix them all and call propose_scope once more. "+
			"An inclusion widens the engagement and needs the operator's explicit approval (needs_include_approval=true in the reply); an exclusion only narrows it and does not.",
		objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Task id the rules are for. Omit it when the conversation is bound to a task: the binding wins."},
			"summary": map[string]any{"type": "string", "description": "One sentence on what the policy covers."},
			"rules": map[string]any{
				"type":        "array",
				"description": "One rule per line of the policy: effect include or exclude, kind, value, and a note quoting the policy line it came from.",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"effect": map[string]any{"type": "string", "enum": []string{"include", "exclude"}},
						"kind":   map[string]any{"type": "string", "enum": []string{"company", "root_domain", "subdomain", "ip", "cidr", "icp", "keyword"}},
						"value":  map[string]any{"type": "string"},
						"note":   map[string]any{"type": "string"},
					},
					"required": []string{"effect", "kind", "value"},
				},
			},
		}, "summary", "rules"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID  int64        `json:"task_id"`
				Summary string       `json:"summary"`
				Rules   []plan.Scope `json:"rules"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("bad input: " + err.Error()), nil
			}
			p := plan.Proposal{Summary: a.Summary, Scope: a.Rules}
			raw, err := json.Marshal(p)
			if err != nil {
				return actool.Errorf("encode proposal: " + err.Error()), nil
			}
			return s.storePlanDraft(ctx, "propose_scope", a.TaskID, p, raw)
		})
}

// storePlanDraft is the one write path both propose tools use: resolve the task
// (the conversation binding wins), validate, store the task's pending draft.
// raw is what the draft table keeps, so the review screen renders the model's
// own proposal rather than a re-encoding of it.
func (s *Server) storePlanDraft(ctx context.Context, tool string, asked int64, p plan.Proposal, raw json.RawMessage) (actool.Result, error) {
	taskID, err := planTaskID(ctx, asked)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	t, err := s.m.PG().GetTask(taskID)
	if err != nil {
		return actool.Errorf("read task: " + err.Error()), nil
	}
	if t == nil {
		return actool.Errorf(fmt.Sprintf("task %d not found", taskID)), nil
	}
	ids, err := s.taskAssetIDs(t.ID)
	if err != nil {
		return actool.Errorf("read assets: " + err.Error()), nil
	}
	if errs := plan.Validate(p, plan.Context{AssetIDs: ids}); len(errs) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "the proposal has %d problem(s); fix them all and call %s once more:\n", len(errs), tool)
		for _, e := range errs {
			fmt.Fprintf(&b, "- %v\n", e)
		}
		return actool.Errorf(strings.TrimRight(b.String(), "\n")), nil
	}
	draft, err := s.m.PG().CreatePlanDraft(ctx, t.ID, p.Summary, raw)
	if err != nil {
		return actool.Errorf("store draft: " + err.Error()), nil
	}
	return jsonResult(map[string]any{
		"draft_id": draft.ID, "summary": p.Summary,
		"goals": len(p.Goals), "intents": len(p.Intents), "hints": len(p.Hints), "scope": len(p.Scope),
		"needs_include_approval": plan.HasInclude(p),
	})
}

// taskAssetIDs is the set plan.Validate checks asset_ids against, so a draft
// cannot anchor an intent to another task's asset.
func (s *Server) taskAssetIDs(taskID int64) (map[int64]bool, error) {
	rows, err := s.m.PG().Query(`SELECT id FROM assets WHERE $1 = ANY(task_ids)`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

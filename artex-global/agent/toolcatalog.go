package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// This file turns the "built-in tools" from pure code into an enumerable catalog that the DB can override:
//   - BuiltinToolSeeds(): expands the built-in tool sets of the three execution agent into seed records (key +
//     description + parameter schema + default bound agent), for the server to idempotently seed into the tools table at startup.
//   - ToolResolve hook: at runtime, filters the assembled tools per agent based on the tools rows in the DB +
//     Override the description/schema + inject parameter defaults. The key/handler remain in the code layer; the DB only changes the prose and default values.
// The handler (Call behavior) always comes from code — the DB cannot change it, only the instructions the model sees and the default input parameters.

// ToolSeed is a seedable snapshot of a built-in tool: the key is CoreTool.Name() (hard-bound to the handler, read-only in the UI),
// UI read-only), Desc/Schema are taken from the tool definitions in the code, and Agents is which agents the code assigns it to by default.
type ToolSeed struct {
	Key    string         // = CoreTool.Name(), primary key, must not be changed
	Desc   string         // Top-level description (can be overridden in the UI)
	Schema map[string]any // Parameter JSON-Schema (structure is read-only; description/default can be edited in the UI)
	Agents []string       // Default bound agent key (worker/planner/mainagent)
}

// builtinToolsByAgent uses a "read-only shell" ToolSet (nil stores) to construct each execution agent's
// domain tool set for each execution agent. Tool constructors only put closures into the Spec and do not dereference the store at construction time, so nil is safe——
// These tools are used here only to read Name()/Description()/InputSchema(); never Call them.
//
// Deliberately excludes the SDK's common tools actool.DefaultTools() (Read/Write/Edit/MultiEdit/LS/Glob/
// Grep/Bash): each agent always has these fixed, with no "which agent to bind to" trade-off, and their descriptions mostly live in Prompt()
// here (this table only covers Description(), which would cause a half-override and be misleading). Do not seed → no DB row → ToolResolve
// passes through unchanged and does not override, so behavior is the same as before. Only artex's own domain tools that are in this table can be managed.
func builtinToolsByAgent() map[string][]actool.CoreTool {
	ts := NewToolSet(nil, "")
	return map[string][]actool.CoreTool{
		"mainagent": ts.MainAgentTools(),
		"planner":   ts.PlannerTools(),
		"worker":    ts.WorkerTools(),
		// goals (the goal decomposer) binds set_goals + set_constraints by default: these are used to write the decomposed goals and
		// Write the extracted operation constraints into the library. Shares the same managed tool with mainagent; the web side can edit the description/schema and select per agent.
		"goals": {ts.setGoals(), ts.setConstraints()},
		// auto binds the vulnerability reporting + asset management tools by default; other domain tools can be checked on demand in the UI.
		// New databases are seeded here; old databases are migrated by seedAutoDefaultBindings.
		"auto": {ts.addFinding(), ts.insertAssets(), ts.addCompanyScope(), ts.listAssets(), ts.listCompanies()},
		// Default bindings for pentest (the standalone penetration-testing agent): query assets / insert assets / report vulnerabilities / query vulnerabilities / query enterprises.
		// New databases are seeded here; legacy databases are migrated by seedPentestDefaultBindings.
		"pentest": {ts.listAssets(), ts.insertAssets(), ts.addFinding(), ts.listFindings(), ts.listCompanies()},
	}
}

// defaultUnbound: these system tools are still entered into the catalog as usual (visible on the web side and manually bindable per agent), but
// By default [binds no agent] — ToolResolve drops tools with empty bindings for every agent; explicit opt-in is required.
// The reason it still stays in some agent's base toolset (such as goal_met in PlannerTools): first, to let the seed
// The reason they still remain in some agent's base tool set (such as goal_met in PlannerTools) is twofold: first, to let seed construct it so it gets its desc/schema; second, when a user manually binds it back, the base at runtime contains it, so ToolResolve will retain it.
//
// goal_met: bypasses prove_goal one by one and declares the ENTIRE task complete directly from the global scope. High weight and risk of misjudgment, and it
// The "prove_goal marks the last goal → auto-close" logic was duplicated, so by default no agent is given it; bind it manually when needed.
var defaultUnbound = map[string]bool{"goal_met": true}

// BuiltinToolSeeds deduplicates and merges each agent's built-in toolset into a seed list: tools with the same name (such as list_assets
// Merge into one entry (multiple agents have it); the Agents take the union, and tools in defaultUnbound are forced to be bound to empty.
func BuiltinToolSeeds() []ToolSeed {
	byAgent := builtinToolsByAgent()
	order := []string{"mainagent", "goals", "planner", "worker", "auto", "pentest"}

	type acc struct {
		tool   actool.CoreTool
		agents []string
	}
	m := map[string]*acc{}
	var keys []string
	for _, ak := range order {
		for _, t := range byAgent[ak] {
			a, ok := m[t.Name()]
			if !ok {
				a = &acc{tool: t}
				m[t.Name()] = a
				keys = append(keys, t.Name())
			}
			a.agents = append(a.agents, ak)
		}
	}

	out := make([]ToolSeed, 0, len(keys))
	for _, k := range keys {
		a := m[k]
		agents := a.agents
		if defaultUnbound[k] {
			agents = []string{} // Enters the catalog and can be bound manually, but is not given to any agent by default (stored as [] rather than null, consistent with other tools).
		}
		out = append(out, ToolSeed{
			Key:    k,
			Desc:   a.tool.Description(),
			Schema: a.tool.InputSchema(),
			Agents: agents,
		})
	}
	return out
}

// ToolResolve, if set, post-processes an agent's fully-assembled tool list against
// the DB tools table: it drops tools not bound to this agent (or globally disabled)
// and wraps the rest so the model sees the DB-overridden description/schema and
// Default-value input get injected. Tools with no matching DB row (MCP/skill/host tools like
// traffic) pass through untouched. nil = tools unchanged. Wired in server/assembly.go.
var ToolResolve func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool

// DecorateTool wraps t so Description()/InputSchema() report the DB overrides and
// Call() injects scalar parameter defaults (from schema's "default" props) whenever
// the model omitted them. Name/Prompt/permission/scheduler flags delegate to t, so
// the tool's identity and handler are unchanged. Empty desc/schema fall back to t's.
func DecorateTool(t actool.CoreTool, desc string, schema map[string]any) actool.CoreTool {
	if desc == "" {
		desc = t.Description()
	}
	if len(schema) == 0 {
		schema = t.InputSchema()
	}
	return &overriddenTool{CoreTool: t, desc: desc, schema: schema}
}

// overriddenTool is a CoreTool decorator: it embeds the original (so all behavioral
// methods — Prompt/IsReadOnly/IsConcurrencySafe/CheckPermissions/Name — delegate)
// and overrides only the model-facing description/schema plus default injection.
type overriddenTool struct {
	actool.CoreTool
	desc   string
	schema map[string]any
}

func (o *overriddenTool) Description() string         { return o.desc }
func (o *overriddenTool) InputSchema() map[string]any { return o.schema }

func (o *overriddenTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	return o.CoreTool.Call(ctx, injectDefaults(in, o.schema), tc)
}

// injectDefaults fills scalar parameter defaults declared in the (possibly edited)
// schema into the input JSON whenever the model omitted the field or left it empty/
// null. Structure (names/types/required) is untouched — only default values are merged in.
func injectDefaults(in json.RawMessage, schema map[string]any) json.RawMessage {
	defs := scalarDefaults(schema)
	if len(defs) == 0 {
		return in
	}
	m := map[string]json.RawMessage{}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return in // non-object input: don't touch it
		}
	}
	changed := false
	for k, dv := range defs {
		if cur, ok := m[k]; !ok || isEmptyJSON(cur) {
			m[k] = dv
			changed = true
		}
	}
	if !changed {
		return in
	}
	b, err := json.Marshal(m)
	if err != nil {
		return in
	}
	return b
}

// scalarDefaults extracts properties[k]["default"] for scalar params (string/
// integer/number/boolean). Array/object defaults are skipped: merging them is
// ambiguous and not worth the surprise.
func scalarDefaults(schema map[string]any) map[string]json.RawMessage {
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		return nil
	}
	out := map[string]json.RawMessage{}
	for name, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		dv, ok := p["default"]
		if !ok || dv == nil {
			continue
		}
		switch p["type"] {
		case "string", "integer", "number", "boolean":
			if b, err := json.Marshal(dv); err == nil {
				out[name] = b
			}
		}
	}
	return out
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := string(raw)
	return s == "null" || s == `""`
}

// aliasTool is a CoreTool decorator that overrides only Name(): it lets a
// CamelCase built-in (e.g. Bash) also answer to the lowercase/snake_case spelling
// a model drifts into (bash, web_fetch). Handler, description, schema, prompt and
// permission all delegate to the wrapped tool, so an alias is behaviourally
// identical — it only repairs exact-match dispatch lookup (norma's execOne does
// reg.Get(use.Name), no case folding). See issue #19.
type aliasTool struct {
	actool.CoreTool
	name string
}

func (a *aliasTool) Name() string { return a.name }

// toolAliasNames returns the lowercase / snake_case / UPPER spellings a CamelCase
// tool name is commonly confused with, dropping the original and duplicates. A
// name already in lower/snake form yields nothing (no drift to defend against).
func toolAliasNames(name string) []string {
	if name == strings.ToLower(name) {
		return nil
	}
	candidates := []string{strings.ToLower(name), camelToSnake(name), strings.ToUpper(name)}
	out := make([]string, 0, len(candidates))
	seen := map[string]bool{name: true}
	for _, v := range candidates {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// camelToSnake converts CamelCase to snake_case (WebFetch → web_fetch,
// TodoWrite → todo_write) while leaving an all-caps run intact (LS → ls).
func camelToSnake(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				prev := runes[i-1]
				var next rune
				if i+1 < len(runes) {
					next = runes[i+1]
				}
				if (prev >= 'a' && prev <= 'z') || (next >= 'a' && next <= 'z') {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// addToolAliases registers drift-tolerant aliases for every CamelCase tool. Each
// alias is added to the returned tool list (so exact-match dispatch finds it) and
// its name is appended to deferred (so the schema is withheld and the model keeps
// seeing only the official CamelCase names — no duplicate exposure, no token
// waste). Names already taken by a real tool are skipped, so nothing is shadowed.
func addToolAliases(tools []actool.CoreTool, deferred []string) ([]actool.CoreTool, []string) {
	taken := map[string]bool{}
	for _, t := range tools {
		taken[t.Name()] = true
	}
	for _, n := range deferred {
		taken[n] = true
	}
	out := tools
	extra := deferred
	for _, t := range tools {
		for _, alias := range toolAliasNames(t.Name()) {
			if taken[alias] {
				continue
			}
			taken[alias] = true
			out = append(out, &aliasTool{CoreTool: t, name: alias})
			extra = append(extra, alias)
		}
	}
	return out, extra
}

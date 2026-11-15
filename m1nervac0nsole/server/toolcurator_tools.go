package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	actool "github.com/structuredstanza/norma/tool"
)

// Tool curator tools: the tool set of the "toolcurator" chat agent, which turns
// tooling the operator provides (a script, a repo, docs, a binary) into Toolbox
// entries: manifest templates and custom tools.
//
// Like the memory curator's, they are host tools built against the server and
// the binding is the security boundary: each is seeded into the tools table
// bound to "toolcurator" alone (seedToolCuratorTools). A host tool with no row is
// unfiltered by ToolResolve and would reach every agent, so the row must exist.
//
// The slice is propose-only. The three read tools change nothing; the three
// write tools (two proposals and the install) sit in
// intercept.approvalRequiredTools, so nothing is stored and no install script
// runs until the operator approves, and a proposed custom tool is created bound
// to no agent: giving an agent the ability to run it stays an operator action.

// toolCuratorAgent is the built-in chat agent these tools are bound to.
const toolCuratorAgent = "toolcurator"

// toolCuratorToolKeys are the tools the tool curator is bound to by default.
var toolCuratorToolKeys = []string{
	"toolbox_list", "toolbox_read", "toolbox_validate", "toolbox_propose_template", "toolbox_propose_tool", "toolbox_install",
}

// toolCuratorTools is the tool curator's tool set.
func (s *Server) toolCuratorTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolToolboxList(),
		s.toolToolboxRead(),
		s.toolToolboxValidate(),
		s.toolToolboxProposeTemplate(),
		s.toolToolboxProposeTool(),
		s.toolToolboxInstall(),
	}
}

// seedToolCuratorTools seeds each tool bound to "toolcurator" only, so
// ToolResolve keeps them off worker, planner, auto and every other agent. Seed
// is first-insert-only, so an operator's later binding edit survives restarts.
func (s *Server) seedToolCuratorTools() {
	bindings, _ := json.Marshal([]string{toolCuratorAgent})
	for _, t := range s.toolCuratorTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			log.Printf("[toolcurator] failed to seed %s: %v", t.Name(), err)
		}
	}
}

// toolboxSampleTarget stands in for the asset a run would target when
// toolbox_validate renders the default argv. It is only ever printed.
const toolboxSampleTarget = "example.com"

func (s *Server) toolToolboxList() actool.CoreTool {
	return roTool("toolbox_list",
		"List the Toolbox: manifest templates (id, source builtin|modified|custom, category, whether the binary is installed, description) and custom tools (key, kind, description, enabled, bound agents). "+
			"Call it first, before drafting anything: if the tool already exists, improve that entry instead of adding a duplicate. Pass q to narrow by id, name, key or description.",
		objSchema(map[string]any{
			"q": strParam("Optional: only entries whose id/key, name or description contains this text (case-insensitive)."),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q string `json:"q"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.ToLower(strings.TrimSpace(a.Q))
			match := func(text string) bool { return q == "" || strings.Contains(strings.ToLower(text), q) }

			templates := []map[string]any{}
			for _, m := range s.manifests().All() {
				if !match(m.ID + " " + m.Name + " " + m.Description) {
					continue
				}
				_, source, _ := s.manifestSource(m.ID)
				templates = append(templates, map[string]any{
					"id": m.ID, "source": source, "category": m.Category,
					"available": binaryPresent(m.Requires), "description": m.Description,
				})
			}
			rows, err := s.m.PG().ListTools()
			if err != nil {
				return actool.Errorf("list failed: " + err.Error()), nil
			}
			custom := []map[string]any{}
			for _, t := range rows {
				if t.System || !match(t.Key+" "+t.Description) {
					continue
				}
				custom = append(custom, map[string]any{
					"key": t.Key, "kind": t.Kind, "description": clipRunes(t.Description, 300),
					"enabled": t.Enabled, "agents": t.Agents,
				})
			}
			return jsonResult(map[string]any{"templates": templates, "custom_tools": custom})
		})
}

func (s *Server) toolToolboxRead() actool.CoreTool {
	return roTool("toolbox_read",
		"Read one Toolbox entry in full: a manifest template's TOML and its source (builtin|modified|custom), or a custom tool's row (kind, exec spec, schema, binding). Use it to base a new entry on a working one or to improve an existing one.",
		objSchema(map[string]any{
			"id": strParam("Template id or custom tool key (from toolbox_list)."),
		}, "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := strings.TrimSpace(a.ID)
			if id == "" {
				return actool.Errorf("id is required"), nil
			}
			if text, source, ok := s.manifestSource(id); ok {
				return jsonResult(map[string]any{"type": "template", "id": id, "source": source, "toml": text})
			}
			t, err := s.m.PG().GetTool(id)
			if err != nil {
				return actool.Errorf("read failed: " + err.Error()), nil
			}
			if t == nil || t.System {
				return actool.Errorf(fmt.Sprintf("no template or custom tool %q; call toolbox_list to see what exists", id)), nil
			}
			return jsonResult(map[string]any{"type": "custom_tool", "tool": t})
		})
}

func (s *Server) toolToolboxValidate() actool.CoreTool {
	return roTool("toolbox_validate",
		"Check a manifest template without saving it: it must parse, name only known keys, have non-empty description/accepts/requires and a positive command.timeout_seconds, render its default argv, and declare the rate control its category requires. "+
			"Returns {ok, id, program, args} on success (args is the argv rendered with default parameters against a sample target; check it is a real command line) or {ok:false, error}. Fix the error and call it again until ok, then propose.",
		objSchema(map[string]any{
			"toml": strParam("The complete manifest TOML."),
		}, "toml"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TOML string `json:"toml"`
			}
			_ = json.Unmarshal(in, &a)
			m, err := manifest.Check(a.TOML)
			if err != nil {
				return jsonResult(map[string]any{"ok": false, "error": err.Error()})
			}
			if refusal := curatorPolicyRefusal(m); refusal != "" {
				return jsonResult(map[string]any{"ok": false, "error": refusal})
			}
			out := map[string]any{"ok": true, "id": m.ID, "program": m.Command.Program}
			// manifest.Check already resolved the defaults, so a failure here only
			// means there is no argv to show; the verdict stays ok.
			// No proxy here: this argv is shown to the operator and the curator
			// runs outside a task session, so a credential must not be rendered.
			if vals, err := m.Effective(nil); err == nil {
				if args, err := m.Resolve(toolboxSampleTarget, vals, ""); err == nil {
					out["args"] = args
				}
			}
			return jsonResult(out)
		})
}

// provenancePrefix marks the curator's verification block in a stored template.
// It is a TOML comment, so the manifest parser ignores it, the operator's own
// text is kept as written, and the block lives in the existing
// tool_manifests.toml column instead of a new table.
const provenancePrefix = "# provenance: "

// withProvenance returns toml with the curator's verification block on top,
// replacing any earlier one so re-proposing a template cannot stack blocks.
func withProvenance(toml, provenance string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(provenance), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			b.WriteString(provenancePrefix + line + "\n")
		}
	}
	for _, line := range strings.Split(strings.TrimRight(toml, "\n"), "\n") {
		if strings.HasPrefix(line, provenancePrefix) {
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// httpIdentityPlaceholders are the argv placeholders that make a tool speak HTTP
// with the engagement's identity.
var httpIdentityPlaceholders = []string{"proxy", "proxyhost", "useragent"}

// usesHTTPIdentity reports whether the argv passes the engagement proxy or
// User-Agent, which makes the tool an HTTP client whatever category it claims.
func usesHTTPIdentity(m *manifest.Manifest) bool {
	for _, a := range m.Command.Args {
		for _, name := range httpIdentityPlaceholders {
			if strings.Contains(a, "{{ "+name) || strings.Contains(a, "{{"+name) {
				return true
			}
		}
	}
	return false
}

// curatorPolicyRefusal refuses a template that would dodge the mandatory rate
// declaration by its category. A web template must declare [limits]; so must a
// template that claims another category while passing the engagement's proxy or
// User-Agent. The shipped set has deliberate exceptions (the proxy caps them), so
// this gate runs where the curator writes, not in manifest.Check.
func curatorPolicyRefusal(m *manifest.Manifest) string {
	if m.Limits.Unit != manifest.RateNone {
		if _, ok := m.Params[m.Limits.Param]; !ok {
			return fmt.Sprintf("%s declares [limits] unit %q but no parameter named %q, so nothing would be capped",
				m.ID, m.Limits.Unit, m.Limits.Param)
		}
		return ""
	}
	if m.Category == manifest.CategoryWeb {
		return fmt.Sprintf("%s is a web template with no [limits]: declare the parameter that carries its throughput (unit rps, pps or threads) and a conservative default",
			m.ID)
	}
	if usesHTTPIdentity(m) {
		return fmt.Sprintf("%s passes {{ proxy }} or {{ useragent }} but declares no [limits]: a template that makes HTTP requests must declare its rate parameter whatever category it claims",
			m.ID)
	}
	return ""
}

func (s *Server) toolToolboxProposeTemplate() actool.CoreTool {
	return wrTool("toolbox_propose_template",
		"Propose a manifest template: saves it to the Toolbox after the operator approves, under the id in its TOML (an existing id replaces that template). Validate with toolbox_validate first; the same checks run again here and a failure is returned as the error. "+
			"provenance is required and is stored with the template: say which flags came from the tool's own help output, which emit fields came from a real run against a 127.0.0.1 fixture, and which parts you inferred. The operator reads it on the approval card and on the template page. "+
			"Only say it was saved when this returns success; a refused approval means nothing was stored.",
		objSchema(map[string]any{
			"toml":       strParam("The complete manifest TOML, exactly as validated."),
			"provenance": strParam("What was verified and what was inferred, one line each, e.g. \"verified: flags from httpx -h (v1.6.0)\", \"verified: emit fields from a 127.0.0.1 fixture run\", \"inferred: default thread count\". Required: a template with no stated provenance is refused."),
		}, "toml", "provenance"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TOML       string `json:"toml"`
				Provenance string `json:"provenance"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Provenance) == "" {
				return actool.Errorf("provenance is required: say which flags came from help output, which emit fields came from a fixture run, and what you inferred"), nil
			}
			m, err := manifest.Check(a.TOML)
			if err != nil {
				return actool.Errorf("template refused: " + err.Error()), nil
			}
			if refusal := curatorPolicyRefusal(m); refusal != "" {
				return actool.Errorf("template refused: " + refusal), nil
			}
			id, err := s.saveManifest(ctx, withProvenance(a.TOML, a.Provenance))
			if err != nil {
				return actool.Errorf("template refused: " + err.Error()), nil
			}
			_, source, _ := s.manifestSource(id)
			return jsonResult(map[string]any{
				"id": id, "source": source, "provenance": strings.TrimSpace(a.Provenance),
				"note": "Saved to the Toolbox with its provenance. If it needs a binary that is not installed, toolbox_install runs the template's install script once the operator approves that too.",
			})
		})
}

func (s *Server) toolToolboxProposeTool() actool.CoreTool {
	return wrTool("toolbox_propose_tool",
		"Propose a custom tool (a one-off script, a command or an HTTP call): created after the operator approves, enabled but bound to NO agent until the operator binds it on the Toolbox page. "+
			"Same validation as the Toolbox editor: key is lowercase letters/digits/underscores starting with a letter and must be new; kind is command, script (Python) or http; an http tool needs a schema with at least one property. "+
			"Prefer toolbox_propose_template for a CLI with parseable output. Only say it was created when this returns success.",
		objSchema(map[string]any{
			"key":         strParam("Tool name the agents will call, e.g. fetch_robots."),
			"description": strParam("What the tool does and when to use it; agents read this to decide."),
			"kind":        strParam("command | script | http"),
			"exec":        map[string]any{"type": "object", "description": "Execution spec. command: {\"command\": \"cmd with {param} placeholders\"}; script: {\"code\": \"python source\"}; http: {\"method\", \"url\", \"headers\", \"body\"} with {param} placeholders. Each accepts \"timeout_ms\"."},
			"schema":      map[string]any{"type": "object", "description": "JSON Schema of the parameters ({\"type\":\"object\",\"properties\":{...}}). Required with at least one property for http."},
		}, "key", "description", "kind", "exec"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Key         string          `json:"key"`
				Description string          `json:"description"`
				Kind        string          `json:"kind"`
				Exec        json.RawMessage `json:"exec"`
				Schema      json.RawMessage `json:"schema"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid arguments: " + err.Error()), nil
			}
			if len(a.Exec) == 0 || string(a.Exec) == "null" {
				return actool.Errorf("exec is required: the tool has nothing to run without it"), nil
			}
			// Agents: an empty, non-nil list, so the row is bound to nobody; the
			// operator binds it after reading the proposal.
			status, err := createCustomTool(s.m.PG(), customToolReq{
				Key: strings.TrimSpace(a.Key), Description: a.Description, Kind: a.Kind,
				Exec: a.Exec, Schema: a.Schema, Agents: []string{}, Enabled: true,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("tool refused (%d): %s", status, err)), nil
			}
			return jsonResult(map[string]any{
				"key":  strings.TrimSpace(a.Key),
				"note": "Created and enabled, bound to no agent. The operator binds it to an agent on the Toolbox page before anything can call it.",
			})
		})
}

// toolToolboxInstall runs a saved template's [install].script. It is its own
// approval, separate from the template save: the operator approves the install
// after reading the script, and the script runs inside the isolated
// install-purpose session rather than in the backend.
func (s *Server) toolToolboxInstall() actool.CoreTool {
	return wrTool("toolbox_install",
		"Install a saved template's declared [install].script. This is its own operator approval - nothing runs until a person approves the card - and the script runs inside the isolated install session, not the backend: no controller secrets, no unrestricted network, and only a staging prefix of its own is writable. "+
			"Write what the tool needs to $PREFIX/bin (PREFIX, HOME and TMPDIR are exported): on success the supervisor publishes it into the persistent toolbox bin directory, which is on PATH in every session and survives sandbox recreation. "+
			"Returns the bounded output plus what was recorded: the script digest, the source revision you pass, the binary version the session reported, the published path/digest/size, the time, and whether the tool is usable afterwards (verified). "+
			"A failed or unverified install is reported as such and publishes nothing: do not tell the operator the tool is ready unless verified is true.",
		objSchema(map[string]any{
			"id":              strParam("Template id whose [install].script to run (from toolbox_list)."),
			"source_revision": strParam("Optional: the repository revision the script installs from (commit sha or tag), recorded as provenance."),
		}, "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID             string `json:"id"`
				SourceRevision string `json:"source_revision"`
			}
			_ = json.Unmarshal(in, &a)
			id := strings.TrimSpace(a.ID)
			if id == "" {
				return actool.Errorf("id is required"), nil
			}
			m := s.manifests().Get(id)
			if m == nil {
				return actool.Errorf(fmt.Sprintf("unknown template %q; call toolbox_list for the ids", id)), nil
			}
			if strings.TrimSpace(m.Install.Script) == "" {
				return actool.Errorf(fmt.Sprintf("%s declares no [install].script, so there is nothing to install", id)), nil
			}
			return jsonResult(s.runManifestInstall(ctx, m, a.SourceRevision))
		})
}

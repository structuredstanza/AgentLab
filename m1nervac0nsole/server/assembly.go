package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
	"github.com/structuredstanza/norma/skill"
	actool "github.com/structuredstanza/norma/tool"
)

// wireAgentAugment connects the PG agent_visibility table into the agent runtime:
// an agent's visible skills are loaded from the filesystem and packed into one
// Skill meta-tool; its visible stdio MCP servers are spawned and expanded to
// mcp__server__tool. skillDir is the root directory of all skill subdirectories.
// hostTools, if set, returns runtime host tools (currently the traffic tools when
// capture is on) to add to EVERY agent's base list — the DB tools table then
// filters them per-agent binding. Empty/nil → no host tools this run (capture off).
func wireAgentAugment(pg *db.DB, skillDir string, hostTools func() ([]actool.CoreTool, map[string][]string)) {
	// One authorizer for the process: it caches a verdict per destination under
	// the stored policy revision, and the MCP tools are assembled per run.
	researchAuth := netpolicy.NewAuthorizer(pg)
	// tcp_probe dials from the backend, outside the gateway: it asks the same policy.
	agent.NetPolicyAuthorizer = researchAuth
	agent.ToolAugment = func(ctx context.Context, agentKey string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		a, err := pg.GetAgentByKey(agentKey)
		if err != nil || a == nil {
			return nil, agent.DeferredInfo{}, nil
		}
		var extra []actool.CoreTool

		// --- skills: load visible skills into reg (used for the Skill meta-tool
		// and to know which MCP servers are skill-gated). ---
		var reg *skill.Registry
		if names, _ := pg.AgentSkillNames(a.ID); len(names) > 0 {
			nameSet := make(map[string]bool, len(names))
			for _, n := range names {
				nameSet[n] = true
			}
			if allReg, err := skill.LoadDir(skillDir); err == nil && allReg != nil {
				reg = skill.NewRegistry()
				for _, s := range allReg.List() {
					// match by directory name (Base of Dir), not by skill display Name
					if s.Dir != "" && nameSet[filepath.Base(s.Dir)] {
						reg.Add(s)
					}
				}
				if len(reg.List()) == 0 {
					reg = nil
				}
			}
		}
		// A server named by any visible skill's `mcps:` is skill-gated: its tools
		// are deferred + locked (not in the global block) until that skill loads.
		gated := map[string]bool{}
		if reg != nil {
			for _, s := range reg.List() {
				for _, srv := range s.MCPs {
					gated[srv] = true
				}
			}
		}

		// --- mcp: connect enabled servers that are directly visible to this agent
		// OR skill-gated (named in a visible skill's mcps field). Directly-visible
		// and NOT gated → global (unlocked from session start). Skill-gated →
		// deferred until that skill is invoked (regardless of direct visibility).
		var closers []io.Closer
		serverTools := map[string][]string{} // server name → its tool names
		var allNames, globalNames []string
		globalSet := map[string]bool{}
		{
			mcpIDs, _ := pg.AgentVisible(a.ID, "mcp")
			want := idSet(mcpIDs)
			all, _ := pg.ListMCP()
			assets := pg.Assets()
			for _, m := range all {
				if !m.Enabled {
					continue
				}
				directVisible := want[m.ID]
				skillGated := gated[m.Name]
				if !directVisible && !skillGated {
					continue // neither directly visible nor referenced by a visible skill
				}
				launch, revoke, err := researchServer(ctx, m)
				if err != nil {
					log.Printf("[mcp] %s not launched: %v", m.Name, err)
					_ = pg.UpdateMCPHealth(m.ID, false, "research proxy: "+err.Error())
					continue
				}
				cl, err := connectMCP(ctx, launch)
				if err != nil {
					if revoke != nil {
						revoke()
					}
					log.Printf("[mcp] %s connection failed: %v", m.Name, err)
					_ = pg.UpdateMCPHealth(m.ID, false, "connect: "+err.Error())
					continue
				}
				closers = append(closers, cl)
				if revoke != nil {
					closers = append(closers, closerFunc(revoke))
				}
				ts, err := cl.Tools(ctx)
				if err != nil {
					log.Printf("[mcp] %s tools/list failed: %v", m.Name, err)
					_ = pg.UpdateMCPHealth(m.ID, false, "tools/list: "+err.Error())
					continue
				}
				_ = pg.UpdateMCPHealth(m.ID, true, "")
				for _, t := range ts {
					// The research browser exposes reading and extraction only;
					// anything else it offers is not assembled at all.
					if !researchToolAllowed(m.Name, t.Name()) {
						continue
					}
					// A browser navigation is the one MCP call that crosses the
					// boundary; judge it here, where every agent's MCP tools are
					// assembled: the research policy for the research browser, the
					// task scope for the testing one.
					t = researchGuardTool(researchAuth, t)
					t = scopeGuardTool(assets, t)
					extra = append(extra, t)
					allNames = append(allNames, t.Name())
					serverTools[m.Name] = append(serverTools[m.Name], t.Name())
					if directVisible && !skillGated {
						// directly visible and not gated → available from session start
						globalNames = append(globalNames, t.Name())
						globalSet[t.Name()] = true
					}
					// skill-gated tools stay out of globalNames; unlocked via unlockSkill()
				}
			}
		}

		// Shared call-gate: global MCP tools are unlocked from the start; skill-gated
		// ones are unlocked when their skill loads (or replayed from history — C2).
		unlock := actool.NewUnlockSet(globalNames...)
		unlockSkill := func(skillName string) {
			if reg == nil {
				return
			}
			if s, ok := reg.Get(skillName); ok {
				for _, srv := range s.MCPs {
					unlock.Add(serverTools[srv]...)
				}
			}
		}

		// Skill meta-tool: on load, unlock the skill's MCPs and reveal their names
		// (the ones not already in the global block).
		if reg != nil {
			reg.OnInvoke = func(s skill.Skill) string {
				unlockSkill(s.Name)
				var reveal []string
				for _, srv := range s.MCPs {
					for _, n := range serverTools[srv] {
						if !globalSet[n] {
							reveal = append(reveal, n)
						}
					}
				}
				return actool.RenderDeferredToolsBlock(reveal)
			}
			// Attribution for the usage ledger: ToolAugment only gets (ctx, agentKey),
			// so the run's task/session ids ride in on the ctx (agent.RunInfo). Read it
			// once here — this closure is rebuilt per run, so the captured value always
			// belongs to this run.
			extra = append(extra, meterSkillTool(reg.Tool(), pg, reg, a.Key, agent.RunInfoFrom(ctx)))
		}

		// host tools (traffic / orchestration / custom) — added to every agent's base;
		// ToolResolve then keeps them only for agents the tool is bound to. Custom
		// tools flagged deferred contribute their names to the deferred wiring so
		// their schema is withheld (SearchExtraTools/ExecuteExtraTool), same as MCP.
		if hostTools != nil {
			ht, deferredBinds := hostTools()
			extra = append(extra, ht...)
			for name, boundAgents := range deferredBinds {
				if !contains(boundAgents, a.Key) {
					continue // only defer names this agent is actually bound to
				}
				allNames = append(allNames, name)       // schema withheld from the prompt
				globalNames = append(globalNames, name) // advertised in the deferred block
				globalSet[name] = true
				if unlock != nil {
					unlock.Add(name) // global deferred → callable from the start
				}
			}
		}

		cleanup := func() {
			for _, c := range closers {
				_ = c.Close()
			}
		}
		def := agent.DeferredInfo{
			Deferred:    allNames,
			GlobalNames: globalNames,
			Unlock:      unlock,
			UnlockSkill: unlockSkill,
		}
		return extra, def, cleanup
	}
}

// closerFunc lets a plain function join the MCP closers, so a research session
// credential is revoked when the run's MCP children are closed.
type closerFunc func()

func (f closerFunc) Close() error {
	f()
	return nil
}

// researchServer returns the row to launch for m. The research browser gets the
// gateway as its --proxy argument, because its own HTTP client ignores
// HTTP_PROXY, and the recorder's CA in SSL_CERT_FILE, because the recorder
// re-signs every certificate it forwards; revoke ends the session credential
// once the child is gone. Every other server is launched exactly as stored.
func researchServer(ctx context.Context, m *db.MCPServer) (*db.MCPServer, func(), error) {
	if m.Name != researchMCPServer {
		return m, nil, nil
	}
	var proxy, ca string
	var revoke func()
	if researchProxyFor != nil {
		var err error
		proxy, ca, revoke, err = researchProxyFor(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	launch := *m
	// The CA is set only while a recorder runs. Without one it is removed rather
	// than left pointing at a file that is gone, which would fail every HTTPS
	// load the child makes.
	env := jsonStrMap(m.Env)
	delete(env, "SSL_CERT_FILE")
	if ca != "" {
		env["SSL_CERT_FILE"] = ca
	}
	launch.Env, _ = json.Marshal(env) // a string map cannot fail to marshal
	if proxy != "" {
		launch.Args, _ = json.Marshal(append(jsonStrSlice(m.Args), "--proxy", proxy))
	}
	return &launch, revoke, nil
}

func idSet(ids []int64) map[int64]bool {
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// seedPrompts writes each built-in agent's code-default prompt body into
// agent_prompts on startup — first-insert only (SeedPromptIfEmpty is a no-op once
// any version exists), so the DB becomes the authoritative editable source while
// user edits survive restarts. Runs after seedBuiltins has created the agent rows.
func seedPrompts(pg *db.DB) {
	for key, tmpl := range agent.BuiltinPromptSeeds() {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			log.Printf("[prompts] skipped seeding %s: agent does not exist (%v)", key, err)
			continue
		}
		if err := pg.SeedPromptIfEmpty(a.ID, tmpl); err != nil {
			log.Printf("[prompts] failed to seed %s: %v", key, err)
		}
	}
	migrateLegacyDefaultPrompts(pg)
}

// legacyPromptHashes maps a built-in agent key to the SHA-256 of the pre-English
// default prompt body shipped by older builds. A stored prompt whose digest matches
// is untouched default text and is replaced by the English default; any other body
// was user-edited and is kept as-is.
var legacyPromptHashes = map[string]string{
	"goals":     "72a7a0159443b41dde29dfba8a3de6a2c8a15b273935495a7b88561fa708aa68",
	"planner":   "14e163f4a44da9fee20a214048a607adc3659b2025275569eb512532ca8c15d5",
	"mainagent": "12bb69ee0886c4fb9beb936d882021a91104860f1da69a5e3eda3d9e345cd399",
	"worker":    "80fbb1c610dd57e266c20b9145793339eee540b809f6db8f5336261b45879f08",
	"auto":      "b2a71b82243607337b19f0642317fed88c144d536412d80eaaf90807f2905a1d",
	"pentest":   "a54bd5713b1c121d0f2ff3a72e0304820b1368c4b4b8159d5d651895663ac652",
	"reporter":  "8ba98208f6c5f2ccb103c88ef13239c4264733400c0e3dfec96d3a3572d78d39",
	"retester":  "d08326aa9fbd9a1367e716cf7ef46533e9096e9a56493f77d364efbf696f7fe0",
}

// legacyWrapupHashes and legacyTaskTimeoutHashes are the digests of the old
// built-in wrap-up defaults. A persisted override matching one is a stale copy of
// the default and is cleared so the English built-in default applies.
var legacyWrapupHashes = map[string]string{
	"goals":     "38e86a4d039ab60fe14e8bfed44102ef965e0ae802f9aa2f490185ee001b7cd7",
	"planner":   "0b1666676c3e471c7607babefb45cca69e0afd9df2b1c779d213c48c794caf84",
	"mainagent": "ff92516c4d1e38c96bb549661d68446a0243841003124d2597dcc33fd43a2c0c",
	"worker":    "f645f8a16ed1d7a8c1d8db2c94bc1049ef4274119a983a20ff846331056f91a0",
	"auto":      "38e86a4d039ab60fe14e8bfed44102ef965e0ae802f9aa2f490185ee001b7cd7",
	"pentest":   "38e86a4d039ab60fe14e8bfed44102ef965e0ae802f9aa2f490185ee001b7cd7",
	"reporter":  "38e86a4d039ab60fe14e8bfed44102ef965e0ae802f9aa2f490185ee001b7cd7",
	"retester":  "38e86a4d039ab60fe14e8bfed44102ef965e0ae802f9aa2f490185ee001b7cd7",
}

var legacyTaskTimeoutHashes = map[string]string{
	"planner": "dbea17e930be983e40420bfbe5ef8912878929e8b6e5848ac36ef52fe53bb0a8",
	"worker":  "412e5c7cf45ba878425bb3be491659a178c0cee66bcfb717324ea9e4557d6aba",
}

// legacyGenericAssistantHash is the digest of the Chinese-era DefaultAssistantPrompt,
// which older builds seeded into every new custom agent.
const legacyGenericAssistantHash = "a179c990bff1ab4e0a6f326945a1c44036ef4c8a54c7c5b635965f6cefdc9f0a"

func promptDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// migrateLegacyDefaultPrompts replaces untouched Chinese-era built-in defaults with
// the English ones. Each step is hash-matched, so custom bodies are never touched
// and a second run is a no-op. Old prompt versions remain in agent_prompts history.
func migrateLegacyDefaultPrompts(pg *db.DB) {
	newBodies := agent.BuiltinPromptSeeds()
	newBodies["reporter"] = agent.ReporterDefaultPrompt
	newBodies["retester"] = agent.RetesterDefaultPrompt
	for key, oldHash := range legacyPromptHashes {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			continue
		}
		if cur, err := pg.CurrentPrompt(a.ID); err != nil {
			log.Printf("[prompts] migrate %s: read current prompt: %v", key, err)
		} else if body := newBodies[key]; body != "" && promptDigest(cur) == oldHash {
			if _, err := pg.SavePrompt(a.ID, body, "Built-in default (English)", "system"); err != nil {
				log.Printf("[prompts] migrate %s: save English default: %v", key, err)
			}
		}
		if a.WrapupPrompt != "" && promptDigest(a.WrapupPrompt) == legacyWrapupHashes[key] {
			if err := pg.SetAgentWrapupPrompt(key, ""); err != nil {
				log.Printf("[prompts] migrate %s: clear wrap-up default: %v", key, err)
			}
		}
		if old := legacyTaskTimeoutHashes[key]; old != "" && a.TaskTimeoutWrapupPrompt != "" && promptDigest(a.TaskTimeoutWrapupPrompt) == old {
			if err := pg.SetAgentTaskTimeoutWrapup(key, "", a.TaskTimeoutWrapupMaxTurns); err != nil {
				log.Printf("[prompts] migrate %s: clear task-timeout wrap-up default: %v", key, err)
			}
		}
	}
	// Any other agent (custom included) still holding the shipped generic default.
	agents, err := pg.ListAgents()
	if err != nil {
		log.Printf("[prompts] migrate generic assistant default: list agents: %v", err)
		return
	}
	for _, a := range agents {
		if _, handled := legacyPromptHashes[a.Key]; handled {
			continue
		}
		// Custom roles can carry the shipped generic wrap-up copy. Clear it on its own so a
		// custom main prompt cannot skip it. Max turns are kept; other wrap-ups stay untouched.
		if a.WrapupPrompt != "" && promptDigest(a.WrapupPrompt) == legacyWrapupHashes["auto"] {
			if err := pg.SetAgentWrapupPrompt(a.Key, ""); err != nil {
				log.Printf("[prompts] migrate %s: clear generic wrap-up default: %v", a.Key, err)
			}
		}
		cur, err := pg.CurrentPrompt(a.ID)
		if err != nil || promptDigest(cur) != legacyGenericAssistantHash {
			continue
		}
		if _, err := pg.SavePrompt(a.ID, agent.DefaultAssistantPrompt, "Built-in default (English)", "system"); err != nil {
			log.Printf("[prompts] migrate %s: save English assistant default: %v", a.Key, err)
		}
	}
	migrateLegacyJudgePrompt(pg)
}

// legacyJudgePromptHash is the digest of the Chinese-era intercept judge prompt. Older
// builds shipped it, and the config writer persisted it as a custom override because it
// differed from the then-current default.
const legacyJudgePromptHash = "d6bf0f5fae9e98f551de5ac73a935a667f1c4eb18b30fd9da2ffb3e851ea2c15"

// migrateLegacyJudgePrompt clears a stored llm_judge_prompt only when it is exactly the old
// shipped judge prompt, so the English built-in applies at runtime. An empty value is the
// existing "use built-in" state. Other judge fields and arbitrary custom prompts are kept.
func migrateLegacyJudgePrompt(pg *db.DB) {
	v, ok, err := pg.GetSetting("llm_judge_prompt")
	if err != nil {
		log.Printf("[prompts] migrate judge prompt: read: %v", err)
		return
	}
	if !ok || promptDigest(v) != legacyJudgePromptHash {
		return
	}
	if err := pg.SetSetting("llm_judge_prompt", ""); err != nil {
		log.Printf("[prompts] migrate judge prompt: clear legacy default: %v", err)
	}
}

// wireTools seeds the built-in tool catalog (idempotent, first-insert only so page
// edits survive restart) and wires the DB tools table into the agent runtime: at
// tool-assembly time each built-in tool is filtered by its agent binding / enabled
// flag and, if kept, wrapped so the model sees the DB-overridden description/schema
// and default-valued parameters get injected. MCP/skill/host tools have no row and pass through.
func wireTools(pg *db.DB, domainReg map[string]actool.CoreTool) {
	agent.FindingTrafficBindingEnabled = func() bool { return pg.GetBool(settingAgentTrafficBinding, false) }
	// Adopt existing rows into seed tracking before seeding, so a description or
	// schema changed in code reaches a database that predates the tracking.
	if err := pg.BackfillToolSeedBaseline(); err != nil {
		log.Printf("[tools] seed baseline backfill failed: %v", err)
	}
	// Seed the built-in domain tools (first-insert only; DO NOTHING preserves edits).
	// No startup prune: rows we didn't seed are left alone so future user-defined
	// custom tools (system=false, added via the UI) survive restarts.
	for _, s := range agent.BuiltinToolSeeds() {
		schema, _ := json.Marshal(s.Schema)
		agents, _ := json.Marshal(s.Agents)
		if err := pg.SeedTool(s.Key, s.Desc, schema, agents); err != nil {
			log.Printf("[tools] failed to seed %s: %v", s.Key, err)
		}
	}
	// Seed the traffic host tools so they're bindable per-agent like built-ins.
	// Default binding = worker (preserves prior behavior). Their runtime availability
	// is still gated by the global capture switch (hostTools() returns them only when
	// capture is on), so an off-capture binding simply never surfaces the tool.
	trafficAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range traffic.SeedToolMetas() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := pg.SeedTool(t.Name(), t.Description(), schema, trafficAgents); err != nil {
			log.Printf("[tools] failed to seed %s: %v", t.Name(), err)
		}
	}
	// bashInteractiveShellNote is appended to Bash's description ONLY for agents whose
	// interactive_shell is on, so Bash points at shell_open for interactive programs
	// without ever referencing a tool that isn't injected (§14.1/§14.2).
	const bashInteractiveShellNote = "\n\nFor programs that need interactive input (msfconsole, interactive ssh logins, REPLs such as mysql, psql, or python, password or yes/no prompts, nc reverse shells), do not use Bash: it has no stdin and will hang. Use shell_open to start an interactive session instead (close it with shell_close). Use Bash only for one-shot, non-interactive commands."
	agent.ToolResolve = func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool {
		rows, err := pg.ListTools()
		if err != nil {
			log.Printf("[tools] failed to read the tool table; allowing tools by code default: %v", err)
			return tools
		}
		byKey := make(map[string]*db.Tool, len(rows))
		for _, t := range rows {
			byKey[t.Key] = t
		}
		runInfo := agent.RunInfoFrom(ctx)
		resolve := func(t actool.CoreTool, row *db.Tool) actool.CoreTool {
			var schema map[string]any
			if len(row.Schema) > 0 {
				_ = json.Unmarshal(row.Schema, &schema)
			}
			return meterTool(agent.DecorateTool(t, row.Description, schema), pg, row.Key, agentKey, runInfo)
		}
		out := tools[:0:0]
		for _, t := range tools {
			row, known := byKey[t.Name()]
			if !known { // MCP/skill/host tool: no row → untouched
				out = append(out, t)
				continue
			}
			if !row.Enabled || !contains(row.Agents, agentKey) {
				continue // disabled globally or not bound to this agent → drop
			}
			out = append(out, resolve(t, row))
		}
		// inject: domain tools bound to this agent in the DB but absent from the
		// incoming list. Covers agents (Auto, custom) whose base only has DefaultTools
		// and therefore never includes ToolSet-backed domain tools. Per-task instances
		// in the base always win: inList is built from the original incoming list so a
		// worker's own upsert_asset is never shadowed by the server-level registry copy.
		if len(domainReg) > 0 {
			inList := make(map[string]bool, len(tools))
			for _, t := range tools {
				inList[t.Name()] = true
			}
			for _, row := range rows {
				if row.Kind == "shell" || !row.Enabled || !contains(row.Agents, agentKey) || inList[row.Key] {
					continue
				}
				inst, ok := domainReg[row.Key]
				if !ok {
					continue // not a domain tool; custom/host tools are injected via hostTools()
				}
				out = append(out, resolve(inst, row))
			}
		}
		// shell hints: user-defined kind="shell" tools are not callable — they are
		// environment declarations that tell the model which command-line tools are
		// installed. Collect the ones bound to this agent and append to Bash's description.
		var shellHints []string
		for _, row := range rows {
			if row.Kind == "shell" && row.Enabled && contains(row.Agents, agentKey) {
				shellHints = append(shellHints, "- "+row.Key+": "+row.Description)
			}
		}
		if len(shellHints) > 0 {
			note := "\n\nThe following tools are installed in this bash environment and can be called directly through Bash:\n" + strings.Join(shellHints, "\n")
			for i, t := range out {
				if t.Name() == "Bash" {
					out[i] = agent.DecorateTool(t, t.Description()+note, t.InputSchema())
					break
				}
			}
		}
		// interactive shell: gated purely by the agent's interactive_shell flag (like
		// web_search), NOT by tools-table binding. When on, inject the 5 shell_* tools
		// and COUPLE the Bash description addendum so it points at shell_open — and never
		// dangles when off. See docs/\u4ea4\u4e92\u5f0fshell\u8bbe\u8ba1.md §14.2.
		if !actool.InteractiveShellDisabled() {
			if a, err := pg.GetAgentByKey(agentKey); err == nil && a != nil && a.InteractiveShell {
				out = append(out, actool.ShellSessionTools()...)
				for i, t := range out {
					if t.Name() == "Bash" {
						out[i] = agent.DecorateTool(t, t.Description()+bashInteractiveShellNote, t.InputSchema())
						break
					}
				}
			}
		}
		return out
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// buildDomainReg builds a name→CoreTool registry from a server-level ToolSet
// (real AssetStore, nil ExplorationStore, taskID=0). Used by ToolResolve to inject
// domain tools into agents (Auto, custom) that don't own a per-task ToolSet.
// nil as → returns nil (no injection, graceful degradation).
//
// The nil ExplorationStore is deliberate — these instances are task-less by
// construction — so every tool here must tolerate it. Asset/company tools do
// (they only need the AssetStore); the exploration-graph tools refuse with a
// clear message via ToolSet.needExploration. Binding one of them to a task-less
// agent in the tools table is therefore a useless tool, not a crash.
func buildDomainReg(as *db.AssetStore) map[string]actool.CoreTool {
	if as == nil {
		return nil
	}
	serverTS := agent.NewToolSet(nil, "")
	serverTS.SetAssetStore(as, as.Companies())
	reg := make(map[string]actool.CoreTool)
	for _, t := range serverTS.AllDomainTools() {
		reg[t.Name()] = t
	}
	return reg
}

func jsonStrSlice(raw json.RawMessage) []string {
	var out []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func jsonStrMap(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

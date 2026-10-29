package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

// wireAgentAugment connects the PG agent_visibility table into the agent runtime:
// an agent's visible skills are loaded from the filesystem and packed into one
// Skill meta-tool; its visible stdio MCP servers are spawned and expanded to
// mcp__server__tool. skillDir is the root directory of all skill subdirectories.
// hostTools, if set, returns runtime host tools (currently the traffic tools when
// capture is on) to add to EVERY agent's base list — the DB tools table then
// filters them per-agent binding. Empty/nil → no host tools this run (capture off).
func wireAgentAugment(pg *db.DB, skillDir string, hostTools func() ([]actool.CoreTool, map[string][]string)) {
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
			for _, m := range all {
				if !m.Enabled {
					continue
				}
				directVisible := want[m.ID]
				skillGated := gated[m.Name]
				if !directVisible && !skillGated {
					continue // neither directly visible nor referenced by a visible skill
				}
				cl, err := connectMCP(ctx, m)
				if err != nil {
					log.Printf("[mcp] %s connection failed: %v", m.Name, err)
					continue
				}
				closers = append(closers, cl)
				ts, err := cl.Tools(ctx)
				if err != nil {
					log.Printf("[mcp] %s tools/list failed: %v", m.Name, err)
					continue
				}
				for _, t := range ts {
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

// legacyToolRow is one built-in tool as first seeded in Chinese: the key, the digest
// of its seeded description, and the digest of its canonical JSON schema. A stored
// field matching its digest is the untouched seeded default; edited and custom
// fields never match and are kept.
type legacyToolRow struct{ key, desc, schema string }

var legacyToolRows = []legacyToolRow{
	{"add_company_scope", "c460db4b5834fb3c22d27937a2b87902cd9eaf4246e53e7e44a4081c5d6243f0", "a2576503fca196496fb810873d6eab4a438fc3baba8b403d48d5aca8906304b1"},
	{"add_hint", "629c6494669d5d5b53b951c70c949833dc1a885e91c85469caa6a9527b9ca61e", "81a3edf9b74a68161abf44177d878e074c2cd83029ffe3b481e4237d46e02c45"},
	{"add_intent", "6754abb7254a6a7ec1cf980f00a768d384d473f84d4c90b1e0446963c0a92767", "4f1e846d98a2d864aaba60343c43646724370f4a4373ec126cce39315bbb00c0"},
	{"add_task_hint", "4eb1f206d86556f2ccc0a394e5058250a602848a109f217cbd00bd3338b72b7e", "8f1a0868a563f27a4377168d01e0221ff0536ffee3465979cde902f65b59cec1"},
	{"add_task_scope", "23caa9d2e944fac4bd7f329bd5de45344a0633ed9f554759c4be753e5c9cc9a3", "6148afed45ca873053d7d49426c6dccffc04a0acfc3167783aee231365bdcb57"},
	{"bind_finding_traffic", "e3ca4e11bf4064efe57ae573a90c73d7e9e8abf5185ae0c108c1984ae4d879af", "c6e20fef4f661a056dbcfae8017faa878acb05afcdc0c6645ab89d921ad0dbb1"},
	{"create_custom_tool", "7bfdeabe156fc42becdab03079dab0f7d4d4aead08b0f782f537533121485a28", "133e4656acfc4bfcbb2c7af39f1799062b526f526088a07debd88275b5a96f55"},
	{"create_mcp", "e71f9d4f5647c8c57d7c0fbe1b86795060e3c31c76fd1d58122061d907b52595", "551c72ef5a9fc82e403bc743f66cef056218298f963c2b1c5aecb26a14fa580a"},
	{"create_skill", "40a5e60ab56cebb9f574dc9fb3bb6f2b418c8d8baa452ff441fbf32c1aa82d2e", "79ca2cee65e01d9fe85af95733cf5d1c2801559e76be555b942a37f9d8389360"},
	{"delete_assets_by_host", "194b747997ca61c2b7a6929f61f7642dcc7e2ca24fb37c279fe6d6297ef0a1f0", "c8537929e7f4449cc5cdca4284432c48f953ce14cdfdca5f78f16113972723f6"},
	{"expand_digest", "e0807f8e20e25f3f682a51c688160942e568ac80ca0d16819e7361a9abe68fb1", "7ccbb8680abca77b46d38ef17eadac5f63e6967a06ca4edddae75498f2a540cb"},
	{"get_finding_retest_context", "c7d224d35a8f484dab0bf72adea727236364b11f7cafe1674f60d81c7985d876", "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"},
	{"get_finding_traffic", "9fbbf5633682ea7d6260cbbfcf20ffd0bf073d659123c8615cc79e753f38afd6", "1d9e37e5413e4536d3c03093734dbe93b66f73c611991d155ebb4066e1ee12c5"},
	{"get_task_graph", "3f2787299dbfa6bb755a7653cb3cab0c00dece049f4c9a4203ebb105dff80ab8", "5ac12509110ede5be63ffacb351c9033692963b4f7fbaec9e010789c2848136a"},
	{"get_task_node_detail", "a0dce2524d6ebc8dc5f94765419d398dd820811a1440169a6f406914a0c2804f", "63e322daf00af66c3bdb4760f0ba0c840e55c37702ae96e8f1bb9f4c180abd3d"},
	{"get_task_worker_trace", "5c5e3a70e3c8f650b094fcf1296b53de4f7f1763574b68a9142787b2adb77c28", "e16e6db15ce1b49fa7f48f246fdf95f00914f3614e8ee608f2d6b6b43dfabca0"},
	{"get_worker_output", "f25ffdc9580a39cb8f6aca6c3bde7860934b73b579157533e97ee85ee271f21e", "9debd13d7fbd68abb833e90e1255181b18b4e2b4608589eab9e316c24a2d373f"},
	{"get_worker_trace", "5931721f9a063a608b1ad5d72c2ca48b0bd763d607769c4d2161f074c23835ec", "a8e4b3a384fb993a4e93c6a849abfa1530575d539497370fda4590dcc5df4ee4"},
	{"goal_met", "cba19394662c07ae525bcf3e21ead34b671a3e391c4e2a020518d4b096a0ac00", "fb8a1cce4d627271fec128df490217763a1789e5db23251b47b416be3373ced5"},
	{"graph_overview", "541280dbe0192fe121e79d956d9bc41553fa2b317a344cf635ee602aa196ada3", "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"},
	{"insert_assets", "c377ce43215f3b6b573b21e301b27180e62a0cc2a480f7b41d54f61692167dbd", "8a901f4ed1345e55f6f6f4d406e80abc6556cb4d272abe7e7f132ab522eb0984"},
	{"kill_work", "34036c67e6fa85c1abe66fb5983e390c97acc525b499d6cad20e907877002db9", "5b3c16008cf2f3b78d7ba2b858ecfaf0ed3623108f9e7de80a5c284c876eedff"},
	{"list_assets", "cf302317a50c3f326e7eaefcd0d7f038bac04424d84cf3deeeb602198aa11aff", "49780a5a9e31416ad279a5d82e0a091a9d9cb361b17b9afeb33299fa87578e21"},
	{"list_companies", "100d9924f89e3c50313af8296dafbc16d802733995f32f09cb24709276d2d9a3", "989193dca6a1b0098cf897b6a0dd1461927981c03a383287c52f2a49cdcd80f4"},
	{"list_facts", "367be32e153ea77e11ab5d4fdc25b8e2a1a7b733cc8e4bbe20df592c322283e0", "fd95769c695eb8bbd5412720e745503c7412314865f99e6117e441536b194aed"},
	{"list_findings", "1e25104858ba614987dee500ff60d67e1fe837910f38ea750d9e2d2e8312bc15", "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"},
	{"list_goals", "8badb45c95ec41fd8208f127cf91db19072b586ce25f82893abe5f320aedd433", "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"},
	{"list_llm_profiles", "e4c1aac1216302ab483281f660ae6d528f6aa69fb76605d93fa8b27083aa98ef", "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"},
	{"list_task_findings", "989043941aa39a3eff03f1f9d8088c392301a16dfe113d465301f08f7ac55ac0", "5ac12509110ede5be63ffacb351c9033692963b4f7fbaec9e010789c2848136a"},
	{"list_task_worker_traces", "db57bc2c72a4b4e53a9b625fd1158b117521c4104f7d4a7c244b299fb7f15c04", "5ac12509110ede5be63ffacb351c9033692963b4f7fbaec9e010789c2848136a"},
	{"list_tasks", "3d5515eb6136cead1b9dd4d3c11368051794ddc9a98c0012d883c7d9f59ac8c3", "efddc7bd8bbcef73a14eb1ace1ffdaec81e518ef1e13c1e9271d0b8acb694a49"},
	{"list_untested_assets", "751b0466c5ae59415d9c4a375ea4fc271f7b558f08342c8616d2579b3ee8e0d5", "0d337d041cbe18f46e5231362d91e22748ac7555b5766748026f3a4fba4dd481"},
	{"node_detail", "15b983a6465d518528df5f0042ca1fbfde7d6f6a7e9a8072656c34b982426417", "485579fda1c67a87fe3c64f5c60a0e6e51b3707cfbf8203081cc439351fbef1d"},
	{"pause_task", "d37d81dbb74321da470ca15e9b2cc6a04f85538f4b1611ef7e05f7f2e11bf6b1", "6058a042c6985e7599de7b7da5ed071d10254068396cb577c600be6320567799"},
	{"prove_goal", "8a40e6de058ad1d43cb9a666b045beeb868f8ad0a04320e76edba6d80fbfad66", "ef7eee2ca11acbab5a87f2aa6e8b8e31feb5fde2c077a8bcf16275feaebd5815"},
	{"record_fact", "8b9446c8c11a2cd45f6f5c45bb541a732c399415a718b44b69479e4619078593", "18152162586d4490c1651838f1811074e847183b99db9d9b49cbe323def55941"},
	{"record_finding_retest_result", "15bf1adec32a2b40e515263b5e8ab882b1328669687138dbbcd6cf74d606623f", "63bbe3d27a96ee382de6d3ec0795e9db0ba76854cf29b025f613aca16bdc97e3"},
	{"report_finding", "91675222f3d26a6fd171f6a7c1693c735d9985a7f93d16dcb77610f550d9655d", "b0d190c0a1dacc7282cb5e501a3ca64912a2908e72f8611a909330df492e29f2"},
	{"search_all_worker_traces", "a5198e6bdabe3c86b660a542fe30464ce6846cb522f29312f687ae84a340a0ac", "4ad19f7a06001c1bb3d1e91de3b37623ed93b7ec52b921875333e40addcea372"},
	{"search_task_worker_traces", "3a52371e00c54c2287ecdc0cd824faed79e4e409281d2b7a991b7fb619efcb34", "cc02120f5b50d1ad31028428f371591918de54e3764a611fefe4847fa9183827"},
	{"set_constraints", "46a72ba15f4381fd8c8e2835ca5dee1c3054de81dde1209b5f913f5f8e68a41d", "0f1c225612e984b42c0067642a722cc6ab964bd9aede8eb5286cf4e7fe9109f3"},
	{"set_goals", "0115b98eabff22aea4710fe36255915c9de3b48cd451111da3074118ae83d1dd", "a86e4aa2517af52563c767c80ff366b0d38d95f5e8e3a4a9938da6036cf5892e"},
	{"spawn_task", "d79dc8da3dbfe456ec7ca051ad6751ff8dbf3e2a4db00e0bd26bdbc2631471a6", "9c3d471cedb044b3695e47f63469d53a86ba7223b16a89f7d56c49653c2d3152"},
	{"steer_work", "a7a86be80c94c7e3525493136124939428413a3311b5283afa66256da6b5e135", "b8af9ecbc011be98992ca412004f36d4d1bcc5963c42f6601f47737096bab6ac"},
	{"traffic_blob", "315f23469723e3c655c74e77f59e87608d750aebc2dce3b14619b24e1a3953c2", "3ee745920a6633c040f361d55a07504b4eecd05427297072fa28a90f770b8c1d"},
	{"traffic_get", "f530c0796b3822cde3bd18677d07b4189de5122dca6109ecbe8cd0e9a6e2f790", "fe9b7d35c8afb03c9cfe89f02e9be1493c8946ae1d56b95bffa2cea33f1224c9"},
	{"traffic_search", "68cd3bfc0d83573b4696a2015b346f60d4950746d08b9658a1f930965d094b95", "b4fc267a72e14b3fd53e235f3ee2786736de51900349fda64c5fab6600839eb3"},
	{"update_custom_tool", "f44f48e618598dd2a99e2a2e2cf355da52751dc5f74734616772158c13a9e50c", "0c9a63c7746da157308dfc71862c2bdb7b855c4348d4d377380f3a48237d3e9a"},
	{"update_finding_report", "243d0fbc8e96f7bb76ac8e1e766baa1fec0c61c458d0689bcc50b5624bdeca9f", "0cdf7cf2e4bc901f8734a01a982298f41f16b1f31be3842217525aa608972508"},
	{"update_mcp", "f045b5bd141083f8837c0958af8fdcce92b120a164b407a62d77063926a61f10", "3886ac763c77090161980af5ca0cfb02e500169bea33c06cc40c7587e46343b4"},
	{"update_skill_file", "c9c09017e8049d928603dbbfbfc66078d64ef5889368d4f96eb954d86fb6d994", "22bf9272dd59ffa5416a1c6be69b6f5ba512ed7de424f6cee714af209a49d0ae"},
}

// legacySchemaDigest hashes a JSON schema in canonical form (sorted keys, compact,
// no HTML escaping) so it matches the schema digests in legacyToolRows.
func legacySchemaDigest(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return promptDigest(strings.TrimSuffix(buf.String(), "\n"))
}

// migrateLegacyToolText refreshes built-in tool rows whose description or schema is
// still the Chinese seeded default. Seeds are first-insert only, so without this an
// existing database would keep the Chinese text forever. It runs after every built-in
// and server tool seed; agent bindings, enabled flags, and custom or edited fields are kept.
func migrateLegacyToolText(pg *db.DB, serverTools []actool.CoreTool) {
	type canonTool struct {
		desc   string
		schema any
	}
	canon := make(map[string]canonTool)
	for _, s := range agent.BuiltinToolSeeds() {
		canon[s.Key] = canonTool{s.Desc, s.Schema}
	}
	for _, t := range traffic.SeedToolMetas() {
		canon[t.Name()] = canonTool{t.Description(), t.InputSchema()}
	}
	for _, t := range serverTools {
		canon[t.Name()] = canonTool{t.Description(), t.InputSchema()}
	}
	legacy := make(map[string]legacyToolRow, len(legacyToolRows))
	for _, r := range legacyToolRows {
		legacy[r.key] = r
	}
	rows, err := pg.ListTools()
	if err != nil {
		log.Printf("[tools] legacy text migration skipped: %v", err)
		return
	}
	for _, t := range rows {
		old, ok := legacy[t.Key]
		c, known := canon[t.Key]
		if !ok || !known || !t.System {
			continue
		}
		desc, schema := t.Description, t.Schema
		changed := false
		if t.Description != c.desc && promptDigest(t.Description) == old.desc {
			desc = c.desc
			changed = true
		}
		if legacySchemaDigest(t.Schema) == old.schema {
			raw, err := json.Marshal(c.schema)
			if err != nil {
				log.Printf("[tools] legacy text migration failed for %s: %v", t.Key, err)
				continue
			}
			if legacySchemaDigest(raw) != old.schema {
				schema = raw
				changed = true
			}
		}
		if !changed {
			continue
		}
		if err := pg.RefreshToolDefaults(t.Key, desc, schema); err != nil {
			log.Printf("[tools] legacy text migration failed for %s: %v", t.Key, err)
		}
	}
}

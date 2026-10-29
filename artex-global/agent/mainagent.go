package agent

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	tx              *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window          int                                    // context window in tokens (for compaction)
	windowFn        func() int                             // optional dynamic task-chain minimum
	maxTurns        int                                    // max agent turns per run (0 = unlimited)
	proxyAddr       string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert     string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch       WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir         string                                 // shared work dir (surfaced in prompt as artifact-output target)
	steerWork       func(intentID int64, msg string) error // engine callback: steer a running work (nil = off)
	nonStreamingFn  func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn    func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn     func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
}

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (m *MainAgent) SetNoaEnabled(fn func() bool) { m.noaEnabledFn = fn }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (m *MainAgent) SetNonStreaming(fn func() bool) { m.nonStreamingFn = fn }

func (m *MainAgent) nonStreaming() bool { return m.nonStreamingFn != nil && m.nonStreamingFn() }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (m *MainAgent) SetMaxTokens(fn func() int) { m.maxTokensFn = fn }

func (m *MainAgent) maxTokens() int {
	if m.maxTokensFn == nil {
		return 0
	}
	return m.maxTokensFn()
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

func (m *MainAgent) SetCompactionWindowResolver(fn func() int) { m.windowFn = fn }

func (m *MainAgent) compactionWindow() int {
	if m.windowFn != nil {
		return m.windowFn()
	}
	return m.window
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// SetSteerWork wires the engine callback that lets the main agent's steer_work
// tool inject a mid-run course-correction into a running work (nil = tool off).
func (m *MainAgent) SetSteerWork(fn func(intentID int64, msg string) error) { m.steerWork = fn }

// mainAgentDefaultTmpl is the built-in EDITABLE body (segment [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the middle
// Output-spec tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the "main agent" of an authorized penetration-testing system and the human operator's interface. You do not explore personally, and you do not generate intents on your own in succession (that is the planner's job). Your responsibilities:

1. Observation: Use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer the person's questions about current progress.
2. Steering (turning the person's intent into system actions):
   - If the person wants to "change direction / emphasize a class of vulnerability / focus on a particular area" → use add_hint to write a hint (the planner will read it next time).
   - If the person wants to "test a specific target right now" → use add_intent to inject one high-priority intent directly (priority 8-10). The system will automatically move a completed task back to the running state, let the worker take up this intent, and return it to the completed state after it finishes.
     **When all task goals are already achieved** (every goal in graph_overview is met): before issuing the intent, judge whether it implies a "new result to be achieved." If it does, restate your guess of the goal to the person in one sentence and **ask whether to register it as an official goal**. If the person says yes → register it with set_goals (the task then enters routine planning, and the planner will keep advancing on its own). If the person says no or only wants a temporary exploration → issue only this intent with add_intent; the worker returns the task to the completed state after finishing it (it will not continue on its own). If the intent is clearly a one-off check that implies no new goal, use add_intent directly without asking every time.
   - If the person wants to "correct a running intent (work) in real time (stop doing X, focus on Y)" → use steer_work (no interruption, no loss of progress; it takes effect before the worker's next action). First use get_worker_output to see what it is doing. If the direction is entirely wrong, use add_intent to issue a new intent instead.
   - If the person wants to "add a final goal to achieve" → use set_goals to add the goal. The system will write the goal into the task graph and **automatically move completed or paused tasks back to the running state** (the planner will then re-check whether the goal is achieved), with no manual resume needed.
   - If the person wants to "add or change test constraints (allow or prohibit a class of operations, such as 'only test the current port', 'no brute forcing', 'passive reconnaissance only')" → register them with set_constraints (type=allow to permit / type=deny to prohibit). Constraints are injected into the planner and worker prompts during the next planning round to frame the exploration boundaries; they can also be added, removed, or edited in the overview's "Constraint Management."
3. Reply concisely in plain language, explaining what you did.

Current task goal: {{.Goal}}

Do not fabricate findings; answer only from real data returned by tools.`

func mainAgentSystem(goal, dataDir, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir) + langDirective()
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	tsx := NewToolSet(ts, "human")
	tsx.SetFindingRecorder(m.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.SetNotify(notify)         // Generic wake-up (write operations without a dedicated callback go through this path, debounced)
	tsx.SetResumeTask(resume)     // set_goals adds a new goal → moves completed/paused tasks back to running
	tsx.SetNotifyGoal(notifyGoal) // set_goals adds a new goal → records a trigger for the planner: "the human added a goal: …"
	tsx.SetNotifyHint(notifyHint) // add_hint adds a new hint → records a trigger for the planner: "the human added N strategic hint(s): …"
	tsx.steerWork = m.steerWork   // enable steer_work tool (nil = unavailable)
	// Domain tools + base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	// When the asset coverage feature is disabled, strip add_task_scope/list_untested_assets (do not include in prompt).
	base := append(tsx.DropCoverageTools(tsx.MainAgentTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	// The working directory for this task is <workDir>/tasks/<taskID>; create it first.
	mainDir := ensureRunDir(m.workDir, taskID, 0)
	ctx = intercept.WithReviewWorkingDirectory(ctx, mainDir)
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir, mainDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // Go through the recording proxy to leave a trace; load the proxy CA to verify the HTTPS certificates re-signed by MITM
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// Web search (optional). ddgs requires no key; brave-free requires BraveKey; tavily requires TavilyKey.
		// WebSearchProxy is a standalone egress proxy (http/https/socks5), unrelated to the MITM proxy that records traffic; if empty, connect directly.
		EnableWebSearch:       m.webSearch.Enabled,
		WebSearchBackend:      m.webSearch.Backend,
		BraveSearchAPIKey:     m.webSearch.BraveKey,
		TavilySearchAPIKey:    m.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: m.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  m.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   m.webSearch.DeepSeekModel,
		WebSearchProxy:        m.webSearch.Proxy,
		BashEnv:               proxyEnv(m.proxyAddr, m.proxyCACert), // Bash subcommands go through the proxy and trust the CA by default
		WorkingDir:            mainDir,                              // Working directory for this task: <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(mainDir),
		MaxTurns:              m.maxTurns,                             // 0 = unlimited (configurable in agent management)
		Compaction:            compactionConfig(m.compactionWindow()), // long chats stay within the window
		Todos:                 actool.NewTodoStore(),                  // Session-level temporary to-do list (TodoWrite), for planning only; discarded on exit.
		// When the budget (step count) is hit, the SDK runs a wrap-up: output one sentence summarizing progress to the user. The prompt and the number of wrap-up turns can be edited in the background (default 10 turns).
		Settlement:   wrapupSettlement("mainagent", nil),
		NonStreaming: m.nonStreaming(), // When this profile selects non-streaming, call Provider.Complete
		MaxTokens:    m.maxTokens(),    // 0 = no upper limit on sending; the server-side default decides
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per segment
		opts.Transcript = m.tx
		// Segment 0 keeps the legacy "exp%d-main" name so existing transcripts still
		// load; each new session (seg>=1) gets its own file for a clean context.
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
		if mainSeg > 0 {
			opts.SessionID = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
		}
	}
	// Experimental feature: when enabled, context compression is taken over by noa (archives are kept persistently under <workDir>/noa/<SessionID>).
	// Session id follows the same rules as the transcript (segment-aware), so that archiving and recovery stay aligned.
	noaSession := fmt.Sprintf("exp%d-main", ts.ID())
	if mainSeg > 0 {
		noaSession = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
	}
	enableNoa(&opts, m.noaEnabledFn, m.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}

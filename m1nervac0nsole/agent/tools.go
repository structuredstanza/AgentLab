package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	acperm "github.com/structuredstanza/norma/permission"
	actool "github.com/structuredstanza/norma/tool"
)

// NetPolicyAuthorizer decides whether a backend-side dial may reach a
// destination. It is the same authorizer the gateway asks, assigned once at
// startup (server/assembly.go); nil refuses every dial, because a destination no
// policy answered for is not authorized.
var NetPolicyAuthorizer netpolicy.Authorizer

// NetPolicySource is the policy state behind NetPolicyAuthorizer, assigned
// beside it. port_scan shares periodically refreshed state across workers,
// rather than reading the database for every port.
var NetPolicySource netpolicy.Source

// OperatorExitConfigured prevents port_scan from bypassing the operator's exit.
// The server wires it at startup; a nil callback refuses direct scans.
var OperatorExitConfigured func() bool

// snapshotSource serves one already-loaded policy state to netpolicy.Store, so
// the snapshot is judged by netpolicy's own logic.
type snapshotSource struct{ st netpolicy.State }

func (s snapshotSource) PolicyState(context.Context, netpolicy.Session) (netpolicy.State, error) {
	return s.st, nil
}

// authorizeDial asks the network policy whether this task may reach one
// destination. The session is backend-internal: it carries the task, so the
// authorizer judges the task's own authorized rules, and no revision, so a
// policy change is observed on the next call.
func authorizeDial(ctx context.Context, az netpolicy.Authorizer, taskID int64, d netpolicy.Destination) netpolicy.Decision {
	if taskID <= 0 {
		return netpolicy.Decision{Stage: netpolicy.StagePolicy, Reason: "no task context to check the destination against"}
	}
	if az == nil {
		return netpolicy.Decision{Stage: netpolicy.StagePolicy, Reason: "no network-policy authorizer is configured"}
	}
	return az.Authorize(ctx, dialSession(taskID), d)
}

// dialSession is the backend-internal session every dial authorization uses.
func dialSession(taskID int64) netpolicy.Session {
	return netpolicy.Session{ID: "dial:" + strconv.FormatInt(taskID, 10), TaskID: taskID, Purpose: netpolicy.PurposeTesting}
}

// resolvedAuthorizer is the dns-stage question: *netpolicy.Store answers it, and
// it is not part of netpolicy.Authorizer because only a caller holding resolved
// addresses can ask it.
type resolvedAuthorizer interface {
	AuthorizeResolved(context.Context, netpolicy.Session, netpolicy.Destination, []net.IP) netpolicy.Decision
}

type dialResolution struct {
	addrs    []net.IP
	recorded bool
	literal  bool
}

type recordedAuthorizer interface {
	AuthorizeRecorded(context.Context, netpolicy.Session, netpolicy.Destination, []net.IP) netpolicy.Decision
}

// recordedDialAddrs reads task claims once, even for scans with per-port rules.
func (t *ToolSet) recordedDialAddrs(host string) []net.IP {
	if t.as == nil || t.taskID <= 0 || net.ParseIP(host) != nil {
		return nil
	}
	addrs, err := t.as.TaskHostAddrs(t.taskID, host)
	if err != nil {
		return nil
	}
	return addrs
}

// resolveDialHost only uses recorded addresses independently covered by the
// task's policy. If none qualify, an authorized hostname follows the DNS path.
// The returned addresses, never the name, are used for dialing.
func (t *ToolSet) resolveDialHost(ctx context.Context, az netpolicy.Authorizer, host string, port int, recorded []net.IP) (dialResolution, netpolicy.Decision, error) {
	d := netpolicy.Destination{Host: host, Port: port, Protocol: "tcp"}
	if ip := net.ParseIP(host); ip != nil {
		return dialResolution{addrs: []net.IP{ip}, literal: true}, authorizeDial(ctx, az, t.taskID, d), nil
	}
	if ra, ok := az.(recordedAuthorizer); ok && t.taskID > 0 {
		var allowed netpolicy.Decision
		addrs := recorded[:0]
		sess := dialSession(t.taskID)
		for i, ip := range recorded {
			if dec := ra.AuthorizeRecorded(ctx, sess, d, recorded[i:i+1]); dec.Allow {
				addrs = append(addrs, ip)
				allowed = dec
			}
		}
		if len(addrs) > 0 {
			return dialResolution{addrs: addrs, recorded: true}, allowed, nil
		}
	}
	dec := authorizeDial(ctx, az, t.taskID, d)
	if !dec.Allow {
		return dialResolution{}, dec, nil
	}
	found, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return dialResolution{}, dec, err
	}
	if len(found) == 0 {
		return dialResolution{}, dec, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	addrs := make([]net.IP, len(found))
	for i, f := range found {
		addrs[i] = f.IP
	}
	return dialResolution{addrs: addrs}, dec, nil
}

// authorizeAddrs rechecks one port against the same origin used to resolve it.
// DNS answers are judged together; a recorded address must qualify on its own.
func (t *ToolSet) authorizeAddrs(ctx context.Context, az netpolicy.Authorizer, host string, port int, resolved dialResolution, ai int) netpolicy.Decision {
	d := netpolicy.Destination{Host: host, Port: port, Protocol: "tcp"}
	if resolved.recorded {
		if ra, ok := az.(recordedAuthorizer); ok && t.taskID > 0 {
			return ra.AuthorizeRecorded(ctx, dialSession(t.taskID), d, resolved.addrs[ai:ai+1])
		}
		return netpolicy.Decision{Stage: netpolicy.StageDNS, Reason: "the network-policy authorizer cannot judge recorded addresses"}
	}
	if resolved.literal {
		return authorizeDial(ctx, az, t.taskID, d)
	}
	ra, ok := az.(resolvedAuthorizer)
	if !ok || t.taskID <= 0 {
		return netpolicy.Decision{Stage: netpolicy.StageDNS, Reason: "the network-policy authorizer cannot judge resolved addresses, so hostname dials are refused"}
	}
	return ra.AuthorizeResolved(ctx, dialSession(t.taskID), d, resolved.addrs)
}

// resolveAuthorizedDial is resolveDialHost plus the per-port dns-stage check:
// the addresses are returned only when the destination is authorized.
func (t *ToolSet) resolveAuthorizedDial(ctx context.Context, az netpolicy.Authorizer, host string, port int) ([]net.IP, netpolicy.Decision, error) {
	resolved, dec, err := t.resolveDialHost(ctx, az, host, port, t.recordedDialAddrs(host))
	if err != nil || !dec.Allow {
		return nil, dec, err
	}
	if !resolved.recorded && !resolved.literal {
		dec = t.authorizeAddrs(ctx, az, host, port, resolved, 0)
		if !dec.Allow {
			return nil, dec, nil
		}
	}
	return resolved.addrs, dec, nil
}

// normalizeDirection fingerprints summaries while ignoring case, whitespace, and changing digits.
func normalizeDirection(summary string) string {
	var b strings.Builder
	digit := false
	for _, r := range strings.ToLower(strings.Join(strings.Fields(summary), " ")) {
		if r >= '0' && r <= '9' {
			if !digit {
				b.WriteByte('#')
			}
			digit = true
			continue
		}
		digit = false
		b.WriteRune(r)
	}
	return b.String()
}

const stagnationMinRepeats = 3

func detectStagnation(done, findings []*db.Node) []map[string]any {
	type direction struct {
		firstID int64
		repeats int
		summary string
	}
	byFingerprint := make(map[string]*direction)
	var order []string
	for _, node := range done {
		var payload map[string]any
		_ = json.Unmarshal(node.Payload, &payload)
		summary, _ := payload["summary"].(string)
		fingerprint := normalizeDirection(summary)
		if fingerprint == "" {
			continue
		}
		d := byFingerprint[fingerprint]
		if d == nil {
			d = &direction{firstID: node.ID, summary: summary}
			byFingerprint[fingerprint] = d
			order = append(order, fingerprint)
		}
		if node.ID < d.firstID {
			d.firstID, d.summary = node.ID, summary
		}
		d.repeats++
	}
	var out []map[string]any
	for _, fingerprint := range order {
		d := byFingerprint[fingerprint]
		if d.repeats < stagnationMinRepeats {
			continue
		}
		produced := false
		for _, finding := range findings {
			if finding.ID > d.firstID {
				produced = true
				break
			}
		}
		if !produced {
			out = append(out, map[string]any{"direction": d.summary, "repeats": d.repeats, "since": d.firstID})
			if len(out) == 3 {
				break
			}
		}
	}
	return out
}

// compactIntents distills intents to {id, summary, state, asset_ids, parents,
// yields} so the planner sees both the direction and its LINEAGE — parents (the
// upstream nodes it derived from: facts/intents/findings) and yields (the facts/
// findings it produced) — without pulling full payloads. parentsOf/yieldsOf are
// built from the exploration edges in graph_overview.
func compactIntents(ns []*db.Node, parentsOf, yieldsOf map[int64][]int64) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		m := map[string]any{"id": n.ID, "summary": p["summary"], "state": n.State}
		if n.Inherited {
			m["source_task_id"] = n.SourceTaskID
			m["inherited"] = true
		}
		// asset_ids is the structured "which assets this direction covers" signal for
		// dedup; fall back to legacy payload keys (target_ids plural, then target_id
		// single) so intents stored before the rename still surface their anchors.
		if tg, ok := p["asset_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_id"]; ok && tg != nil && tg != "" {
			m["asset_ids"] = []any{tg}
		}
		if ps := parentsOf[n.ID]; len(ps) > 0 {
			m["parents"] = ps // Upstream: which nodes this intent is derived from (multiple facts may jointly produce one intent)
		}
		if ys := yieldsOf[n.ID]; len(ys) > 0 {
			m["yields"] = ys // Downstream: which facts/findings this intent produced
		}
		out = append(out, m)
	}
	return out
}

// ToolSet exposes the PG-backed dual graph (asset + exploration) to an LLM agent.
// One ToolSet is created per planner/worker run; per-run signals live here.
type ToolSet struct {
	findingRecorder FindingRecorder
	as              *db.AssetStore   // asset store (optional; nil = asset tools not available)
	cs              *db.CompanyStore // company store (optional)
	mem             MemoryStore      // knowledge base + reflection pool (optional; nil = memory tools refuse)
	ts              *db.ExplorationStore
	worker          string
	taskID          int64 // PG tasks.id; 0 when unknown (tests / orchestrator cross-task reads)
	// workDir is the data dir the task workspaces live under; report_finding
	// resolves screenshot_paths against it. Empty = screenshots cannot be
	// validated and are refused.
	workDir string
	// coverageDisabled mirrors tasks.coverage_enabled=false. Stored inverted so the
	// zero value (all existing ToolSet constructions) means ENABLED — matching the
	// DB default (true). When true: graphOverviewData drops the coverage block, the
	// auto-scope hook (insertAssets) is skipped, and add_task_scope/list_untested_assets
	// are filtered out of the agent's tool list. The scope field stays regardless.
	coverageDisabled bool
	// ownerNode is the exploration node that writes attach to: assets this run
	// touches get anchored to it as lineage/provenance (NOT visibility — the asset
	// graph is global and shared). Worker = its claimed intent; planner = begin root.
	ownerNode int64
	GoalMet   bool
	Reason    string
	writes    WriteCounts
	// killWork, if set, terminates a running work by intent id, or cancels an
	// intent that has not started yet (engine callback, wired by the planner).
	// reason is recorded on the cancelled intent. nil = the kill_work tool
	// reports unavailable.
	killWork func(ctx context.Context, taskID, intentID int64, reason string) error
	// steerWork, if set, queues a mid-run course-correction for the work running an
	// intent id (engine callback, wired by the planner): the worker injects it before
	// its next tool call and re-plans, without being killed. nil = tool unavailable.
	steerWork func(intentID int64, msg string) error
	// enrich, if set, receives async auto-completion triggers (DNS resolve for a
	// domain, HTTP probe for a site) for assets this run persists. The trigger
	// carries this run's task id, because the engine is manager-wide and must
	// check the destination against that task's boundary. nil = no engine
	// enrichment.
	enrich EnrichTrigger
	// notify, if set, wakes the task's planner after a graph change that should be
	// re-planned promptly (currently: a new hint). nil = no wake (the hint is still
	// stored and read on the next round triggered by other events). debounced.
	notify func()
	// notifyFinding, if set, wakes the task's planner when this run reports a finding,
	// carrying (intentID, summary) so the round can spell out which intent found what.
	// Wired for workers; nil elsewhere → falls back to notify (bare wake).
	notifyFinding func(intentID int64, summary string)
	// resumeTask, if set, revives the task after a graph change that should make a
	// stopped task run again (currently: set_goals adds a goal). It flips a terminal/
	// paused task back to running and (re)starts the engine loops — a plain notify()
	// can't, because the planner's terminal gate swallows wakes. Wired ONLY for the
	// main agent (human steering); nil for the goals decomposer and workers.
	resumeTask func() (string, error) // returns an honest admission acknowledgement, or the admission error
	// notifyGoal, if set, wakes the planner AND records ONE "person added N goals:…" trigger
	// for a whole set_goals call (batch-aware — one call, one trigger, not one per goal)
	// so the next round spells out the added goals (instead of the planner having to
	// spot new open goals in the overview). Wired ONLY for the main agent; nil for the
	// goals decomposer (round-0 has no running planner to inform) and workers → those
	// fall back to the bare notify.
	notifyGoal func(texts []string)
	// notifyHint, if set, wakes the planner AND records ONE "N new strategy hints were added: …"
	// trigger for a whole add_hint call (batch-aware — one call, one trigger) so the next
	// round is told the round was fired by a new hint and spells the hint out, instead of
	// the planner having to spot it folded into the graph overview. Wired for the main
	// agent + cross-task orchestration; nil elsewhere → falls back to the bare notify.
	notifyHint func(texts []string)
}

// SetNotifyGoal wires the goal-add trigger callback (see ToolSet.notifyGoal). Set only
// by the main-agent chat, so runtime-added goals are announced to the planner by name.
func (t *ToolSet) SetNotifyGoal(fn func([]string)) { t.notifyGoal = fn }

// SetNotifyHint wires the hint-add trigger callback (see ToolSet.notifyHint). Set by
// the main-agent chat and cross-task orchestration, so a runtime-added hint fires a
// planner round announced by name instead of a bare wake.
func (t *ToolSet) SetNotifyHint(fn func([]string)) { t.notifyHint = fn }

// SetResumeTask wires the task-revive callback (see ToolSet.resumeTask). Set only by
// the main-agent chat, so runtime-added goals can pull a finished task back to running.
func (t *ToolSet) SetResumeTask(fn func() (string, error)) { t.resumeTask = fn }

// SetKillWork wires the confirmed-stop callback behind the kill_work tool.
func (t *ToolSet) SetKillWork(fn func(ctx context.Context, taskID, intentID int64, reason string) error) {
	t.killWork = fn
}

// SetNotify wires the planner-wake callback (see ToolSet.notify). Set by callers
// that hold the task handle (main-agent chat, cross-task orchestration).
func (t *ToolSet) SetNotify(fn func()) { t.notify = fn }

// SetNotifyFinding wires the finding-wake callback (see ToolSet.notifyFinding).
func (t *ToolSet) SetNotifyFinding(fn func(int64, string)) { t.notifyFinding = fn }

// EnrichTrigger is the enrichment engine seen from the tool layer (see package
// enrich). Kept as an interface here to avoid coupling agent → enrich.
//
// taskID travels with every trigger because the engine is manager-wide: it must
// check the destination against the boundary of the task the asset was found
// under, not against whichever task happens to be running. An id without a task
// (0) is refused by the engine rather than enriched on nobody's authority.
type EnrichTrigger interface {
	ResolveDomain(taskID, id int64, host string)
	ProbeSite(taskID, id int64, url string)
}

// WriteCounts breaks down what a worker persisted this run, by node kind, so the
// engine can log an accurate "wrote back" summary instead of lumping assets and
// findings under "facts" (record_fact → Facts, insert_assets → Assets,
// report_finding → Findings; each element of a batch counts once).
type WriteCounts struct {
	Facts    int
	Assets   int
	Findings int
}

// Total is every node persisted this run, regardless of kind — the
// "explored but persisted nothing" signal (Total == 0).
func (w WriteCounts) Total() int { return w.Facts + w.Assets + w.Findings }

// String renders the per-kind breakdown for logs, e.g. "Fact1 Asset25 Vuln0".
func (w WriteCounts) String() string {
	return fmt.Sprintf("facts %d assets %d findings %d", w.Facts, w.Assets, w.Findings)
}

// Writes reports what this run wrote back, split by node kind (so the engine can
// tell "explored but persisted nothing" apart from a completed intent, and log an
// honest breakdown instead of calling assets/findings "facts").
func (t *ToolSet) Writes() WriteCounts { return t.writes }

func NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet {
	return &ToolSet{ts: ts, worker: worker}
}

// SetTaskID sets the PG task id on this ToolSet so that report_finding can
// dual-write to the standalone findings table (which survives task deletion).
func (t *ToolSet) SetTaskID(id int64) { t.taskID = id }

// SetWorkDir sets the data dir that holds the task workspaces, so
// report_finding can check the screenshot paths it records.
func (t *ToolSet) SetWorkDir(dir string) { t.workDir = dir }

// SetCoverageEnabled records whether this task has the asset-coverage feature on
// (default enabled). Passing false makes graphOverviewData omit the coverage block
// and DropCoverageTools filter the two coverage-only tools out of the agent's tool
// list. It does NOT stop scope accumulation: insertAssets' auto-scope hook runs
// either way, because task_scope is the task's range boundary (the filter basis for
// asset queries), not merely a coverage denominator.
func (t *ToolSet) SetCoverageEnabled(enabled bool) { t.coverageDisabled = !enabled }

// coverageOnlyTools are the LLM tools that only make sense when asset coverage is
// on. When the feature is off they are filtered out of the agent's tool list so
// they neither pollute the prompt nor let the model build a disabled denominator.
// add_task_scope is deliberately NOT here: task_scope is the task's range boundary
// (the filter basis for asset queries), not merely a coverage denominator, so the
// agents that own scope definition keep it either way — in lockstep with insertAssets'
// auto-scope hook, which also runs regardless of the switch.
var coverageOnlyTools = map[string]bool{"list_untested_assets": true}

// DropCoverageTools returns tools with the coverage-only ones removed when this
// task has the feature disabled; otherwise it returns tools unchanged.
func (t *ToolSet) DropCoverageTools(tools []actool.CoreTool) []actool.CoreTool {
	if !t.coverageDisabled {
		return tools
	}
	out := tools[:0:0]
	for _, tool := range tools {
		if coverageOnlyTools[tool.Name()] {
			continue
		}
		out = append(out, tool)
	}
	return out
}

// Cross-task reuse: exported accessors returning the per-task tool logic bound to
// THIS ToolSet's store. Host-side orchestration tools build a ToolSet for an
// arbitrary task, then Call these — so cross-task reads/hint reuse the exact
// same logic as the in-task tools. (readTool ignores ToolContext, so Call(…,nil)
// is safe; add_hint is a writeTool but also doesn't deref the context here.)
func (t *ToolSet) GraphOverviewTool() actool.CoreTool      { return t.graphOverview() }
func (t *ToolSet) ListFindingsTool() actool.CoreTool       { return t.listFindings() }
func (t *ToolSet) GetWorkerTraceTool() actool.CoreTool     { return t.getWorkerTrace() }
func (t *ToolSet) ListWorkerTracesTool() actool.CoreTool   { return t.listWorkerTraces() }
func (t *ToolSet) SearchWorkerTracesTool() actool.CoreTool { return t.searchAllWorkerTraces() }
func (t *ToolSet) NodeDetailTool() actool.CoreTool         { return t.nodeDetail() }
func (t *ToolSet) AddHintTool() actool.CoreTool            { return t.addHint() }

// SetEnrich wires the async enrichment engine (DNS/HTTP auto-completion).
func (t *ToolSet) SetEnrich(e EnrichTrigger) { t.enrich = e }

// SetOwnerNode sets the exploration node that writes anchor to (worker: its
// intent node; planner/main: the begin root). Assets created/referenced while
// ownerNode is set are anchored to it as lineage (not visibility).
func (t *ToolSet) SetOwnerNode(id int64) { t.ownerNode = id }

// anchorOwner records a lineage edge from this run's owner node to an asset
// (no-op if unset). Provenance only — the asset graph is global and shared, so
// this no longer affects which assets a task can read.
func (t *ToolSet) anchorOwner(assetID int64) {
	if t.ts != nil && t.ownerNode > 0 && assetID > 0 {
		_ = t.ts.Anchor(t.ownerNode, assetID)
	}
}

// pid parses an id that may arrive as a JSON number or string ("" / 0 → 0).
func pid(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

// pidList parses a list of ids (number|string), dropping zeros/invalids.
func pidList(raw []json.RawMessage) []int64 {
	var out []int64
	for _, r := range raw {
		if v := pid(r); v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func idp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func writeTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// readExpTool / writeExpTool build a domain tool whose handler dereferences the
// task-bound ExplorationStore. Two ToolSets carry a nil store: the catalog's
// seed-only shell (never called) and the server-level one behind buildDomainReg,
// which the tools table can bind to ANY agent — including ones that never run
// inside a task (auto/pentest/reporter/custom agent/side-channel question). Refusing there
// keeps a mis-bound tool a bad tool call; without the guard it was a nil deref,
// and tool handlers run on the harness's own goroutine, so the panic is out of
// reach of every recover() in the server and kills the whole process.
func (t *ToolSet) readExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return readTool(name, desc, schema, t.needExploration(name, run))
}

func (t *ToolSet) writeExpTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return writeTool(name, desc, schema, t.needExploration(name, run))
}

// needExploration wraps a handler so it only runs with an exploration store.
// Tools that degrade more usefully than "unavailable" (report_finding points at
// add_task_hint, set_goals/set_constraints at the task itself) keep their own
// bespoke guard instead.
func (t *ToolSet) needExploration(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.ts == nil {
			return actool.Errorf(name + " requires task context (exploration graph): the current agent is not running inside a task, so the task's exploration graph is unavailable and this tool is disabled. Use it inside a task, or use a cross-task read tool that takes task_id (get_task_node_detail / list_task_findings / get_task_graph, etc.)."), nil
		}
		return run(ctx, in)
	}
}

func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return t.readExpTool("graph_overview",
		"(exploration graph) Distilled exploration-state summary: asset counts, sites without an interface, frontier, findings, hints (strategic hints from humans or the main agent; must be incorporated when generating intents). Call this first when planning.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.graphOverviewData())
		})
}

// graphOverviewData computes the distilled situational snapshot shared by the
// graph_overview tool and the planner's wake-up prompt (which pre-injects it so
// the model needn't spend a turn calling the tool — every plan round starts with
// an empty context and always needs this first).
func (t *ToolSet) graphOverviewData() map[string]any {
	out := map[string]any{}
	// goals summary folded in so the planner needn't call list_goals each round.
	goals, _ := t.ts.ListByKind(db.KindGoal, 100)
	gsum := make([]map[string]any, 0, len(goals))
	for _, g := range goals {
		var p map[string]any
		_ = json.Unmarshal(g.Payload, &p)
		gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
	}
	out["goals"] = gsum
	// hints: strategic hints that a human/main agent attaches to the graph via add_hint; folded in so the
	// planner reads them every round when generating intents (otherwise write-only). Only active hints:
	// a consumed hint was superseded or closed and must stop steering the planner.
	hints, _ := t.ts.ListByKindState(db.KindHint, "active", 50)
	hsum := make([]map[string]any, 0, len(hints))
	for _, h := range hints {
		var p map[string]any
		_ = json.Unmarshal(h.Payload, &p)
		hint := map[string]any{"id": h.ID, "state": h.State, "text": p["text"]}
		if findingTrafficBindingEnabled() && p["traffic_refs"] != nil {
			hint["traffic_refs"] = p["traffic_refs"]
		}
		hsum = append(hsum, hint)
	}
	out["hints"] = hsum
	// lineage from the exploration edges: an intent's parents (what it
	// derived_from — possibly several facts combined) and its yields (the
	// facts/findings it produced). factFrom maps a fact → the intent that
	// produced it. This is the relationship layer the flat lists lacked.
	edges, _ := t.ts.Edges(5000)
	parentsOf := map[int64][]int64{}
	yieldsOf := map[int64][]int64{}
	factFrom := map[int64]int64{}
	for _, e := range edges {
		switch e.Rel {
		case db.RelDerivedFrom, db.RelSpawns: // upstream: derived_from (fact/finding/intent→intent) or spawns (origin fact→goal, legacy begin→intent)
			parentsOf[e.To] = append(parentsOf[e.To], e.From)
		case db.RelYields: // intent --yields--> fact/finding
			yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
			factFrom[e.To] = e.From
		}
	}
	// cold-digest §6: members folded into an active digest are shown via cold_digests
	// (below), not the flat recent_* lists. `covered` maps member id → its digest id.
	// §6 render-time revival check: a covered member that has become hot again (a new
	// intent derived from it) must reappear this round — so `hidden` folds a member out
	// only when it is covered AND still cold.
	covered, _ := t.ts.CoveredMembers()
	// Render-time hot set (ancestor of a live intent / fact under a live intent).
	// §6 revival check: a covered member that revived (now hot) must NOT stay folded
	// — hidden() only folds a member out when it is covered AND still cold. Computed
	// every round (cheap for real graph sizes); nil map degrades safely.
	var hotAtRender map[int64]bool
	if cg, _, err := loadColdGraph(t.ts); err == nil {
		hotAtRender = cg.hotSet()
	}
	hidden := func(id int64) bool { _, c := covered[id]; return c && !hotAtRender[id] }
	const openIntentsCap = 30
	fr, _ := t.ts.Frontier(openIntentsCap) // priority DESC, id ASC — the top N highest-priority items; the true total is in frontier_open
	out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf)
	all, _ := t.ts.ListByKind(db.KindIntent, 300)
	var running, paused, recentDone []*db.Node
	for _, n := range all {
		switch n.State {
		case "running":
			running = append(running, n)
		case "paused":
			paused = append(paused, n) // waiting on the operator (ask_operator): in play, not a stalled frontier
		case "done", "blocked", "exhausted":
			if hidden(n.ID) {
				continue // in a cold_digest and still cold — shown via cold_digests (§6.2)
			}
			recentDone = append(recentDone, n) // Newest first (all sorted by id descending); folded items are excluded; when outputting, truncate to the latest N
		}
	}
	out["running_intents"] = compactIntents(running, parentsOf, yieldsOf)
	// paused_intents: an intent parked on a human (ask_operator). It is in play,
	// not a stalled frontier, so it must be visible: the flat open/running lists
	// would otherwise make a paused engagement read as "nothing is happening".
	const pausedIntentsCap = 12
	if len(paused) > pausedIntentsCap {
		paused = paused[:pausedIntentsCap] // newest first, like recent_done_intents
	}
	out["paused_intents"] = compactIntents(paused, parentsOf, yieldsOf)
	// done_intents_total: total count of finished intents (done/blocked/exhausted), parallel to recent_done_intents
	// naming — the latter is merely its latest-window truncated view. Showing the two keys side by side makes them self-describing: "what is seen is N/total",
	// so the planner, when deduplicating, does not mistake "not displayed" for "never dispatched", with no need for a separate explanation in the prompt.
	if dt, err := t.ts.CountFinishedIntents(); err == nil {
		out["done_intents_total"] = dt
	}
	// frontier_open: true total count of open intents (open_intents is only the top-priority N-item truncated view of it).
	if fo, err := t.ts.CountOpenIntents(); err == nil {
		out["frontier_open"] = fo
	} else {
		out["frontier_open"] = len(fr)
	}
	// findings (confirmed vulns) and facts (worker exploration results) are
	// now distinct node kinds. recent_facts surfaces fact summaries (esp.
	// negative results) so the planner sees them in one call; full content
	// via node_detail(id).
	vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
	factNodes, _ := t.ts.ListByKind(db.KindFact, 1000) // newest first
	out["findings_total"] = len(vulnNodes)             // Total count of confirmed vulnerabilities (goal judgment uses this); details in finding_list (latest window)
	out["facts"] = len(factNodes)                      // Count of exploration facts/conclusions (including negative conclusions)
	if creds := t.taskCredentialOverview(); creds != nil {
		out["task_credentials"] = creds
		out["task_credentials_note"] = "test accounts for this task; reuse matching entries for authenticated testing; an empty password means register the account with a strong unique password and record it with save_task_credential"
	}
	if stale := detectStagnation(recentDone, vulnNodes); len(stale) > 0 {
		out["stagnation_warning"] = map[string]any{
			"directions":  stale,
			"instruction": "these directions were dispatched repeatedly with zero findings produced since their first attempt — do NOT re-dispatch the same approach again; open a materially different direction, or judge the goal on the existing evidence instead of grinding",
		}
	}
	// findings are the highest-value output of the task → the overview carries the latest window (≤10 items; vulnNodes is already sorted by id descending, so newest first),
	// Lets the planner see the most recently confirmed vulnerabilities at a glance each round when deciding goals; use list_findings for the full set or older ones.
	// Each entry keeps only {id, summary, from_intent?}: from_intent is the intent that produced this vulnerability.
	// evidence/assets/vulnclass/severity/state etc. can still be fetched via list_findings / node_detail(id).
	const findingListCap = 10
	findingList := make([]map[string]any, 0, findingListCap)
	for _, n := range vulnNodes {
		if len(findingList) >= findingListCap {
			break
		}
		var fp map[string]any
		_ = json.Unmarshal(n.Payload, &fp)
		m := map[string]any{"id": n.ID, "summary": fp["summary"]}
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // Which intent produced this vulnerability
		}
		findingList = append(findingList, m)
	}
	out["finding_list"] = findingList
	// recent_facts: the newest window of non-folded facts (≤N, factNodes sorted by id descending, newest first). Those already folded into
	// digest and still cold (hidden) go through cold_digests and are not repeated here. Each entry {id, summary, from_intent?,
	// confidence?}; for details such as evidence, use node_detail(id). For older entries, page through with list_facts.
	const recentFactsCap = 20
	recentFacts := make([]map[string]any, 0, recentFactsCap)
	for _, n := range factNodes {
		if len(recentFacts) >= recentFactsCap {
			break
		}
		if hidden(n.ID) {
			continue // Already folded into a digest and still cold — see cold_digests
		}
		m := compactNode(n)
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from // Which intent produced this fact
		}
		// Bring confidence into the overview so the planner can see at a glance which conclusions are only inferred (especially negative conclusions
		// not to be treated as airtight); evidence is long, so leave it for node_detail(id).
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) == nil {
			if c, ok := fp["confidence"].(string); ok && c != "" {
				m["confidence"] = c
			}
		}
		recentFacts = append(recentFacts, m)
	}
	out["recent_facts"] = recentFacts
	// recent_done_intents: the newest window of non-folded finished intents (≤N; recentDone is already sorted by id in descending order).
	// For earlier ones, see the done_intents_total count + node_detail(id).
	const recentDoneCap = 12
	if len(recentDone) > recentDoneCap {
		recentDone = recentDone[:recentDoneCap]
	}
	out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf)
	// Cold-digest §6.1: collapse the digest body of cold zones, keep the top N by latest member time in descending order; older digests that get truncated
	// Only return the bare id (it can still be expanded via expand_digest), to avoid making the cold zone's sole exit unbounded in length.
	const coldDigestsCap = 15
	if cds, more := coldDigestsRecent(t.ts, coldDigestsCap); len(cds) > 0 {
		out["cold_digests"] = cds // [{id, body, member_count}] —— read body directly (§6.1)
		if len(more) > 0 {
			out["cold_digests_more"] = more // The id of a truncated older digest; use expand_digest(id) to expand it
		}
	}
	// the original task (root) so the planner always has it, not just the
	// decomposed goals.
	if description, goal, err := t.ts.Root(); err == nil {
		out["task"] = map[string]any{"description": description, "goal": goal}
	}
	// Direct source tasks are a live, read-only blackboard view. Keep their
	// summaries in a separate field so their intents never enter this task's
	// frontier or get mistaken for locally claimable work.
	out["related_tasks"] = t.relatedTaskOverviews()
	// coverage: a rough reference for asset test coverage—among the assets within task_scope, the proportion touched by a fact
	// coverage: a rough reference for asset test coverage — among the assets in scope (task_scope), the proportion touched by a fact, plus by_type (total / tested per type). To see the specific untested assets, the agent calls list_untested_assets on demand and judges for itself. Present only in task context.
	// When asset coverage is disabled (coverageDisabled): keep only host_count (awareness of the total number of target hosts),
	// drop the coverage metrics such as denominator/tested/pct/by_type/note, to avoid cluttering the context and to avoid inducing
	// add_task_scope/list_untested_assets are hidden.
	if t.as != nil && t.ts != nil && t.taskID > 0 {
		{
			m := map[string]any{}
			if !t.coverageDisabled {
				if cov, err := t.as.TaskCoverageWithSources(t.taskID); err == nil {
					m["denominator"] = cov.Denominator
					m["tested"] = cov.Tested
					m["by_type"] = cov.ByType
					m["note"] = "coverage: asset test coverage (across interfaces and other related assets), a rough estimate for reference only. Includes the scope and fact anchors of this task and directly linked tasks; linked scope is read-only. Container-type assets and large enumerations make it read low, so do not conclude testing is complete from it. Use add_task_scope to add to this task's scope, and list_untested_assets to see untested assets [usually do not call list_untested_assets; just proceed with the task];"
					if cov.Denominator == 0 {
						m["pct"] = nil
						m["status"] = "scope not anchored"
					} else {
						m["pct"] = cov.Pct
					}
				}
			}
			if hosts, err := t.as.HostsByTaskWithSources(t.taskID); err == nil {
				// Only provide the total host count; do not flatten the host list into graph_overview (in large-scope tasks it is a large set of strings
				// Large strings that are repeated everywhere carry limited value for planning decisions); for specific hosts, query with list_assets as needed.
				m["host_count"] = len(hosts)
			}
			if len(m) > 0 {
				out["coverage"] = m
			}
		}
	}
	// target_liveness: hosts a direct probe could not reach. It exists so a
	// host that has gone dark is a machine fact: without it the planner spends
	// rounds dispatching availability checks it could already know are futile.
	// Absence of a host here means no probe has failed, not that it is up.
	const targetLivenessCap = 10
	if t.as != nil && t.ts != nil {
		if hosts, err := t.as.UnreachableHosts(t.taskID, targetLivenessCap); err == nil && len(hosts) > 0 {
			lv := make([]map[string]any, 0, len(hosts))
			for _, h := range hosts {
				lv = append(lv, map[string]any{"host": h.Host, "unreachable_since": h.Since.Unix()})
			}
			out["target_liveness"] = lv
		}
	}
	return out
}

func inheritedMap(m map[string]any, sourceTaskID int64) map[string]any {
	m["source_task_id"] = sourceTaskID
	m["inherited"] = true
	return m
}

const (
	relatedOverviewTotalTextRunes      = 48_000
	relatedOverviewMaxTextPerSource    = 8_000
	relatedOverviewMaxGoalsPerSource   = 8
	relatedOverviewMaxHintsPerSource   = 6
	relatedOverviewMaxFactsPerSource   = 12
	relatedOverviewMaxFindingsPerTask  = 6
	relatedOverviewMaxIntentsPerTask   = 8
	relatedOverviewMaxScopePerSource   = 12
	relatedOverviewMaxDigestsPerSource = 6
)

// overviewTextBudget bounds inherited prompt text while preserving a fair slice
// for every direct source. Full evidence remains available through the on-demand
// read tools, so truncation here does not discard persisted blackboard data.
type overviewTextBudget struct {
	remaining int
	truncated bool
}

func relatedOverviewBudgetForSources(sourceCount int) int {
	if sourceCount <= 0 {
		return 0
	}
	if sourceCount > db.MaxTaskSourceCount {
		sourceCount = db.MaxTaskSourceCount
	}
	perSource := relatedOverviewTotalTextRunes / sourceCount
	if perSource > relatedOverviewMaxTextPerSource {
		perSource = relatedOverviewMaxTextPerSource
	}
	return perSource
}

func (b *overviewTextBudget) take(value any, fieldLimit int) string {
	var text string
	switch value := value.(type) {
	case string:
		text = strings.TrimSpace(value)
	case nil:
		return ""
	default:
		text = strings.TrimSpace(fmt.Sprint(value))
	}
	if text == "" {
		return ""
	}
	if b.remaining <= 0 || fieldLimit <= 0 {
		b.truncated = true
		return ""
	}
	runes := []rune(text)
	limit := fieldLimit
	if limit > b.remaining {
		limit = b.remaining
	}
	if len(runes) > limit {
		b.truncated = true
		if limit == 1 {
			text = "…"
		} else {
			text = string(runes[:limit-1]) + "…"
		}
		runes = []rune(text)
	}
	b.remaining -= len(runes)
	return text
}

func recentTerminalIntents(store *db.ExplorationStore, limit int) []*db.Node {
	if limit <= 0 {
		return []*db.Node{}
	}
	const batch = 300
	cursor := int64(0)
	out := make([]*db.Node, 0, limit)
	for len(out) < limit {
		page, more, err := store.ListByKindPage(db.KindIntent, cursor, batch)
		if err != nil || len(page) == 0 {
			break
		}
		for _, intent := range page {
			switch intent.State {
			case "done", "blocked", "exhausted", "stopped":
				out = append(out, intent)
			}
			if len(out) >= limit {
				break
			}
		}
		if !more {
			break
		}
		cursor = page[len(page)-1].ID
	}
	return out
}

// relatedTaskOverviews distills persistent blackboard state from direct source
// tasks. It intentionally reads each source's local store methods, never its own
// related sources, so inheritance is one level only.
func (t *ToolSet) relatedTaskOverviews() []map[string]any {
	sources, err := t.ts.DirectSourceStores()
	if err != nil {
		return []map[string]any{}
	}
	if len(sources) > db.MaxTaskSourceCount {
		sources = sources[:db.MaxTaskSourceCount]
	}
	perSourceTextBudget := relatedOverviewBudgetForSources(len(sources))
	out := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		ts := source.Store
		// §2 cross-task: render the source task's OWN folded view — fold out the
		// members it has already folded, and surface its cold_digests read-only.
		hidden := hiddenMembersFor(ts)
		budget := overviewTextBudget{remaining: perSourceTextBudget}
		item := map[string]any{
			"source_task_id": source.Task.TaskID,
			"inherited":      true,
			"task": map[string]any{
				"description": budget.take(source.Task.Description, 800),
				"goal":        budget.take(source.Task.Goal, 800),
				"status":      source.Task.Status,
			},
		}
		stats, statsErr := ts.Stats()

		edges, _ := ts.Edges(5000)
		parentsOf := map[int64][]int64{}
		yieldsOf := map[int64][]int64{}
		factFrom := map[int64]int64{}
		for _, edge := range edges {
			switch edge.Rel {
			case db.RelDerivedFrom, db.RelSpawns:
				parentsOf[edge.To] = append(parentsOf[edge.To], edge.From)
			case db.RelYields:
				yieldsOf[edge.From] = append(yieldsOf[edge.From], edge.To)
				factFrom[edge.To] = edge.From
			}
		}

		goals, _ := ts.ListByKind(db.KindGoal, relatedOverviewMaxGoalsPerSource)
		goalSummary := make([]map[string]any, 0, len(goals))
		for _, goal := range goals {
			var payload map[string]any
			_ = json.Unmarshal(goal.Payload, &payload)
			goalSummary = append(goalSummary, inheritedMap(map[string]any{
				"id": goal.ID, "state": goal.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["goals"] = goalSummary

		// State-filtered in SQL: superseded/closed guidance must not reach another
		// task's planner, and must not crowd active hints out of the cap.
		hints, _ := ts.ListByKindState(db.KindHint, "active", relatedOverviewMaxHintsPerSource)
		hintSummary := make([]map[string]any, 0, len(hints))
		for _, hint := range hints {
			var payload map[string]any
			_ = json.Unmarshal(hint.Payload, &payload)
			hintSummary = append(hintSummary, inheritedMap(map[string]any{
				"id": hint.ID, "state": hint.State, "text": budget.take(payload["text"], 400),
			}, source.Task.TaskID))
		}
		item["hints"] = hintSummary

		facts, _ := ts.ListByKind(db.KindFact, relatedOverviewMaxFactsPerSource)
		findings, _ := ts.ListByKind(db.KindFinding, relatedOverviewMaxFindingsPerTask)
		intentNodes, _ := ts.ListByKind(db.KindIntent, 300)
		terminalIntent := make(map[int64]bool, len(intentNodes))
		for _, intent := range intentNodes {
			terminalIntent[intent.ID] = inheritedIntentSummaryState(intent.State)
		}
		item["facts"] = len(facts)
		item["findings"] = len(findings)
		if statsErr == nil {
			item["facts"] = stats[db.KindFact]
			item["findings"] = stats[db.KindFinding]
			// Hints are compared by active state, which Stats() does not count, so
			// only the all-state kinds can report truncation here.
			if stats[db.KindGoal] > len(goals) ||
				stats[db.KindFact] > len(facts) || stats[db.KindFinding] > len(findings) {
				budget.truncated = true
			}
		}
		recentFindings := make([]map[string]any, 0, len(findings))
		for _, finding := range findings {
			entry := inheritedMap(compactFinding(finding), source.Task.TaskID)
			entry["summary"] = budget.take(entry["summary"], 400)
			recentFindings = append(recentFindings, entry)
		}
		item["recent_findings"] = recentFindings
		recentFacts := make([]map[string]any, 0, len(facts))
		for _, fact := range facts {
			if hidden(fact.ID) {
				continue // folded into this source's cold_digests — shown there (§2/§6.2)
			}
			m := inheritedMap(compactNode(fact), source.Task.TaskID)
			m["summary"] = budget.take(m["summary"], 400)
			if from := factFrom[fact.ID]; from > 0 && terminalIntent[from] {
				m["from_intent"] = from
			}
			var payload map[string]any
			if json.Unmarshal(fact.Payload, &payload) == nil {
				if confidence, ok := payload["confidence"].(string); ok && confidence != "" {
					m["confidence"] = confidence
				}
			}
			recentFacts = append(recentFacts, m)
		}
		item["recent_facts"] = recentFacts

		recentDoneRaw := recentTerminalIntents(ts, relatedOverviewMaxIntentsPerTask)
		recentDone := recentDoneRaw[:0] // in-place filter: drop this source's folded intents (§2)
		for _, intent := range recentDoneRaw {
			if hidden(intent.ID) {
				continue
			}
			recentDone = append(recentDone, intent)
		}
		for _, intent := range recentDone {
			intent.Inherited = true
			intent.SourceTaskID = source.Task.TaskID
		}
		intentResults := compactIntents(recentDone, parentsOf, yieldsOf)
		for i, intent := range recentDone {
			intentResults[i]["summary"] = budget.take(intentResults[i]["summary"], 400)
			acts, _, err := ts.ActivityPageForTerminalIntent(intent.ID, 0, 20)
			if err != nil {
				continue
			}
			var resultSummary, textFallback string
			for _, activity := range acts {
				switch activity.Kind {
				case "result":
					resultSummary = activity.Summary
				case "text":
					textFallback = activity.Summary
				}
			}
			if resultSummary == "" {
				resultSummary = textFallback
			}
			if resultSummary != "" {
				intentResults[i]["result_summary"] = budget.take(resultSummary, 800)
			}
		}
		item["recent_intent_results"] = intentResults
		// §2 cross-task: the source task's folded cold region, read-only, newest-member
		// first & capped like the current task's. Members (and overflow digests) are
		// resolvable via expand_digest(id)/node_detail(id), which search source tasks.
		if cds, more := coldDigestsRecent(ts, relatedOverviewMaxDigestsPerSource); len(cds) > 0 {
			for _, cd := range cds {
				cd["inherited"] = true
				cd["source_task_id"] = source.Task.TaskID
			}
			item["cold_digests"] = cds
			if len(more) > 0 {
				item["cold_digests_more"] = more // id of a truncated, older digest; expand with expand_digest(id)
			}
		}
		if statsErr == nil {
			item["node_stats"] = stats
		}

		if t.as != nil {
			if scopeRows, err := t.as.ListTaskScope(source.Task.TaskID); err == nil && len(scopeRows) > 0 {
				scopeCount := len(scopeRows)
				if len(scopeRows) > relatedOverviewMaxScopePerSource {
					scopeRows = scopeRows[:relatedOverviewMaxScopePerSource]
					budget.truncated = true
				}
				scope := make([]map[string]any, 0, len(scopeRows))
				for _, row := range scopeRows {
					entry := map[string]any{"kind": row.Kind, "source": budget.take(row.Source, 300)}
					switch {
					case row.Domain != "":
						entry["value"] = budget.take(row.Domain, 400)
					case row.Net != "":
						entry["value"] = budget.take(row.Net, 400)
					case row.Value != "":
						entry["value"] = budget.take(row.Value, 400)
					case row.CompanyID != nil:
						entry["company_id"] = *row.CompanyID
					}
					scope = append(scope, entry)
				}
				item["asset_scope"] = scope
				item["asset_scope_count"] = scopeCount
			}
			if coverage, err := t.as.TaskCoverage(source.Task.TaskID, source.Task.ExplorationID); err == nil {
				item["asset_coverage"] = map[string]any{
					"denominator": coverage.Denominator,
					"tested":      coverage.Tested,
					"pct":         coverage.Pct,
					"by_type":     coverage.ByType,
				}
			}
		}
		if budget.truncated {
			item["summary_truncated"] = true
		}
		out = append(out, item)
	}
	return out
}

func inheritedIntentSummaryState(state string) bool {
	switch state {
	case "done", "blocked", "exhausted", "stopped":
		return true
	default:
		return false
	}
}

// compactNode distills any exploration node to id + summary + state, dropping the
// big detail/evidence (fetch that on demand via node_detail).
//
// The summary is capped: graph_overview embeds every recent fact in the
// planner's *current* user turn on every round, and compaction rewrites only
// the history. One worker that pastes a large response into a summary would
// therefore make every later round exceed the context window, with no way to
// evict it until twenty newer facts are written — which needs the planner to
// run. The cap is compactSummaryRunes, applied by every compact* view.
func compactNode(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if s, ok := p["summary"].(string); ok {
		clipped, cut := clipRunes(s, compactSummaryRunes)
		m["summary"] = clipped
		if cut {
			m["summary_truncated"] = true
		}
	}
	if n.Inherited {
		inheritedMap(m, n.SourceTaskID)
	}
	return m
}

// compactSummaryRunes bounds a summary injected into any agent-visible view.
// Facts carry one-line conclusions, but nothing enforces brevity; a runaway
// summary must not bloat a whole page — and in graph_overview it lands in the
// planner's current turn on every round, where nothing can evict it. Full text
// stays available via node_detail(id).
const compactSummaryRunes = 160

// clipRunes truncates s to at most n runes and reports whether it cut.
func clipRunes(s string, n int) (string, bool) {
	if n <= 0 {
		return "", s != ""
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i] + "…", true
		}
		count++
	}
	return s, false
}

// compactFinding is compactNode plus the vuln-specific vulnclass/severity.
//
// It delegates to compactNode so the summary cap applies here too: a finding's
// summary reaches the planner through graph_overview every round, exactly like
// a fact's, so leaving it uncapped would defeat the bound.
func compactFinding(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := compactNode(n)
	if vc, ok := p["vulnclass"]; ok && vc != nil && vc != "" {
		m["vulnclass"] = vc
	}
	if sv, ok := p["severity"]; ok && sv != nil && sv != "" {
		m["severity"] = sv
	}
	return m
}

func (t *ToolSet) listFindings() actool.CoreTool {
	return t.readExpTool("list_findings", "List the [confirmed vulnerabilities] of this task and directly linked tasks (compact: id+task_id+intent_id+vulnclass+severity+summary+status). Entries from linked tasks carry source_task_id/inherited=true and are read-only. This contains only vulnerabilities; for ordinary exploration facts use list_facts, for details use node_detail(id).",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKindWithSources(db.KindFinding, 500)
			if err := t.ts.PopulateFindingTrafficIDs(f); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			intentOf, _ := t.ts.FindingIntentsWithSources() // finding id -> id of the intent that produced it
			taskID := t.taskID
			if taskID <= 0 {
				taskID, _ = t.ts.TaskID()
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				m := compactFinding(n)
				if n.FindingID > 0 {
					m["finding_id"], m["finding_node_id"], m["traffic_count"] = n.FindingID, n.ID, n.TrafficCount
				}
				if n.Inherited {
					m["task_id"] = n.SourceTaskID
				} else {
					m["task_id"] = taskID
				}
				if iid, ok := intentOf[n.ID]; ok {
					m["intent_id"] = iid
				}
				out = append(out, m)
			}
			return jsonResult(out)
		})
}

// factsPageSize is the default page size for list_facts. Facts pile up on long
// tasks; returning all of them at once (the old behaviour) could blow up the
// context, so default to the newest page and let the agent page/filter for more.
const factsPageSize = 20

func (t *ToolSet) listFacts() actool.CoreTool {
	return t.readExpTool("list_facts", "Paginated list of the [exploration facts/conclusions] of this task and directly linked tasks, newest first (compact: id+summary+state; long summaries are truncated, use node_detail(id) for the full text). All parameters are optional: limit (default 20, max 100), before (cursor: pass the next_before returned by the previous page to get an older page; omit or 0 = newest page), q (filter by summary keyword). Returns {facts, total, has_more, next_before}: total is the count after filtering; when has_more=true, use next_before to fetch the next page. Entries from linked tasks carry source_task_id/inherited=true and are read-only. For vulnerabilities see list_findings.",
		obj(map[string]any{
			"limit":  intp("Number of results to return, default 20, max 100"),
			"before": intp("Pagination cursor: only return older facts with an id less than this value; omit or 0 = newest page"),
			"q":      str("Filter by keyword in the fact summary (case-insensitive); omit = no filter"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit  int    `json:"limit"`
				Before int64  `json:"before"`
				Q      string `json:"q"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = factsPageSize
			}
			if limit > 100 {
				limit = 100
			}
			f, hasMore, total, err := t.ts.ListByKindPageWithSources(db.KindFact, a.Before, limit, strings.TrimSpace(a.Q))
			if err != nil {
				return actool.Result{}, err
			}
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				out = append(out, compactNode(n))
			}
			res := map[string]any{"facts": out, "total": total, "has_more": hasMore}
			if hasMore && len(f) > 0 {
				res["next_before"] = f[len(f)-1].ID // Pass this back to fetch the next page (older items)
			}
			return jsonResult(res)
		})
}

func (t *ToolSet) nodeDetail() actool.CoreTool {
	return t.readExpTool("node_detail", "Get the full content of an exploration-graph node by id from this task or directly linked tasks. Inherited nodes carry source_task_id/inherited=true and are read-only. Only accepts exploration-node ids returned by list_facts/list_findings/graph_overview; for assets use list_assets/asset_neighbors.",
		obj(map[string]any{"id": idp("exploration graph node id (not an asset id)")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ID)
			if id <= 0 {
				return actool.Errorf("id is required"), nil
			}
			n, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == nil {
				return actool.Errorf(fmt.Sprintf("exploration node %d not found. If you are looking for an asset, use list_assets / asset_neighbors (assets and exploration nodes are separate id spaces; an asset id cannot be passed to node_detail).", id)), nil
			}
			if err := t.ts.PopulateFindingTrafficIDs([]*db.Node{n}); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(n) // full payload incl. detail / evidence, plus explicit finding IDs
		})
}

// --- planner write tools ---

// intentItem is one exploration direction for add_intent, whether in a batch or a single entry.
type intentItem struct {
	Summary   string            `json:"summary"`
	AssetIDs  []json.RawMessage `json:"asset_ids"`
	ParentIDs []json.RawMessage `json:"parent_ids"`
	Priority  int               `json:"priority"`
}

// addOneIntent creates one intent node, links it to its upstream lineage, and returns its id.
// Constraint: an intent may only be anchored to confirmed knowledge. Every parent_id must be an existing fact/finding
// Node (must not be attached under another intent/goal/hint). For a completely new top-level direction, leave parent_ids empty; as a fallback, link to the origin fact.
// This enforces, at creation time, that every intent connects to a fact node and is discovery-driven rather than planned out of thin air.
func (t *ToolSet) addOneIntent(it intentItem) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary must not be empty")
	}
	// Validate the anchor first (before creating the node) so that a bad anchor does not leave an orphaned intent behind.
	parents := pidList(it.ParentIDs)
	for _, pidv := range parents {
		n, err := t.ts.GetNodeWithSources(pidv)
		if err != nil || n == nil {
			return 0, fmt.Errorf("parent_id %d does not exist in this task or directly linked tasks: parent_ids must be ids of existing [fact/finding] nodes; for a new top-level direction, leave parent_ids empty", pidv)
		}
		if n.Kind != db.KindFact && n.Kind != db.KindFinding {
			return 0, fmt.Errorf("parent_id %d is a %q node and cannot serve as an intent anchor: intents may only be anchored on confirmed [fact/finding] nodes, not on intents/goals/hints; for a new top-level direction, leave parent_ids empty", pidv, n.Kind)
		}
	}
	priority := it.Priority
	if priority == 0 {
		priority = 5
	}
	anchors := pidList(it.AssetIDs)
	// Asset interception: if an asset bound to the intent matches a system asset interception rule, issuing the intent is forbidden.
	if t.as != nil && len(anchors) > 0 {
		hits, err := t.as.CheckAssetsIntercept(t.taskID, anchors)
		if err != nil {
			return 0, fmt.Errorf("asset interception check failed: %w", err)
		}
		if len(hits) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "Assets bound to intent \"%s\" failed the test-scope check; stop testing the related assets:", it.Summary)
			for _, h := range hits {
				fmt.Fprintf(&b, "\n - %s", h.Describe())
			}
			return 0, fmt.Errorf("%s", b.String())
		}
	}
	payload := map[string]any{"summary": it.Summary}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	id, err := t.ts.AddIntent(payload, priority, anchors, "planner")
	if err != nil {
		return 0, err
	}
	// upstream lineage: link each (validated) fact/finding parent → this intent, so
	// "multiple facts combine into one new intent" is expressible.
	for _, parent := range parents {
		_ = t.ts.Link(parent, db.RelDerivedFrom, id)
	}
	// a top-level intent (no explicit parent) connects to the origin fact, so every
	// intent still traces back to a fact node — at task start the only fact is the
	// origin, and the first intents derive from it.
	if len(parents) == 0 {
		if origin, _ := t.ts.OriginFactID(); origin > 0 {
			_ = t.ts.Link(origin, db.RelDerivedFrom, id)
		}
	}
	return id, nil
}

func (t *ToolSet) addIntent() actool.CoreTool {
	return t.writeExpTool("add_intent", "Generate an [exploration direction], write it to the frontier, and link it into the exploration chain. An intent is an open exploration direction, not a fixed type: describe in one sentence via summary what to explore, verify, or exploit.\n"+
		"★Prefer batching: submit the several new directions from one round together in the intents array (saves round trips compared with one call each). Returns an ids array of the same length and order as intents (failed items have id=0; see errors for details). For a single item, omit intents and give summary at the top level.",
		obj(map[string]any{
			"intents":    map[string]any{"type": "array", "description": "[Preferred] Array of new exploration directions, processed in order. Each element has the same fields as the top-level fields below (summary/asset_ids/parent_ids/priority). Returns ids of the same length and order as this array.", "items": map[string]any{"type": "object"}},
			"summary":    str("[Single] One-sentence description of this exploration direction: what to do and why. A clearly stated direction is enough; it does not depend on asset ids."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Target asset ids to test or attack in this direction (**pass them whenever possible**; 0, 1, or many; these are asset ids returned by list_assets, not exploration node ids): which assets (sites/interfaces/parameters/hosts, etc.) this direction targets. Whenever the direction revolves around specific assets, be sure to pass them: it is the structured marker for 'which targets this exploration hits', used for coverage deduplication and for linking the intent into the asset chain. Leave empty only for pure global reconnaissance with no concrete target assets."},
			"parent_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Upstream anchor ids (optional, 0, 1, or many): which confirmed [fact/finding] nodes this direction is derived from. **May only contain existing fact/finding node ids, never intents/goals/hints**: an intent must be anchored on confirmed knowledge, so it is finding-driven rather than planned from nothing. If several facts together produce one new intent, pass them all; for a new top-level reconnaissance direction, leave this empty (it is automatically attached to the task's origin fact)."},
			"priority":   intp("Priority 0-10, default 5"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents    []intentItem `json:"intents"`
				intentItem              // Single-item mode: top-level summary/asset_ids/parent_ids/priority
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []intentItem{a.intentItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			createdAny := false
			for i, it := range items {
				id, err := t.addOneIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				createdAny = true
			}

			// When a human directly dispatches an intent through the main agent → if the task is already done (the goalless branch with no open goals), it
			// is moved back to running so that a worker can pick up this intent for execution. resumeTask is only injected by the main agent's Chat entry point
			// (SetResumeTask); the planner's ToolSet is nil, so when the planner calls add_intent itself, this block is a
			// no-op and does not affect its normal production of intents. The intent node has already been created above (open), so reviving the task will not mistakenly treat it as drained.
			ack, aerr := "", error(nil)
			if createdAny {
				ack, aerr = t.admit()
			}

			if !batch { // Single item: keep the original return value
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return admissionText(fmt.Sprintf("intent created: %d (open, not executing yet)", ids[0]), ack, aerr), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return admissionJSON(out, ack, aerr)
		})
}

// admit runs the main-agent-only task admission (nil callback = not wired, no
// admission to report). The graph write has already happened when it is called.
func (t *ToolSet) admit() (string, error) {
	if t.resumeTask == nil {
		return "", nil
	}
	return t.resumeTask()
}

// admissionText appends the admission outcome to a single-item reply; a failed
// admission is an error result, because the saved node will not run by itself.
func admissionText(msg, ack string, err error) actool.Result {
	if err != nil {
		return actool.Errorf(msg + "; saved, but task admission FAILED: " + err.Error())
	}
	if ack != "" {
		msg += "; " + ack
	}
	return actool.Text(msg)
}

// admissionJSON is the batch counterpart: ids stay in the payload either way,
// and a failed admission makes the whole result an error.
func admissionJSON(out map[string]any, ack string, err error) (actool.Result, error) {
	if err == nil {
		if ack != "" {
			out["admission"] = ack
		}
		return jsonResult(out)
	}
	out["admission_error"] = err.Error()
	b, _ := json.Marshal(out)
	return actool.Errorf(string(b)), nil
}

func (t *ToolSet) listGoals() actool.CoreTool {
	return t.readExpTool("list_goals", "List this task's goal nodes and their states (open/met), used to judge whether they are achieved.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			g, _ := t.ts.ListByKind(db.KindGoal, 100)
			return jsonResult(g)
		})
}

// pausedIntentIDs lists intents still parked in paused state (waiting on a
// human). The completion gate refuses to close the task while any remain: a
// paused intent is in play, and completing would silently abandon it.
func (t *ToolSet) pausedIntentIDs() []int64 {
	if t.ts == nil {
		return nil
	}
	intents, err := t.ts.ListByKindState(db.KindIntent, "paused", 1000)
	if err != nil {
		return nil
	}
	ids := make([]int64, 0, len(intents))
	for _, n := range intents {
		ids = append(ids, n.ID)
	}
	return ids
}

// allGoalsMet reports whether every goal of the task is met, treating goalID as
// met. The pre-write gate uses it to refuse a completion that would strand a
// paused intent before anything is persisted; the post-write check re-reads it
// so a concurrent prove_goal is not missed.
func (t *ToolSet) allGoalsMet(goalID int64) (int, bool) {
	goals, err := t.ts.ListByKind(db.KindGoal, 1000)
	if err != nil || len(goals) == 0 {
		return 0, false
	}
	for _, g := range goals {
		if g.ID != goalID && g.State != "met" {
			return len(goals), false
		}
	}
	return len(goals), true
}

func (t *ToolSet) proveGoal() actool.CoreTool {
	return t.writeExpTool("prove_goal", "Call this when you judge that a finding or fact proves a goal has been achieved: link the evidence node to the goal node and mark the goal met.",
		obj(map[string]any{
			"goal_id":     idp("goal node id"),
			"evidence_id": idp("id of the finding/fact node that proves it"),
			"reason":      str("Why this evidence satisfies the goal"),
		}, "goal_id", "evidence_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GoalID     json.RawMessage `json:"goal_id"`
				EvidenceID json.RawMessage `json:"evidence_id"`
				Reason     string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			goal, ev := pid(a.GoalID), pid(a.EvidenceID)
			if goal == 0 || ev == 0 {
				return actool.Errorf("goal_id and evidence_id are required"), nil
			}
			goalNode, err := t.ts.GetNode(goal)
			if err != nil || goalNode == nil || goalNode.Kind != db.KindGoal {
				return actool.Errorf("goal_id must be a goal node of this task (goals of linked tasks are read-only)"), nil
			}
			evidenceNode, err := t.ts.GetNodeWithSources(ev)
			if err != nil || evidenceNode == nil || (evidenceNode.Kind != db.KindFact && evidenceNode.Kind != db.KindFinding) {
				return actool.Errorf("evidence_id must be a finding/fact node of this task or of directly linked tasks"), nil
			}
			// The completion gate runs before either write: refusing after the
			// goal was already linked and marked met left the change persisted
			// with nothing re-evaluating completion, so the planner could not
			// simply retry once the paused intents were resolved.
			if _, allMet := t.allGoalsMet(goal); allMet {
				if paused := t.pausedIntentIDs(); len(paused) > 0 {
					return actool.Errorf(fmt.Sprintf("all goals are met, but intent(s) %v are still paused: the task cannot complete while they are open. Resume them, or call kill_work on each with a reason, then re-check.", paused)), nil
				}
			}
			// Both writes must succeed before the goal counts as met. Dropping
			// their errors let a failed SetNodeState leave the goal open in the
			// database while the all-met check below still returned met=true
			// (it re-reads, but a transient failure there can succeed while the
			// write failed), which closes the task on evidence that was never
			// persisted. A dropped Link error likewise leaves a "met" goal with
			// no proof edge, so the audit view shows no evidence.
			if err := t.ts.Link(ev, db.RelProves, goal); err != nil {
				return actool.Errorf(fmt.Sprintf("could not link evidence %d to goal %d: %v", ev, goal, err)), nil
			}
			if err := t.ts.SetNodeState(goal, "met"); err != nil {
				return actool.Errorf(fmt.Sprintf("could not mark goal %d met: %v", goal, err)), nil
			}
			// Each time a goal is marked met, check whether ALL goals of this task are now met; if so, automatically determine
			// Task completed (sets GoalMet), no need to rely on the model explicitly calling goal_met anymore.
			if n, allMet := t.allGoalsMet(goal); allMet {
				if paused := t.pausedIntentIDs(); len(paused) > 0 {
					return actool.Errorf(fmt.Sprintf("all goals are met, but intent(s) %v are still paused: the task cannot complete while they are open. Resume them, or call kill_work on each with a reason, then re-check.", paused)), nil
				}
				t.GoalMet = true
				t.Reason = fmt.Sprintf("All %d goals are met (last triggered by goal %d)", n, goal)
				return actool.Text(fmt.Sprintf("goal %d marked met; all goals of this task are achieved, so the task is automatically judged complete", goal)), nil
			}
			return actool.Text(fmt.Sprintf("goal %d marked met", goal)), nil
		})
}

func (t *ToolSet) goalMet() actool.CoreTool {
	return writeTool("goal_met", "[Immediately end the entire task]: call this only when you have confirmed that [all goals of the task are truly achieved and the whole task is complete] (note: this means the task as a [whole]; achieving just one goal, one flag, or one vulnerability does [not count], and in that case use prove_goal to mark that goal instead). ⚠️It is not for [ending the current planning round]: if there are no new intents to dispatch this round, or you are waiting on worker output, just [end this round directly without calling this tool] (zero intents is completely normal). For normal completion, prefer prove_goal to prove goals one by one; goal_met is only a way to bypass per-goal proof and close out the whole task directly.",
		obj(map[string]any{"reason": str("Reason for achievement (must be evidence that the goal was truly achieved, not a reason such as 'no new directions this round' that merely ends the round)")}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Reason string }
			_ = json.Unmarshal(in, &a)
			if paused := t.pausedIntentIDs(); len(paused) > 0 {
				return actool.Errorf(fmt.Sprintf("cannot complete the task: intent(s) %v are still paused. Resume them, or call kill_work on each with a reason, first.", paused)), nil
			}
			t.GoalMet = true
			t.Reason = a.Reason
			return actool.Text("acknowledged: goal marked met"), nil
		})
}

// --- worker write tools ---

func (t *ToolSet) addFinding() actool.CoreTool {
	return writeTool("report_finding", "Record a confirmed vulnerability; provide verifiable evidence such as command output and logs in evidence, and attach browser_screenshot paths in screenshot_paths so the UI renders them. Pass the current intent_id in task context. No evidence kind is mandatory. For an HTTP finding whose request is repeatable and non-destructive, RECOMMENDED: replay it through the recorder (curl via the proxy env) and cite that exchange in traffic_ids. For non-HTTP or destructive findings, cite artifacts (exec artifact ids from your tool results) and flows (host/port/proto; the window defaults to this intent's run time), which pin the matching packets from the capture. The returned finding_id is the independent vulnerability record ID; finding_node_id is the exploration node ID (the first line keeps this node number).", obj(map[string]any{
		"vulnclass": str("Vulnerability class"), "name": str("Vulnerability name"), "severity": str("critical|high|medium|low"), "summary": str("Finding summary"),
		"intent_id": idp("Intent id of the current task"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Affected asset ids"},
		"evidence":         str("Evidence/PoC text"),
		"evidence_hint_id": idp("Optional: id of the hint node in this task that corresponds to this vulnerability; its structured traffic_refs are carried over automatically. Cannot reference inherited hints or hints belonging to other vulnerabilities"),
		"screenshot_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional. Paths returned by browser_screenshot (tasks/<taskId>/screenshots/<name>.png), recorded as renderable evidence. Each must exist as a file of at most 10 MB; at most 10 paths. A bad path refuses the whole report."},
		"traffic_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional shorthand for traffic_refs: real exchange IDs from traffic_search, bound as proof."},
		"artifacts":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional. Exec artifact ids (exec-artifacts/<id>) from the [exec artifact: ...] line of your tool results, anchored by the hash of their manifest. At most 10."},
		"flows": map[string]any{"type": "array", "description": "Optional. Packets of direct (non-proxied) traffic to pin from the capture. host is an authorized IP; port 0 = any; proto tcp|udp|any; from/to are RFC3339. The window cannot start before the intent was created (or the task started if no intent is given). At most 5. A flow that cannot be pinned is reported back and the finding is still recorded.",
			"items": obj(map[string]any{"host": str("IP address"), "port": map[string]any{"type": "integer"}, "proto": map[string]any{"type": "string", "enum": []string{"tcp", "udp", "any"}}, "from": str("RFC3339 start"), "to": str("RFC3339 end")}, "host")},
		"traffic_refs": map[string]any{"type": "array", "description": "Optional. For HTTP/HTTPS vulnerabilities, first search and verify item by item that the requests/responses actually support the vulnerability conclusion, then fill in the real IDs in reproduction order. For non-HTTP vulnerabilities such as TCP, or when traffic was not captured or no exact record is found, omit this or pass [], which does not block reporting; explain the reason in evidence and provide other verifiable evidence. Do not guess IDs, infer associations from domain or time, or repeat probes merely to pad packets. Roles: baseline = normal control; proof = proof of vulnerability; verification = supplementary verification; supporting = auxiliary evidence.",
			"items": obj(map[string]any{"traffic_id": str("Real traffic ID returned by traffic_search"), "role": map[string]any{"type": "string", "enum": []string{"baseline", "proof", "verification", "supporting"}}, "note": str("How this traffic supports the vulnerability conclusion")}, "traffic_id")},
	}, "vulnclass", "severity", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			VulnClass, Name, Severity, Summary, Evidence string
			IntentID                                     json.RawMessage   `json:"intent_id"`
			AssetIDs                                     []json.RawMessage `json:"asset_ids"`
			TrafficRefs                                  []db.TrafficRef   `json:"traffic_refs"`
			EvidenceHintID                               json.RawMessage   `json:"evidence_hint_id"`
			ScreenshotPaths                              []string          `json:"screenshot_paths"`
			TrafficIDs                                   []string          `json:"traffic_ids"`
			Artifacts                                    []string          `json:"artifacts"`
			Flows                                        []findingFlow     `json:"flows"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.ts == nil {
			return actool.Errorf("report_finding requires task context; on platform chats, hand the vulnerability over to the corresponding task via add_task_hint, carrying the existing traffic_refs in the hint so the task agent registers it. An already-registered vulnerability can be backfilled with bind_finding_traffic."), nil
		}
		// Auto-binding off: ignore the evidence params instead of rejecting the call.
		// stripTrafficParameters already removes them from the advertised schema, but
		// models routinely emit fields anyway — failing here would discard a confirmed
		// finding over a stray parameter. The success path below reports evidence_status
		// "not_bound" with the "Closed; can be linked manually on the page" note, which is what the caller needs.
		if !findingTrafficBindingEnabled() {
			a.TrafficRefs, a.TrafficIDs, a.EvidenceHintID = nil, nil, nil
		}
		for _, id := range a.TrafficIDs {
			a.TrafficRefs = append(a.TrafficRefs, db.TrafficRef{TrafficID: id, Role: "proof"})
		}
		if len(a.EvidenceHintID) > 0 && pid(a.EvidenceHintID) <= 0 {
			return actool.Errorf("evidence_hint_id must be a valid hint node ID; omit it when there is no handover hint"), nil
		}
		refs, err := t.findingRefsFromHint(pid(a.EvidenceHintID), a.TrafficRefs)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		shots, err := t.checkScreenshots(a.ScreenshotPaths)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		intentID := pid(a.IntentID)
		pinned, failed := t.pinEvidence(ctx, a.Artifacts, a.Flows, intentID)
		if len(pinned) > 0 {
			a.Evidence = strings.TrimSpace(a.Evidence + "\n\nPinned evidence:\n- " + strings.Join(pinned, "\n- "))
		}
		input := db.RecordFindingInput{TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: intentID, VulnClass: a.VulnClass, Name: a.Name, Severity: a.Severity, Summary: a.Summary, Evidence: a.Evidence, Worker: t.worker, AssetIDs: pidList(a.AssetIDs), Screenshots: shots}
		var recorded *db.RecordedFinding
		if t.findingRecorder != nil {
			recorded, err = t.findingRecorder.Record(ctx, input, refs)
		} else if len(refs) > 0 {
			return actool.Errorf("traffic evidence storage is unavailable; vulnerability not registered"), nil
		} else {
			recorded, err = t.ts.RecordFinding(ctx, input)
		}
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if t.notifyFinding != nil {
			iid := input.IntentID
			if iid <= 0 {
				iid = t.ownerNode
			}
			t.notifyFinding(iid, a.Summary)
		} else if t.notify != nil {
			t.notify()
		}
		t.writes.Findings++
		// Keep the first line's node-ID contract for existing reporter triggers.
		for i := range recorded.Traffic.Bindings {
			recorded.Traffic.Bindings[i].Snapshot.ReqHead = ""
			recorded.Traffic.Bindings[i].Snapshot.RespHead = ""
		}
		result := struct {
			*db.RecordedFinding
			EvidenceStatus string   `json:"evidence_status"`
			EvidenceNote   string   `json:"evidence_note,omitempty"`
			Pinned         []string `json:"evidence_pinned,omitempty"`
			PinFailed      []string `json:"evidence_pin_failed,omitempty"`
		}{RecordedFinding: recorded, EvidenceStatus: "bound", Pinned: pinned, PinFailed: failed}
		if len(recorded.Traffic.Bindings) == 0 {
			result.EvidenceStatus = "not_bound"
			result.EvidenceNote = "Vulnerability saved with no traffic bound."
			if len(pinned) == 0 {
				result.EvidenceNote += " " + evidenceAdvice
			}
			if !findingTrafficBindingEnabled() {
				result.EvidenceNote = "Vulnerability saved. Automatic traffic binding by the agent is disabled; link traffic manually on the page."
			}
		}
		raw, _ := json.Marshal(result)
		// The first line stays "finding recorded: <node id>": the reporter trigger
		// and update_finding_report both parse that prefix. A folded repeat says
		// so on the next line instead, which the model reads and the parsers ignore.
		head := fmt.Sprintf("finding recorded: %d", recorded.NodeID)
		if !recorded.Created {
			head += "\nnote: this matched an existing finding of the same name and assets; that row was refreshed, not duplicated"
		}
		return actool.Text(head + "\n" + string(raw)), nil
	})
}

const (
	maxFindingScreenshots     = 10
	maxFindingScreenshotBytes = 10 << 20
)

// checkScreenshots validates the screenshot paths of one report before the row
// is written: a bad path refuses the report instead of storing a link the UI
// cannot render. Returns the paths unchanged.
func (t *ToolSet) checkScreenshots(paths []string) ([]string, error) {
	if len(paths) > maxFindingScreenshots {
		return nil, fmt.Errorf("screenshot_paths: at most %d paths, got %d", maxFindingScreenshots, len(paths))
	}
	prefix := "tasks/" + strconv.FormatInt(t.taskID, 10) + "/screenshots/"
	for _, p := range paths {
		bad := func(why string) error { return fmt.Errorf("screenshot_paths: %q: %s", p, why) }
		if !filepath.IsLocal(p) {
			return nil, bad("must be a workspace-relative path")
		}
		if strings.Contains(strings.ReplaceAll(p, `\`, "/"), "..") {
			return nil, bad("must not contain ..")
		}
		if !strings.HasPrefix(p, prefix) {
			return nil, bad("must be under " + prefix)
		}
		if t.workDir == "" {
			return nil, bad("screenshot storage is unavailable")
		}
		fi, err := os.Stat(filepath.Join(t.workDir, filepath.FromSlash(p)))
		if err != nil {
			return nil, bad("does not exist")
		}
		if !fi.Mode().IsRegular() {
			return nil, bad("is not a regular file")
		}
		if fi.Size() > maxFindingScreenshotBytes {
			return nil, bad("is larger than 10 MB")
		}
	}
	return paths, nil
}

// recordFact writes a general exploration RESULT/conclusion (not a vuln, not a
// new asset) into the EXPLORATION graph, chained to the intent that produced it.
// This is the home for observations and — importantly — negative results
// ("port closed", "param not injectable", "no login found"). Such conclusions
// must NOT be stuffed into the asset graph via upsert_asset.
// factItem is a single fact entry for record_fact, whether batched or individual.
type factItem struct {
	Summary    string            `json:"summary"`
	Detail     string            `json:"detail"`
	Evidence   string            `json:"evidence"`   // One line of key evidence (command + key output line), supporting the conclusion and convenient for later verification
	Confidence string            `json:"confidence"` // observed (directly seen) | inferred (deduced from observed phenomena)
	IntentID   json.RawMessage   `json:"intent_id"`
	AssetIDs   []json.RawMessage `json:"asset_ids"`
}

// recordOneFact writes one fact node and links it to the intent (intent→yields→fact). defaultIntent is
// Default intent for batch operations (used when the item does not specify an intent_id).
func (t *ToolSet) recordOneFact(it factItem, defaultIntent int64) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary cannot be empty")
	}
	payload := map[string]any{"summary": it.Summary}
	if it.Detail != "" {
		payload["detail"] = it.Detail
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	if c := strings.TrimSpace(it.Confidence); c != "" {
		payload["confidence"] = c
	}
	intent := pid(it.IntentID)
	if intent <= 0 {
		intent = defaultIntent
	}
	if intent > 0 {
		node, err := t.ts.GetNode(intent)
		if err != nil || node == nil || node.Kind != db.KindIntent {
			return 0, fmt.Errorf("intent_id must be an intent in this task (intents from related tasks are read-only)")
		}
	}
	// a fact is its OWN node kind (distinct from a vuln finding).
	id, err := t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, pidList(it.AssetIDs))
	if err != nil {
		return 0, err
	}
	if intent > 0 {
		_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> fact
	}
	t.writes.Facts++
	return id, nil
}

func (t *ToolSet) recordFact() actool.CoreTool {
	return t.writeExpTool("record_fact", "Record exploration facts/conclusions in the exploration graph and link them to the intent that produced them (intent_id). Use this to record exploration results—including positive conclusions such as fingerprints/enumeration and negative conclusions such as 'port is closed', 'parameter is not injectable', or 'no login entry point was found'.\n"+
		"⚠️Combine multiple observations from one exploration into a single fact rather than splitting them. When possible, represent them together in one fact: summary = a one-sentence conclusion; detail = related details (which may include multiple items). Example: a fingerprinting intent should produce one fact {summary:'Identified the technology stack and response characteristics of site X', detail:'nginx 1.25 / Vue3 / 200 / title=.. / body_len=..'}, rather than separate facts for the status code, fingerprint, and title. An intent usually produces one fact; splitting too finely makes the graph grow without limit.\n"+
		"★Use the facts array to write multiple distinct conclusions in one call (each may omit intent_id and use the top-level intent_id by default). The returned ids array has the same length and order as facts.\n"+
		"⚠️Only record conclusions you actually saw in tool output; do not guess. evidence and confidence help prevent inaccurate conclusions from polluting the graph:\n"+
		"  · evidence = one key line supporting this conclusion (the command plus the one or two most convincing output lines). Keep it concise—the details belong in detail; do not paste large output blocks here.\n"+
		"  · confidence = observed (directly visible in the output) | inferred (deduced from evidence).\n"+
		"  · **For negative conclusions** (not injectable / port closed / no entry point found, etc.), record only an observation plus a tentative interpretation: state what you actually saw; the planner decides whether to abandon the direction based on the full picture. Always provide evidence. Mark as inferred if testing was incomplete or evidence is weak (including a single probe or an uncertain impression); use observed only when testing was exhaustive and the result was directly seen.",
		obj(map[string]any{
			"facts":      map[string]any{"type": "array", "description": "[Use when there are multiple distinct conclusions] Array of facts. Each element has the same fields as the top-level fields below (summary/detail/evidence/confidence/intent_id/asset_ids); if intent_id is omitted, the top-level intent_id is used. Returned ids match this array in length and order.", "items": map[string]any{"type": "object"}},
			"summary":    str("A one-sentence summary of the exploration conclusion (an overview of detail)"),
			"intent_id":  idp("ID of the intent that produced this fact (the intent assigned to you; the default for each item in a batch)"),
			"detail":     str("Details related to this fact: include the multiple observations from this exploration here"),
			"evidence":   str("One key line of evidence: the command plus the one or two output lines that best support the conclusion. Keep it concise; do not paste large output blocks (put details in detail)."),
			"confidence": str("observed (directly visible in the output) | inferred (deduced from evidence). Label negative conclusions honestly."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Related asset IDs (optional, 0/1/multiple): the assets this fact concerns"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Facts    []factItem `json:"facts"`
				factItem            // Single-item mode + batch default intent_id
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Facts) > 0
			items := a.Facts
			if !batch {
				items = []factItem{a.factItem}
			}
			defaultIntent := pid(a.factItem.IntentID) // Top-level intent_id = batch default

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.recordOneFact(it, defaultIntent)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // Single item: keep the original return value
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("fact recorded: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

type hintItem struct {
	Text        string            `json:"text"`
	AssetIDs    []json.RawMessage `json:"asset_ids"`
	TrafficRefs []db.TrafficRef   `json:"traffic_refs"`
	Supersedes  []json.RawMessage `json:"supersedes"`
}

// addOneHint attaches one hint node (active/human) to the exploration graph, can anchor to an asset, and returns the id.
// Hint ids listed in supersedes are marked consumed, so a newer rule retires the
// guidance it replaces instead of the planner reading both forever.
func (t *ToolSet) addOneHint(it hintItem) (int64, error) {
	if len(it.TrafficRefs) > 0 && !findingTrafficBindingEnabled() {
		return 0, fmt.Errorf("Agent automatic traffic binding is disabled, so the hint carrying traffic_refs was not saved; enable it in system settings, or send text only")
	}
	if strings.TrimSpace(it.Text) == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	// Validate before creating the node: a bad id fails this item without
	// leaving an orphaned hint behind.
	for _, raw := range it.Supersedes {
		sid := pid(raw)
		if sid <= 0 {
			return 0, fmt.Errorf("supersedes must contain valid hint ids")
		}
		n, err := t.ts.GetNode(sid)
		if err != nil {
			return 0, err
		}
		if n == nil || n.Kind != db.KindHint {
			return 0, fmt.Errorf("supersedes id %d is not a hint of this task", sid)
		}
	}
	var anchors []int64
	for _, raw := range it.AssetIDs {
		if tid := pid(raw); tid > 0 {
			anchors = append(anchors, tid)
		}
	}
	refs, err := db.NormalizeTrafficRefs(it.TrafficRefs)
	if err != nil {
		return 0, err
	}
	payload := map[string]any{"text": it.Text}
	if len(refs) > 0 {
		payload["traffic_refs"] = refs
	}
	// The planner is not woken per item here. addHint triggers it once after the whole batch is written (carrying the hint text),
	// to avoid flooding the planner's trigger line with one add_hint per hint.
	id, err := t.ts.AddNode(db.KindHint, payload, 0, "active", "human", anchors)
	if err != nil {
		return 0, err
	}
	for _, raw := range it.Supersedes {
		// Best-effort like the lineage links: the new hint is already stored, and
		// a failed state flip only leaves the old hint visible one round longer.
		_ = t.ts.SetNodeState(pid(raw), "consumed")
	}
	return id, nil
}

type goalItem struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass"`
}

// addOneGoal attaches one goal node (open) to the exploration graph: linked to the task root (origin fact, rel spawns).
// origin takes t.worker (default: system). Goals written by the goals decomposer are recorded as "goals", and those from the main agent runtime as "human".
// "human". The planner is woken up by setGoals once the whole batch has been written (see below); this part only persists the data.
func (t *ToolSet) addOneGoal(it goalItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	payload := map[string]any{"text": text}
	if vc := strings.TrimSpace(it.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	origin := t.worker
	if origin == "" {
		origin = "system"
	}
	id, err := t.ts.AddNode(db.KindGoal, payload, 0, "open", origin, nil)
	if err != nil {
		return 0, err
	}
	if of, _ := t.ts.OriginFactID(); of > 0 && id > 0 {
		_ = t.ts.Link(of, db.RelSpawns, id) // goals descend from the task root (origin fact)
	}
	return id, nil
}

// setGoals adds exploration goals (goal nodes) to [this task]. It serves both as the submission tool for the goal decomposer and as the main
// A tool for supplementing targets at agent runtime — the same managed tool, whose description/schema can be edited on the web side and bound per agent.
func (t *ToolSet) setGoals() actool.CoreTool {
	return writeTool("set_goals",
		"Adds exploration goals (goal) to [this task]. A goal is a final deliverable/verifiable result, not an attack step or reconnaissance action.\n"+
			"★Prefer batching: put multiple goals in the goals array and submit them in one call; returns ids of the same length and order (failed items have id=0; see errors for details). For a single goal, omit goals and give text at the top level.\n"+
			"vulnclass is optional: the matching vulnerability class (e.g. SQLi/IDOR); leave empty for business-logic goals. Whether a goal is achieved is determined by the system and marked met; this tool only adds goals.",
		obj(map[string]any{
			"goals":     map[string]any{"type": "array", "description": "[Preferred] Array of goals to add, processed in order. Each element: text (required, one independent, verifiable final goal) + vulnclass (optional). Returns ids of the same length and order as this array.", "items": map[string]any{"type": "object"}},
			"text":      str("[single] One independent, verifiable final goal"),
			"vulnclass": str("[single] Matching vulnerability class (if clear), e.g. SQLi/IDOR; leave empty for business-logic goals"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_goals is not enabled: ExplorationStore is not initialized"), nil
			}
			var a struct {
				Goals    []goalItem `json:"goals"`
				goalItem            // Single-item mode: top-level text/vulnclass
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Goals) > 0
			items := a.Goals
			if !batch {
				items = []goalItem{a.goalItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneGoal(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			ack, aerr := "", error(nil)
			if len(addedTexts) > 0 {
				// Wake the planner (once for the whole batch). Prefer notifyGoal: one set_goals call records a single trigger like "the user added N goals: …",
				// N targets: …" triggers, without flooding one message per item; the decomposer/worker has no such callback → fall back to plain notify (decomposer
				// with round-0 has no notify wired either, meaning no-op, because the planner has not started yet).
				switch {
				case t.notifyGoal != nil:
					t.notifyGoal(addedTexts)
				case t.notify != nil:
					t.notify()
				}
				// When the main agent adds goals at runtime, pull completed/paused tasks back to running so they keep going (the terminal-state gate
				// swallows ordinary notify; must be explicitly revived). Only mainagent wires this callback; the decomposer/worker is nil.
				ack, aerr = t.admit()
			}

			if !batch { // Single item: keep the original return value
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return admissionText(fmt.Sprintf("goal added: %d", ids[0]), ack, aerr), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return admissionJSON(out, ack, aerr)
		})
}

type constraintItem struct {
	Text string `json:"text"`
	Type string `json:"type"` // allow | deny
}

// addOneConstraint writes one operation constraint to task_constraints. origin is taken from t.worker (default: system):
// The decomposer writes "goals", and the main agent writes "human".
func (t *ToolSet) addOneConstraint(it constraintItem) (int64, error) {
	text := strings.TrimSpace(it.Text)
	if text == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	kind := strings.TrimSpace(strings.ToLower(it.Type))
	if kind == "" {
		kind = "deny" // Default to deny when unspecified: when no type is labeled, take the more conservative stance
	}
	if kind != "allow" && kind != "deny" {
		return 0, fmt.Errorf("type must be allow or deny")
	}
	return t.ts.AddConstraint(kind, text, t.worker)
}

// setConstraints adds operation constraints for [this task] (allow = what is permitted / deny = what is prohibited). It is both a goal
// The submission tool for extracting constraints in decomposer round-0, and also the tool for the main agent to supplement constraints at runtime — the same managed tool, editable in the web
// Edit descriptions/schema and bind per agent. Constraints are injected into the planner/worker system prompts to bound the exploration scope.
func (t *ToolSet) setConstraints() actool.CoreTool {
	return writeTool("set_constraints",
		"Adds operation constraints to [this task] to define the exploration boundary: type=allow (operations that are permitted) or deny (operations that are forbidden).\n"+
			"A constraint is a rule about which operations may or may not be performed (e.g. 'only test the current port, do not scan other ports', 'do not perform write operations on production databases', 'only passive reconnaissance is allowed'); it is not a goal, nor an attack step.\n"+
			"★Prefer batching: put multiple constraints in the constraints array and submit them in one call; returns ids of the same length and order (failed items have id=0; see errors for details). For a single constraint, omit constraints and give text/type at the top level.\n"+
			"Only record constraints explicitly stated in the task goal/description; do not invent any. When unsure of the type, use deny (more conservative).",
		obj(map[string]any{
			"constraints": map[string]any{"type": "array", "description": "[Preferred] Array of constraints to add, processed in order. Each element: text (required, one constraint) + type (allow|deny). Returns ids of the same length and order as this array.", "items": map[string]any{"type": "object"}},
			"text":        str("[single] Content of one operation constraint"),
			"type":        str("[single] allow (permitted) or deny (forbidden); defaults to deny when omitted"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("set_constraints is not enabled: ExplorationStore is not initialized"), nil
			}
			var a struct {
				Constraints    []constraintItem `json:"constraints"`
				constraintItem                  // Single-record mode: top-level text/type
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Constraints) > 0
			items := a.Constraints
			if !batch {
				items = []constraintItem{a.constraintItem}
			}
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneConstraint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			if !batch { // Single record: keep the return simple
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("constraint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) addHint() actool.CoreTool {
	return t.writeExpTool("add_hint", "Attaches strategic hints from a human or the main agent to the exploration graph; the planner will read them when it next generates intents.\n"+
		"★Prefer batching: put multiple hints in the hints array and submit them in one call (saves round trips compared with one call per hint). Returns an ids array of the same length and order as hints (failed items have id=0; see errors for details). For a single hint, omit hints and give text at the top level.\n"+
		"supersedes: ids of earlier hints of this task that this hint replaces; they are marked consumed and stop reaching the planner.",
		obj(map[string]any{
			"hints":        map[string]any{"type": "array", "description": "[Preferred] Array of hints to add, processed in order. Each element has the same fields as the top-level fields below (text/asset_ids/traffic_refs/supersedes). Returns ids of the same length and order as this array.", "items": obj(map[string]any{"text": str("Hint content"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": HintTrafficSchema(), "supersedes": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Ids of earlier hints of this task that this hint replaces (they become consumed)"}})},
			"text":         str("[single] Hint content, e.g. 'focus on authenticated APIs'"),
			"traffic_refs": HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Anchored asset ids (optional, 0/1/multiple)"},
			"supersedes":   map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[single] Ids of earlier hints of this task that this hint replaces (they become consumed)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Hints    []hintItem `json:"hints"`
				hintItem            // Single-record mode: top-level text/asset_ids
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Hints) > 0
			items := a.Hints
			if !batch {
				items = []hintItem{a.hintItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			var addedTexts []string
			for i, it := range items {
				id, err := t.addOneHint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
				addedTexts = append(addedTexts, strings.TrimSpace(it.Text))
			}
			if len(addedTexts) > 0 {
				// Wake the planner (once for the whole batch). Prefer notifyHint: record a single add_hint that says "the human added N strategic hint(s): …" to trigger it, so the planner knows this round was triggered by newly added hints and can see the hint content;
				// N strategic hints: ..." triggers, so the planner explicitly knows "this round was triggered by newly added hints" and sees the hint content;
				// Without this callback wired up, fall back to a bare notify (bare wake; the hint is still folded into the graph for it to read itself).
				switch {
				case t.notifyHint != nil:
					t.notifyHint(addedTexts)
				case t.notify != nil:
					t.notify()
				}
			}

			if !batch { // Single item: keep the original return value
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("hint added: %d (recorded as guidance for the planner's next round; it launches no work, changes no running intent and stops nothing - use add_intent to start work, kill_work to stop)", ids[0])), nil
			}
			out := map[string]any{"ids": ids, "note": "hints are guidance for the planner's next round; they launch no work and stop nothing"}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// killWorkTool lets the planner terminate a running work or cancel an intent
// that has not started yet, by intent id.
func (t *ToolSet) killWorkTool() actool.CoreTool {
	return t.writeExpTool("kill_work", "Stops one intent (work) of this task. A running work is terminated (marked stopped, not re-claimed); an intent that has not started (open/queued/paused) is cancelled through the same audited path the operator uses. Use this to halt off-track exploration or to retract work that a new hint now forbids. reason is required and recorded as the cancellation reason. Use get_worker_output first to see what a running work is doing before deciding.",
		obj(map[string]any{
			"intent_id": idp("Intent id to stop (= work handle)"),
			"reason":    str("Why this direction is being stopped; recorded on the intent so the cancellation is auditable"),
		}, "intent_id", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.killWork == nil {
				return actool.Errorf("kill_work is currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Reason   string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			reason := strings.TrimSpace(a.Reason)
			if reason == "" {
				return actool.Errorf("reason is required"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id must be an intent in this task (intents from related tasks are read-only)"), nil
			}
			if err := t.killWork(ctx, t.taskID, id, reason); err != nil {
				return actool.Errorf("stop NOT confirmed for intent " + strconv.FormatInt(id, 10) + ": " + err.Error()), nil
			}
			// killWork returns only after the worker settled, so the stored state is the proof.
			state := "unknown"
			if after, err := t.ts.GetNode(id); err == nil && after != nil {
				state = after.State
			}
			if state == "running" {
				return actool.Errorf(fmt.Sprintf("stop NOT confirmed: intent %d is still recorded as running", id)), nil
			}
			return actool.Text(fmt.Sprintf("Stopped intent %d: the worker has exited and the intent is now %q (reason recorded). Nothing of it is still running.", id, state)), nil
		})
}

// steerWorkTool lets the planner inject a mid-run course-correction into a running
// work WITHOUT killing it: the message reaches the worker before its next tool call,
// which re-plans its next step (already-gathered context is kept). For in-intent
// nudges ("stop doing X, focus on Y"); if the whole direction is wrong use kill_work + a new intent.
func (t *ToolSet) steerWorkTool() actool.CoreTool {
	return t.writeExpTool("steer_work", "Injects corrective instructions into a running intent (work) in real time without interrupting it or losing existing progress: the worker receives your instructions before its next action and adjusts accordingly. Use this for in-intent corrections such as 'stop going down X, focus on Y'; if the whole direction is wrong, use kill_work and then open a new intent. Consider first using get_worker_output to see what it is doing.",
		obj(map[string]any{
			"intent_id": idp("Intent id to correct (= work handle)"),
			"message":   str("Corrective instruction for the worker, stating clearly what to stop and what to switch to"),
		}, "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.steerWork == nil {
				return actool.Errorf("steer_work is currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Message  string          `json:"message"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			node, err := t.ts.GetNode(id)
			if err != nil || node == nil || node.Kind != db.KindIntent {
				return actool.Errorf("intent_id must be an intent in this task (intents from related tasks are read-only)"), nil
			}
			if strings.TrimSpace(a.Message) == "" {
				return actool.Errorf("message is required"), nil
			}
			if err := t.steerWork(id, a.Message); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("Queued a correction for the work of intent %d. It is NOT a stop and was not applied yet: the worker receives it before its next tool call. Use kill_work to actually stop the intent.", id)), nil
		})
}

// getWorkerOutput returns a work's final (or, up to the point of abort, its) conclusion text by intent id.
func (t *ToolSet) getWorkerOutput() actool.CoreTool {
	return t.readExpTool("get_worker_output", "Get the final output conclusion of an intent (work) in this task or a directly related task. Results from related tasks carry source_task_id/inherited=true and are read-only. A normally finished work returns its summary; a stopped or failed work returns its last output up to the point it was aborted.",
		obj(map[string]any{"intent_id": idp("Intent id (= work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			intentNode, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id is not owned by this task or its directly related tasks"), nil
			}
			acts, _, err := t.ts.ActivityPageWithSources(id, 1000)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var chosen, fallback *db.Activity
			for i := range acts {
				switch acts[i].Kind {
				case "result":
					chosen = &acts[i]
					fallback = &acts[i]
				case "text":
					fallback = &acts[i]
				}
			}
			pick := chosen
			if pick == nil {
				pick = fallback
			}
			if pick == nil {
				if intentNode.Inherited {
					return jsonResult(inheritedMap(map[string]any{
						"intent_id": id, "final_text": "(this work has no output yet)",
					}, intentNode.SourceTaskID))
				}
				return actool.Text("(this work has no output yet)"), nil
			}
			detail, _ := t.ts.ActivityDetailWithSources(pick.ID)
			if detail == "" {
				detail = pick.Summary
			}
			result := map[string]any{
				"intent_id": id, "final_text": detail,
				"summary": pick.Summary, "is_error": pick.IsError,
			}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// traceSteps renders summary-only trace rows, re-truncating each summary to 100
// chars — the stored summary is capped at 200 for the UI transcript; the trace
// tools want it tighter since a whole work's step list is many rows.
func traceSteps(acts []db.Activity) []map[string]any {
	steps := make([]map[string]any, 0, len(acts))
	for i := range acts {
		step := map[string]any{
			"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
			"is_error": acts[i].IsError, "summary": firstLine(acts[i].Summary, 100),
		}
		if acts[i].Inherited {
			inheritedMap(step, acts[i].SourceTaskID)
		}
		steps = append(steps, step)
	}
	return steps
}

// getWorkerTrace exposes a work's execution PROCESS (not just its final output):
// list step summaries, keyword-search within one work, or pull full detail of a
// few specific steps. Thinking steps are excluded everywhere.
func (t *ToolSet) getWorkerTrace() actool.CoreTool {
	return t.readExpTool("get_worker_trace",
		"View the execution process of an intent (work), as opposed to get_worker_output, which only gives the final conclusion. Three usages:\n"+
			"① Pass only intent_id → returns the summary stream of each step of the work (summary ≤100 chars, including step_id; only an outline of actions, without full output);\n"+
			"② intent_id + q → returns only summaries of steps matching the keyword (searches both summaries and full output; still only summary—use ③ to see content);\n"+
			"③ intent_id + step_ids → returns the full content (detail) of these steps; at most 5 per call—extra ids return only the first 5, and notice/omitted_step_ids lists the ones not fetched.\n"+
			"Typical flow: first locate suspicious step_ids with ① / ②, then use ③ to fetch their full output. Thinking steps are excluded. Historical traces of directly related tasks are supported; their results carry source_task_id/inherited=true and are read-only.",
		obj(map[string]any{
			"intent_id": idp("Intent id (= work handle)"),
			"q":         str("Keyword: returns only steps whose summary/full output match it (optional; mutually exclusive with step_ids)"),
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "step_id(s) whose full content to fetch (from ①/② results; at most 5 per call—extra ids return only the first 5, the rest are listed in omitted_step_ids)"},
			"limit":     intp("Maximum number of results for the summary stream/search (optional)"),
		}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage   `json:"intent_id"`
				Q        string            `json:"q"`
				StepIDs  []json.RawMessage `json:"step_ids"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			intentNode, nodeErr := t.ts.GetNodeWithSources(id)
			if nodeErr != nil {
				return actool.Errorf(nodeErr.Error()), nil
			}
			if intentNode == nil || intentNode.Kind != db.KindIntent {
				return actool.Errorf("intent_id is not owned by this task or its directly related tasks"), nil
			}
			// ③ detail drill-down by step ids, thinking excluded by the store.
			if len(a.StepIDs) > 0 {
				// Dedup + drop invalid ids first so garbage/duplicates don't eat into
				// the per-call cap. detail is returned in full (untruncated), so the
				// cap bounds one tool result; over the cap we serve the first N and
				// tell the model exactly which ids were deferred, instead of erroring
				// and forcing it to re-plan the call.
				const maxStepIDs = 5
				var ids []int64
				seen := make(map[int64]bool)
				for _, raw := range a.StepIDs {
					if v := pid(raw); v > 0 && !seen[v] {
						seen[v] = true
						ids = append(ids, v)
					}
				}
				var omitted []int64
				if len(ids) > maxStepIDs {
					omitted = append(omitted, ids[maxStepIDs:]...)
					ids = ids[:maxStepIDs]
				}
				acts, err := t.ts.ActivityByIDsWithSources(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(acts))
				for i := range acts {
					if acts[i].NodeID == nil || *acts[i].NodeID != id || acts[i].Inherited != intentNode.Inherited ||
						(acts[i].Inherited && acts[i].SourceTaskID != intentNode.SourceTaskID) {
						continue
					}
					step := map[string]any{
						"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
						"is_error": acts[i].IsError, "detail": acts[i].Detail,
					}
					if acts[i].Inherited {
						inheritedMap(step, acts[i].SourceTaskID)
					}
					steps = append(steps, step)
				}
				result := map[string]any{"intent_id": id, "steps": steps, "returned_step_ids": ids}
				if len(omitted) > 0 {
					// returned_step_ids/omitted_step_ids let the model decide programmatically
					// whether another call is worth it; the notice states the same in prose.
					result["omitted_step_ids"] = omitted
					result["notice"] = fmt.Sprintf(
						"Up to %d steps' full content can be fetched at once; this call returned the first %d (%v), and the %d omitted are %v. "+
							"If this content is enough to locate the issue, there is no need to fetch the remaining steps; if more is needed, call again with these step_ids.",
						maxStepIDs, len(ids), ids, len(omitted), omitted)
				}
				if intentNode.Inherited {
					inheritedMap(result, intentNode.SourceTaskID)
				}
				return jsonResult(result)
			}
			// ①/② summary stream, optionally keyword-filtered; 100-char summaries.
			var acts []db.Activity
			var err error
			if strings.TrimSpace(a.Q) != "" {
				acts, err = t.ts.ActivityTraceSearchWithSources(id, a.Q, a.Limit)
			} else {
				acts, err = t.ts.ActivityTraceWithSources(id, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			result := map[string]any{"intent_id": id, "steps": traceSteps(acts)}
			if intentNode.Inherited {
				inheritedMap(result, intentNode.SourceTaskID)
			}
			return jsonResult(result)
		})
}

// searchAllWorkerTraces keyword-searches EVERY work's process in this task — for
// finding what a worker saw but never wrote back as a fact. Returns only matching
// summaries (≤100 chars), each tagged with its intent_id for follow-up drill-down.
func (t *ToolSet) searchAllWorkerTraces() actool.CoreTool {
	return t.readExpTool("search_all_worker_traces",
		"[Not recommended in most cases, since the system already provides most of this information] Searches the execution traces of OTHER works in this task by keyword (q), to recover something a worker saw but did not record in a fact (a path, token, error, etc.). "+
			"Steps of your own intent are excluded automatically (they are already in your context). "+
			"Returns only summaries (summary ≤100 chars) of matching steps, each with intent_id; then use get_worker_trace(intent_id, step_ids=[...]) to fetch full content.",
		obj(map[string]any{
			"q":     str("Keyword (searched in the summaries and full output of all work steps)"),
			"limit": intp("Maximum number of results, default 100 (optional)"),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Q) == "" {
				return actool.Errorf("q is required"), nil
			}
			// Excludes the steps of the caller's own intent (the worker's own trace is already in its context).
			acts, err := t.ts.ActivityTraceSearchAllWithSources(t.ownerNode, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits := make([]map[string]any, 0, len(acts))
			for i := range acts {
				var intent int64
				if acts[i].NodeID != nil {
					intent = *acts[i].NodeID
				}
				hit := map[string]any{
					"intent_id": intent, "step_id": acts[i].ID, "worker": acts[i].Worker,
					"kind": acts[i].Kind, "tool": acts[i].Tool, "is_error": acts[i].IsError,
					"summary": firstLine(acts[i].Summary, 100),
				}
				if acts[i].Inherited {
					inheritedMap(hit, acts[i].SourceTaskID)
				}
				hits = append(hits, hit)
			}
			return jsonResult(map[string]any{"query": a.Q, "hits": hits})
		})
}

// listWorkerTraces gives a worker (which has no graph_overview and can't see the
// intent graph) a lightweight index of the works in this task — intent_id +
// one-line summary + state — so it can DISCOVER which works to inspect via
// get_worker_trace. Without this a worker only knows intent_ids that come back
// from search_all_worker_traces hits. Excludes still-open intents (not yet run →
// no process to inspect).
func (t *ToolSet) listWorkerTraces() actool.CoreTool {
	return t.readExpTool("list_worker_traces",
		"[Not recommended in most cases, since the system already provides most of this information] Lists the indexed works (intents) already run in this task: intent_id + one-line direction (summary) + status. "+
			"You (the worker) cannot see the exploration graph; use this to find which works are worth reviewing, then call get_worker_trace(intent_id) to see their steps and get_worker_trace(intent_id, step_ids=[...]) for details. "+
			"Lists only executed works (running/done/exhausted/blocked/stopped), not open works that have not run yet. Note: your task boundary is still the intent you were assigned; looking at other works is only to reuse observations and avoid duplicate work.",
		obj(map[string]any{
			"q":     str("Filter by summary keyword (optional)"),
			"limit": intp("Maximum number of results, default 50 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			all, err := t.ts.ListByKindWithSources(db.KindIntent, 500)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, limit)
			for _, n := range all {
				if n.Inherited && n.State == "running" {
					continue
				}
				switch n.State {
				case "running", "done", "exhausted", "blocked", "stopped": // has run → has a process
				default:
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				summary, _ := p["summary"].(string)
				if q != "" && !strings.Contains(strings.ToLower(summary), q) {
					continue
				}
				item := map[string]any{"intent_id": n.ID, "summary": summary, "state": n.State}
				if n.Inherited {
					inheritedMap(item, n.SourceTaskID)
				}
				out = append(out, item)
				if len(out) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{"works": out})
		})
}

const (
	// tcpProbeTimeout is the default dial timeout for tcp_probe. It is longer
	// than the egress proxy's CONNECT probe because the model asked for this
	// specific check and a filtered port is a real answer worth waiting for;
	// tcpProbeMaxTimeout bounds what a caller may request so one call cannot
	// outlive a worker's remaining budget by much.
	tcpProbeTimeout    = 5 * time.Second
	tcpProbeMaxTimeout = 30 * time.Second
)

// tcpProbe dials one host:port directly, so the answer is the target's.
//
// It deliberately bypasses the environment proxy the worker injects into every
// tool's environment (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) and the egress proxy:
// both answer CONNECT before the target is dialled, so a "port open" reading
// taken through them is the proxy's answer, not the host's. net.Dialer reads no
// proxy variables, so a direct dial is what this tool does by construction.
//
// The outcome is also recorded as target liveness: a failure marks the host
// unreachable in graph_overview until a later successful probe clears it, which
// is how the planner stops re-dispatching checks against a host already known
// to be dark.
//
// A direct dial is contact, so the task's network policy authorizes the
// destination first: a task with no authorized rule covering the host and port
// is refused instead of probed.
func (t *ToolSet) tcpProbe() actool.CoreTool {
	return writeTool("tcp_probe",
		"Check whether a TCP port on a host actually accepts a connection, by dialling it directly (no HTTP proxy). Use this instead of a proxied curl/nc for availability: a proxy answers CONNECT before it dials the target, so through it a dead host still looks open. Reports connected / refused / timed-out / dns-failure, and records the result as target liveness (a failure marks the host unreachable in graph_overview until a later successful probe clears it). A successful probe also records the port with provenance=probe on the host's IP asset.",
		obj(map[string]any{
			"host":            str("Hostname or IP address to dial"),
			"port":            intp("TCP port (1-65535)"),
			"timeout_seconds": intp("Dial timeout in seconds (default 5, max 30)"),
		}, "host", "port"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Host    string `json:"host"`
				Port    int    `json:"port"`
				Timeout int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			host := strings.TrimSpace(a.Host)
			if host == "" {
				return actool.Errorf("host is required"), nil
			}
			if a.Port < 1 || a.Port > 65535 {
				return actool.Errorf("port must be 1-65535"), nil
			}
			timeout := tcpProbeTimeout
			if a.Timeout > 0 {
				timeout = min(time.Duration(a.Timeout)*time.Second, tcpProbeMaxTimeout)
			}
			// A direct dial is contact with the target, so the task's network
			// policy decides it before the socket is opened: an unauthorized (or
			// unknown) destination is not probed, and its liveness is not written.
			// A name is resolved once and only the authorized addresses are dialled.
			addrs, dec, err := t.resolveAuthorizedDial(ctx, NetPolicyAuthorizer, host, a.Port)
			if err == nil && !dec.Allow {
				return actool.Errorf("tcp_probe refused: " + dec.Reason), nil
			}
			started := time.Now()
			// Try every authorized address before calling the host dark: one
			// dead A record among live ones is common, and the gateway's own dial
			// already tries them in order.
			used := net.IP(nil)
			if err == nil {
				var conn net.Conn
				for _, ip := range addrs {
					conn, err = (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(a.Port)))
					used = ip
					if err == nil {
						conn.Close()
						break
					}
					if ctx.Err() != nil {
						break
					}
				}
			}
			result := classifyDial(err)
			// Liveness is best-effort state, not a probe result: a write failure
			// must not turn a successful connection into a failed tool call. A
			// refusal is a reply, so the host is alive; only silence or a failed
			// lookup marks it unreachable.
			if t.as != nil {
				switch result {
				case "connected", "refused":
					_ = t.as.ClearUnreachable(host)
				default:
					_ = t.as.MarkUnreachable(host)
				}
				if result == "connected" && used != nil {
					_ = t.as.AppendIPPort(used.String(), a.Port, "", db.PortProvenanceProbe)
				}
			}
			out := map[string]any{
				"host": host, "port": a.Port, "result": result,
				"duration_ms": time.Since(started).Milliseconds(),
			}
			// Report the address that actually produced the outcome, not the
			// first of the set.
			if used != nil && used.String() != host {
				out["address"] = used.String()
			}
			if err != nil && result == "error" {
				out["detail"] = err.Error()
			}
			return jsonResult(out)
		})
}

const (
	// portScanWorkers bounds concurrent dials. It is a file-descriptor bound,
	// not a rate cap: the operator allows any scan size and speed.
	portScanWorkers        = 256
	portScanTimeout        = 1500 * time.Millisecond
	portScanMaxTimeout     = 10 * time.Second
	portScanPolicyInterval = 2 * time.Second
	maxCredibleOpenPorts   = 1000
)

// portScanTop is the "top" preset: common TCP services, one list and no others.
var portScanTop = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 113, 119, 123, 135, 137, 139, 143, 161, 179, 389, 443,
	445, 465, 500, 514, 515, 543, 544, 548, 554, 587, 593, 631, 636, 646, 873, 990, 993, 995, 1025, 1080,
	1194, 1433, 1434, 1521, 1701, 1720, 1723, 2049, 2082, 2083, 2086, 2087, 2121, 2181, 2375, 2376, 3000, 3128, 3306, 3389,
	3690, 4443, 4444, 4848, 5000, 5060, 5432, 5601, 5672, 5900, 5984, 5985, 5986, 6379, 6443, 6667, 7001, 7077, 8000, 8008,
	8080, 8081, 8082, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 50000,
}

// parsePorts expands "22,80,8000-8100" or "top" into ascending distinct ports.
func parsePorts(spec string) ([]int, error) {
	var seen [65536]bool
	add := func(p int) { seen[p] = true }
	if strings.TrimSpace(spec) == "top" {
		for _, p := range portScanTop {
			add(p)
		}
	} else {
		for _, part := range strings.Split(spec, ",") {
			lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
			a, err := strconv.Atoi(strings.TrimSpace(lo))
			b := a
			if err == nil && isRange {
				b, err = strconv.Atoi(strings.TrimSpace(hi))
			}
			if err != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("invalid port or range %q (want 1-65535, e.g. \"22,80,8000-8100\" or \"top\")", part)
			}
			for p := a; p <= b; p++ {
				add(p)
			}
		}
	}
	var out []int
	for p, ok := range seen {
		if ok {
			out = append(out, p)
		}
	}
	return out, nil
}

type portScanJob struct{ ai, pi int }

type portScanPolicy struct {
	src            netpolicy.Source
	session        netpolicy.Session
	exitConfigured func() bool
	revision       int64
	snapshot       atomic.Pointer[netpolicy.Store]
}

func (p *portScanPolicy) refresh(ctx context.Context) error {
	if p.exitConfigured == nil {
		return errors.New("operator exit configuration is unavailable")
	}
	if p.exitConfigured() {
		return errors.New("operator global proxy is configured")
	}
	if p.src == nil {
		return errors.New("no network-policy source is configured")
	}
	st, err := p.src.PolicyState(ctx, p.session)
	if err != nil {
		return fmt.Errorf("policy unavailable: %w", err)
	}
	// A new revision supersedes in-flight authorizations. Stop the scan
	// rather than letting a connection continue under the old grant.
	if p.snapshot.Load() != nil && st.Revision != p.revision {
		return errors.New("network policy changed during scan")
	}
	p.revision = st.Revision
	p.snapshot.Store(netpolicy.NewAuthorizer(snapshotSource{st}))
	return nil
}

// feed refreshes even while workers are busy or completing the last few dials.
func (p *portScanPolicy) feed(ctx context.Context, jobs chan<- portScanJob, done <-chan struct{}, targets, ports int) error {
	ticker := time.NewTicker(portScanPolicyInterval)
	defer ticker.Stop()
	defer func() {
		if jobs != nil {
			close(jobs)
		}
	}()
	var j portScanJob
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return nil
		case <-ticker.C:
			refresh, stop := context.WithTimeout(ctx, portScanPolicyInterval)
			err := p.refresh(refresh)
			stop()
			if err != nil {
				return err
			}
		case jobs <- j:
			j.pi++
			if j.pi == ports {
				j.pi = 0
				j.ai++
				if j.ai == targets {
					close(jobs)
					jobs = nil
				}
			}
		}
	}
}

type portScanTally struct {
	open   []int
	counts map[string]int
}

// recordPortScanTally renders one address's result and writes its per-address
// observations. The hostname's own liveness is the caller's job: it needs every
// address's outcome before deciding, or the last one scanned wins.
func (t *ToolSet) recordPortScanTally(addr string, tl *portScanTally) (map[string]any, bool) {
	replied := tl.counts["open"]+tl.counts["refused"] > 0
	result := map[string]any{"address": addr, "open": []int{}, "counts": tl.counts}
	open := tl.open
	if len(open) > maxCredibleOpenPorts {
		result["note"] = fmt.Sprintf("answers on %d ports, likely a middlebox", len(open))
		open = nil
	}
	if len(open) > 0 {
		sort.Ints(open)
		result["open"] = open
	}
	// Best-effort observations; a scan entirely refused by policy learned nothing.
	if t.as != nil {
		if len(open) > 0 {
			_ = t.as.SetIPOpenPorts(addr, open)
		}
		switch {
		case replied:
			_ = t.as.ClearUnreachable(addr)
		case tl.counts["timed_out"]+tl.counts["error"] > 0:
			_ = t.as.MarkUnreachable(addr)
		}
	}
	return result, replied
}

// portScan checks authorized TCP destinations from the backend independently of
// the subprocess VPN lane. Resolve once and authorize the exact dial addresses;
// portScanWorkers bounds descriptors, not request rate or port count.
func (t *ToolSet) portScan() actool.CoreTool {
	return writeTool("port_scan",
		"TCP connect port scan dialled from the backend, each destination authorized by the task's network policy. Use when the scoped subprocess VPN direct lane is unavailable (no live tun0). With the lane available, run_tool nmap supports SYN, TCP connect and UDP scans as uid 1000 with CAP_NET_RAW; raw Nmap commands need --privileged -Pn (the manifest supplies these flags), never sudo or root. Do not tunnel port scans through an HTTP proxy. host may be an IP or a hostname; ports is a comma list with ranges (\"22,80,8000-8100\", \"1-65535\") or \"top\" (about 100 common ports). A name resolving to several addresses scans the first and lists the rest as other_addresses; set all_addresses to scan every one. Reports open ports plus refused / timed_out / error / not_authorized counts, and records open ports (provenance=probe) and host liveness unless the replies likely came from a middlebox.",
		obj(map[string]any{
			"host":          str("IP address or hostname to scan"),
			"ports":         str("Ports to scan: comma list with ranges, e.g. \"22,80,8000-8100\" or \"1-65535\", or \"top\""),
			"timeout_ms":    intp("Per-port dial timeout in milliseconds (default 1500, max 10000)"),
			"all_addresses": map[string]any{"type": "boolean", "description": "When host resolves to several addresses, scan all of them instead of only the first (default false)"},
		}, "host", "ports"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Host         string `json:"host"`
				Ports        string `json:"ports"`
				TimeoutMS    int    `json:"timeout_ms"`
				AllAddresses bool   `json:"all_addresses"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			host := strings.TrimSpace(a.Host)
			if host == "" {
				return actool.Errorf("host is required"), nil
			}
			ports, err := parsePorts(a.Ports)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			timeout := portScanTimeout
			if a.TimeoutMS > 0 {
				timeout = min(time.Duration(a.TimeoutMS)*time.Millisecond, portScanMaxTimeout)
			}
			started := time.Now()
			if t.taskID <= 0 {
				return actool.Errorf("port_scan refused: no task context to check the destination against"), nil
			}
			policy := portScanPolicy{src: NetPolicySource, session: dialSession(t.taskID), exitConfigured: OperatorExitConfigured}
			if err := policy.refresh(ctx); err != nil {
				return actool.Errorf("port_scan refused: " + err.Error()), nil
			}
			// The pre-resolution check is port-aware (rules may list ports), so
			// take the first port the policy admits; each port is re-judged below.
			recorded := t.recordedDialAddrs(host)
			var resolved dialResolution
			var dec netpolicy.Decision
			for _, p := range ports {
				if resolved, dec, err = t.resolveDialHost(ctx, policy.snapshot.Load(), host, p, recorded); err != nil || dec.Allow {
					break
				}
			}
			if err != nil {
				return actool.Errorf("port_scan: cannot resolve " + host + ": " + err.Error()), nil
			}
			if !dec.Allow {
				return actool.Errorf("port_scan refused: " + dec.Reason), nil
			}
			// Resolution can outlast the snapshot's refresh cadence.
			if time.Since(started) >= portScanPolicyInterval {
				if err := policy.refresh(ctx); err != nil {
					return actool.Errorf("port_scan stopped: " + err.Error()), nil
				}
			}
			targets, others := resolved.addrs[:1], resolved.addrs[1:]
			if a.AllAddresses {
				targets, others = resolved.addrs, nil
			}

			tallies := make([]portScanTally, len(targets))
			for i := range tallies {
				tallies[i].counts = map[string]int{"open": 0, "refused": 0, "timed_out": 0, "error": 0, "not_authorized": 0}
			}
			scanCtx, cancelDials := context.WithCancel(ctx)
			defer cancelDials()
			jobs := make(chan portScanJob)
			var mu sync.Mutex
			var wg sync.WaitGroup
			dialer := &net.Dialer{Timeout: timeout}
			for range min(portScanWorkers, len(targets)*len(ports)) {
				wg.Go(func() {
					for j := range jobs {
						if scanCtx.Err() != nil {
							continue
						}
						port := ports[j.pi]
						kind := "not_authorized"
						if t.authorizeAddrs(scanCtx, policy.snapshot.Load(), host, port, resolved, j.ai).Allow {
							conn, err := dialer.DialContext(scanCtx, "tcp", net.JoinHostPort(targets[j.ai].String(), strconv.Itoa(port)))
							if err == nil {
								conn.Close()
							}
							switch classifyDial(err) {
							case "connected":
								kind = "open"
							case "refused":
								kind = "refused"
							case "timed-out":
								kind = "timed_out"
							default:
								kind = "error"
							}
						}
						mu.Lock()
						tallies[j.ai].counts[kind]++
						if kind == "open" {
							tallies[j.ai].open = append(tallies[j.ai].open, port)
						}
						mu.Unlock()
					}
				})
			}
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			err = policy.feed(scanCtx, jobs, done, len(targets), len(ports))
			cancelDials()
			<-done
			if err := ctx.Err(); err != nil {
				return actool.Errorf("port_scan cancelled: " + err.Error()), nil
			}
			if err != nil {
				return actool.Errorf("port_scan stopped: " + err.Error()), nil
			}

			results := make([]map[string]any, 0, len(targets))
			scanned := make([]string, 0, len(targets))
			silent := true
			for i, ip := range targets {
				addr := ip.String()
				scanned = append(scanned, addr)
				result, replied := t.recordPortScanTally(addr, &tallies[i])
				results = append(results, result)
				if replied {
					silent = false
				}
			}
			// The hostname is live if any scanned address replied; dark only when
			// every address was scanned and none did.
			if t.as != nil {
				switch {
				case !silent:
					_ = t.as.ClearUnreachable(host)
				case len(others) == 0:
					_ = t.as.MarkUnreachable(host)
				}
			}
			out := map[string]any{
				"host": host, "addresses_scanned": scanned, "ports_scanned": len(ports),
				"results": results, "duration_ms": time.Since(started).Milliseconds(),
			}
			if len(others) > 0 {
				ss := make([]string, len(others))
				for i, ip := range others {
					ss[i] = ip.String()
				}
				out["other_addresses"] = ss
				out["other_addresses_note"] = "these addresses may front the same service (load balancer / reverse proxy); set all_addresses to scan them"
			}
			if silent {
				out["note"] = "no reply: filtered or host down"
			}
			return jsonResult(out)
		})
}

// classifyDial names a dial outcome for the model. A refusal and a timeout are
// different facts (nothing listening vs. filtered or overloaded), and a DNS
// failure means the name never resolved, so they are reported apart rather than
// collapsed into one "unreachable".
func classifyDial(err error) string {
	if err == nil {
		return "connected"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns-failure"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timed-out"
	}
	return "error"
}

// PlannerTools is the read + intent-generation + goal-judgement tool set.
func (t *ToolSet) PlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		// cold-digest §6.1: restore folded cold nodes (digest body → members → detail).
		t.expandDigest(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.listGoals(), t.addIntent(), t.proveGoal(), t.goalMet(),
		t.killWorkTool(), t.steerWorkTool(),
		// report_finding: when assessing the situation during planning, if the caller has already confirmed a vulnerability itself, it may register it directly (same tool as the worker).
		t.addFinding(),
		// list_companies: view the company list + scope + asset count (to obtain company_id / understand the ownership scope).
		t.listCompanies(),
		// list_assets: During planning, search the entire asset library by DSL (paired with the "untested within scope" view of list_untested_assets,
		// adding the ability to query the whole library by conditions such as domain/fingerprint/port/status code).
		t.listAssets(),
		// add_company_scope: During planning, you can include domains/IP/CIDR/ICP/keywords in the asset scope of a company (automatically claiming matching assets).
		t.addCompanyScope(),
		// add_task_scope: actively bring a whole root domain, a whole company, a specific subdomain, or an IP into this task's test scope (the coverage denominator).
		t.addTaskScope(),
		// list_untested_assets: On demand, list untested assets within this task's scope (by type, with pagination), and decide on supplementary testing yourself.
		t.listUntestedAssets(),
		// recall / knowledge_add / reflect: the task's operational memory (planner
		// records the reflections it derives from the round's evidence).
		t.recallTool(), t.knowledgeAddTool(), t.reflectTool(),
	}
}

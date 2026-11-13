// Domain model — types used across the UI.
// Derived from the functional spec (section 7: key data shapes).

export type TaskStatus = "created" | "queued" | "running" | "paused" | "needs_operator" | "done" | "failed" | "timeout";
export type EngineMode = "exploring" | "paused" | "stalled" | "idle";

export interface Task {
  id: string;
  name?: string; // Optional task name; empty/missing = unnamed, falls back to the description when displayed.
  category_id?: number;
  category_name?: string;
  pinned?: boolean;
  pinned_at?: string | null;
  description: string;
  goal: string;
  status: TaskStatus;
  created_at: string;
  created_unix?: number; // created_at as unix seconds (run-duration calc)
  completed_at?: string; // RFC3339 finish time (done/failed); "" if unfinished
  completed_unix?: number; // completed_at as unix seconds (0/undef if unfinished)
  last_activity_unix?: number; // unix seconds of the last activity (0/undef if none)
  paused?: boolean;
  blocked_reason?: string; // Why the planner handed the task back (status needs_operator); "" otherwise
  queued?: boolean;
  active?: boolean;
  in_flight?: number;
  findings?: { critical: number; high: number; medium: number; low: number }; // Number of registered vulnerabilities (broken down by severity level).
  last_activity?: string;
  stalled?: boolean;
  goals_total?: number;
  goals_met?: number;
  engine_mode?: EngineMode;
  tokens?: TokenTotal; // whole-task token consumption
  llm_profile_id?: number; // LLM profile used; absent = default profile
  llm_profile_ids?: number[]; // ordered task-level failover chain
  active_llm_profile_id?: number; // profile used by the next LLM call
  llm_failover_state?: "default" | "ready" | "chain_exhausted" | string;
  llm_failover_reason?: string;
  source_task_ids?: string[]; // directly related tasks inherited as read-only context
  archive_blocked_by_task_id?: string; // live direct dependent that must be archived first
  company_ids?: number[]; // associated company scopes; current company assets join the task at creation
  coverage_enabled?: boolean; // Asset coverage feature switch (set at creation, enabled by default); false = coverage is not computed or displayed.
  plan_quiet_mode?: boolean; // Planner quiet mode (#86); default true
  llm_rotate?: boolean; // Worker chain-head rotation (#85); default false
  paused_at?: string | null;
}

export interface TaskCategory {
  id: number;
  name: string;
  task_count: number;
  created_at: string;
  updated_at: string;
}

export interface TaskTemplate {
  id: number;
  name: string;
  description: string;
  goal: string;
  category_id?: number | null; // Default category; null/omitted = none
  intercept_rules?: AssetInterceptRuleInput[]; // Preset task-level block/allow rules
  created_at: string;
  updated_at: string;
}

export interface DeleteTaskOptions {
  delete_assets: boolean;
  delete_traffic: boolean;
  delete_files: boolean;
  delete_findings: boolean;
  delete_llm_records: boolean;
}

export interface DeleteTaskResult {
  deleted: string;
  assets_deleted: number;
  assets_detached: number;
  traffic_deleted: number;
  files_deleted: boolean;
  findings_deleted: number;
  llm_records_deleted: number;
  cleanup_warning?: string;
}

export type TaskArchiveState =
  | "archive_queued"
  | "archiving"
  | "archive_failed"
  | "ready"
  | "restore_queued"
  | "restoring"
  | "restore_failed"
  | "delete_queued"
  | "deleting"
  | "delete_failed";

export interface TaskArchiveTokenStats {
  calls?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface TaskArchive {
  id: number;
  task_id: number;
  state: TaskArchiveState;
  phase: string;
  progress: number;
  error?: string;
  warnings?: string[];
  format_version: number;
  sha256?: string;
  original_size: number;
  compressed_size: number;
  task_name: string;
  task_description: string;
  task_goal: string;
  original_status: TaskStatus;
  category_id?: number;
  category_name?: string;
  source_task_ids: number[];
  remaining_timeout_seconds: number;
  data_counts: Record<string, number>;
  aggregate_stats: {
    tokens?: TaskArchiveTokenStats;
    skills?: Record<string, number>;
    tools?: Record<string, number>;
    findings?: Record<string, number>;
  };
  archived_at?: string;
  requested_at: string;
  created_at: string;
  updated_at: string;
}

export interface TaskArchivePage {
  items: TaskArchive[];
  total: number;
  page: number;
  size: number;
}

export interface ArchiveBatchItem {
  id: string;
  archive_id?: number;
  ok: boolean;
  queued: boolean;
  error?: string;
  // "evidence": the archive gate refused this task because a finding still has
  // no bound traffic. The batch route answers 202, so this field, not the error
  // text, is what the retry-with-force path keys on.
  gate?: "evidence";
}

// ---- Asset graph (global, shared across tasks) ----
export type AssetType =
  | "company"
  | "domain"
  | "ip"
  | "port"
  | "service"
  | "site"
  | "endpoint"
  | "parameter"
  | "tech"
  | "credential"
  | "data";

export type NodeState = "observed" | "confirmed" | "tombstoned";

export interface AssetNode {
  id: string;
  type: AssetType;
  name: string;
  key: string; // nkey
  value?: string;
  company_id?: string; // ID of the company the asset belongs to; empty = unassigned
  state: NodeState;
  confidence: number; // 0..1
  attrs?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export type AssetRel =
  | "owns"
  | "resolves"
  | "exposes"
  | "runs"
  | "serves"
  | "has_endpoint"
  | "has_param"
  | "fingerprinted"
  | "authenticates_as"
  | "reachable"
  | "has_subdomain";

export interface Edge {
  src: string;
  dst: string;
  rel: AssetRel | ExploreRel;
}

// Task asset view — server-side enriched, paginated.
export interface TaskAssetRef {
  id: string;
  name?: string;
  key: string;
  attrs?: Record<string, unknown>;
}

export interface TaskAssetItem extends AssetNode {
  techs?: TaskAssetRef[];
  auth?: TaskAssetRef[];
  params?: TaskAssetRef[];
}

export interface TaskAssetView {
  counts: Record<string, number>;
  total: number;
  items: TaskAssetItem[];
}

// ---- New unified asset model (new backend) ----
export type NewAssetType = "root_domain" | "ip" | "subdomain" | "app" | "service" | "endpoint";

export interface Asset {
  id: number;
  type: NewAssetType;
  company_id?: number;
  task_ids: number[];
  domain?: string;
  root_domain?: string;
  ip?: string;
  c_segment?: string;
  port?: number;
  icp?: string;
  bound_domains?: string[];
  open_ports?: { port: number; service?: string }[];
  record_type?: string;
  record_value?: string[] | string;
  bundle_id?: string;
  app_name?: string;
  category?: string;
  app_description?: string;
  app_icp?: string;
  url?: string;
  service_type?: string;
  service_name?: string;
  favicon_mmh3?: string;
  status_code?: number;
  content_length?: number;
  page_title?: string;
  technologies?: string[];
  auth?: Record<string, unknown>[];
  method?: string;
  params?: Record<string, unknown>[];
  extra?: Record<string, unknown>;
  last_seen: string;
  task_source?: string;
  task_source_summary?: string;
  task_source_node_id?: number;
}

export interface IntentAsset {
  intent_id: number | string;
  asset_id: number;
  type: NewAssetType;
  label: string;
  source: string;
  source_summary: string;
  source_node_id?: number;
  source_task_id: number;
  inherited: boolean;
}

export interface TaskAssetScopeMutation {
  requested: number;
  assets_linked: number;
  assets_existing: number;
  scopes_added: number;
  scopes_existing: number;
}

// ---- Asset coverage graph (per task) ----
// One node of the force-directed "asset coverage graph". The key is unique: assets = "a:<id>", companies = "c:<id>",
// root domain without an asset row = "r:<domain>". Nodes with in_scope=false are grey context nodes used only for drawing edges.
export interface CoverageGraphNode {
  key: string;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";
  label: string;
  tested: boolean;
  in_scope: boolean;
  asset_id?: number;
  company_id?: number;
  domain?: string;
  root_domain?: string;
  ip?: string;
  url?: string;
  port?: number;
  service_type?: string;
  app_name?: string;
  page_title?: string;
  status_code?: number;
}

export interface CoverageGraphEdge {
  src: string;
  dst: string;
}

export interface CoverageGraphData {
  nodes: CoverageGraphNode[];
  edges: CoverageGraphEdge[];
}

// Intents, facts, and findings linked to an asset in this task's exploration graph (for the coverage graph node drawer).
export interface CoverageAssetRef {
  id: number;
  kind: string;
  state: string;
  summary: string;
  source_task_id?: string;
  inherited?: boolean;
}
export interface CoverageAssetRefs {
  intents: CoverageAssetRef[];
  facts: CoverageAssetRef[];
  findings: CoverageAssetRef[];
}

// ---- Workspace file manager (workDir) ----
export interface WorkspaceEntry {
  name: string;
  path: string; // workspace-relative, forward slashes
  dir: boolean;
  size: number;
  mtime: number; // unix millis
}
export interface WorkspaceListing {
  path: string;
  entries: WorkspaceEntry[];
}
export interface WorkspaceFile {
  path: string;
  size: number;
  binary: boolean;
  too_large?: boolean;
  content?: string;
}

// One entry in the task's test scope (the coverage denominator and the authorization boundary).
export interface TaskScopeRow {
  id: number;
  task_id: number;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "cidr" | "icp" | "keyword";
  company_id?: number;
  company_name?: string; // Resolved by a backend JOIN on companies; only has a value when kind=company
  domain?: string;
  net?: string;
  value?: string;
  source: "auto" | "agent" | "manual";
  reason?: string;
}

export type CompanyScopeKind = "domain" | "ip" | "cidr" | "icp" | "keyword";

// Structured asset scope rules submitted when a new company is added.
export interface CompanyScopeRule {
  kind: CompanyScopeKind;
  value: string;
}

// The result of writing the asset scope. errors are the rows in this submission that are invalid; warnings are existing data issues that are unrelated to this submission
// but would make the ownership result differ from expectations, such as an asset whose ip field stores a hostname.
export interface CompanyScopeMutation {
  added: number;
  skipped: number;
  invalid: number;
  errors?: string[];
  warnings?: string[];
}

// One rule of the company asset scope rules (the single source of truth for ownership).
export interface ScopeRow {
  id: number;
  company_id: number;
  kind: CompanyScopeKind;
  domain?: string; // Has a value when kind=domain
  net?: string; // Has a value when kind=ip|cidr
  value?: string; // May be returned directly by the backend when kind=icp|keyword
  raw: string; // The raw user input, used for display and for backfilling the form
  reason?: string;
}

// Company: the asset node with type=company, plus the icon, asset count, and asset scope rules.
export interface Company {
  id: number;
  name: string;
  logo?: string; // Remote icon URL; if empty, the frontend falls back to the first letter of the name
  asset_count: number;
  scope?: ScopeRow[];
}

// ---- Exploration graph (per task) ----
export type ExploreKind = "task" | "begin" | "goal" | "intent" | "fact" | "finding" | "hint" | "digest";
export type GoalState = "open" | "met" | "abandoned";
export type IntentState = "open" | "running" | "paused" | "done" | "blocked" | "exhausted" | "stopped";
export type FindingState = "confirmed" | "dismissed";
export type HintState = "active" | "consumed";
export type ExploreRel = "spawns" | "derived_from" | "yields" | "proves" | "covers";

export interface TaskNode {
  id: string;
  type: ExploreKind;
  payload?: string;
  priority: number; // 0..10
  state: string; // GoalState | IntentState | FindingState | HintState
  origin: string;
  ts: string;
  source_task_id?: string;
  inherited?: boolean;
  delete_reason?: string; // Reason for the deletion when the intent is soft-deleted (state='deleted')
}

// One page of the broadcast board: nodes paginated in creation order, plus the edges involved in this page, plus the nodes at the other end of those edges (refs, indexed by id),
// so that every broadcast can explain "where it came from and what it produced" without pulling the entire graph.
export interface ExplorationNodePage {
  items: TaskNode[];
  total: number;
  page: number;
  size: number;
  edges: Edge[];
  refs: Record<string, TaskNode>;
  // Node id → assets anchored to that node (shown alongside when the broadcast board is expanded; includes nodes on this page and their neighbors).
  assets: Record<string, FindingAsset[]>;
}

export interface ExplorationNodeQuery {
  page?: number;
  size?: number;
  kinds?: ExploreKind[];
  states?: string[];
  q?: string;
  order?: "asc" | "desc";
}

// Targets used by the target management card (the backend has already split the payload into text/vulnclass).
export interface TaskGoal {
  id: string;
  text: string;
  vulnclass?: string;
  state: string; // GoalState
  origin?: string;
  ts: string;
}

// Operation constraints used by the constraint management card (allow = permitted / deny = forbidden).
export type ConstraintKind = "allow" | "deny";
export interface TaskConstraint {
  id: string;
  kind: ConstraintKind;
  text: string;
  origin?: string;
  ts?: string;
}

// ---- Findings ----
export type Severity = "critical" | "high" | "medium" | "low";

// Finding disposition status: pending / in progress / confirmed / handled / fixed / false positive / ignored / duplicate / risk accepted.
export type FindingStatus =
  | "pending"
  | "in_progress"
  | "confirmed"
  | "resolved"
  | "fixed"
  | "false_positive"
  | "ignored"
  | "duplicate"
  | "risk_accepted";

// FindingAsset is an asset bound to a finding (the label is already pre-rendered by the backend).
export interface FindingAsset {
  id: string;
  type: string;
  label: string;
}

export interface Finding {
  traffic_count?: number;
  evidence_version?: number;
  report_evidence_version?: number;
  report_stale?: boolean;
  id: string;
  finding_id?: string; // Row id in the standalone findings table; the handle for status updates (older nodes within a task may be missing it)
  vulnclass: string;
  name?: string; // Vulnerability name; when empty, display falls back to vulnclass
  severity: Severity;
  status: FindingStatus;
  summary: string;
  evidence: string;
  report?: string; // Detailed report (Markdown); returned only by the detail endpoint, empty in list responses
  intent_id?: string;
  param_id?: string;
  task_id?: string;
  task_description?: string;
  source_task_id?: string;
  inherited?: boolean;
  assets?: FindingAsset[];
  ts: string;
}

// FindingsPage is the server-side paginated response for the findings list.
export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingGroup {
  task_id: string | number | null;
  task_name?: string; // Optional task name; empty or omitted means unnamed
  task_description: string;
  task_status: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingGroupsPage {
  items: FindingGroup[];
  total: number;
  finding_total: number;
  page: number;
  page_size: number;
}

export interface FindingDeepenResponse {
  task_id: string;
  intent_id: string;
  state: IntentState;
  queued: boolean;
}

// FindingStats is the aggregate over the entire findings table (stat cards and the vulnerability-type dropdown), computed server-side and unaffected by pagination.
export interface FindingStats {
  total: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  vulnclasses: string[];
  tasks: FindingTaskOption[];
}

// FindingTaskOption is one entry in the findings page's "by task" filter dropdown: a task that has findings (an empty description means the task has been deleted,
// and the frontend falls back to displaying the id) along with its finding count.
export interface FindingTaskOption {
  id: string | number;
  name?: string; // Optional task name; empty or omitted means unnamed
  description: string;
  count: number;
}

// FindingQuery holds the pagination, filter, and sort parameters for the findings list.
export interface FindingQuery {
  page: number;
  pageSize: number;
  severity?: "all" | Severity;
  status?: "all" | FindingStatus;
  vulnclass?: string;
  task?: string; // Task id; "all" or empty = do not filter by task
  query?: string;
  sort?: "severity" | "time";
  // Asset tree node key; selecting a node = selecting its entire subtree. Empty = do not filter by asset.
  assetScope?: string;
}

// ---- Findings by asset (asset view) ----
export type FindingAssetKind = "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint" | "none";

// FindingAssetNode is a node in the asset tree. The key takes the form a:<id> (asset), c:<id> (enterprise),
// r:<domain> (root domain with no asset row in the database), __none__ (not linked to any asset).
export interface FindingAssetNode {
  key: string;
  parent?: string;
  kind: FindingAssetKind;
  label: string;
  asset_id?: number;
  company_id?: number;
  self: number; // Number of findings attached directly to this asset
  total: number; // Including descendants, deduplicated by finding
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingAssetTree {
  nodes: FindingAssetNode[];
  finding_total: number;
  truncated: boolean;
  dropped_kinds?: string[];
}

// ---- Activity / sessions ----
export type ActivityKind =
  | "tool_use"
  | "tool_result"
  | "text"
  | "thinking"
  | "result"
  | "user"
  | "intent" // LLM-generated exploration objective leading a worker session (UI-synthesized)
  | "round" // planner round boundary marker (engine-emitted)
  | "usage" // live cumulative token usage (per model turn); not rendered
  | "llm_switch" // automatic/manual task-level LLM switch
  | "llm_failover" // task-level provider switch / chain exhaustion audit event
  | "intercept_request"; // user-approval request from the intercept layer

// ChatAttachment is a single uploaded file: path is relative to the session/task working directory (i.e., the agent's CWD).
export interface ChatAttachment {
  name: string;
  path: string;
  size: number;
  abs?: string; // Absolute path (returned when uploading to staging with scope=staging; write it into the task description before creating the task)
}

export interface Activity {
  seq: number;
  intent_id?: string;
  worker: string; // session owner: planner | mainagent | work#1 ...
  ts: string;
  kind: ActivityKind;
  tool?: string;
  tool_use_id?: string;
  is_error?: boolean;
  summary: string;
  detail?: string;
  metadata?: {
    llm_transition?: LLMTransition;
  };
  source_task_id?: string;
  inherited?: boolean;
  main_seg?: number; // main-agent conversation segment (present only on worker="mainagent" rows)
  // token usage (present only on kind='result')
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface LLMAuditProfile {
  id: number;
  name: string;
  format: string;
  model: string;
}

export interface LLMTransition {
  mode: "automatic" | "manual" | "exhausted";
  reason: string;
  previous?: LLMAuditProfile;
  next?: LLMAuditProfile;
}

export interface TaskLLMResolution {
  profile_id?: number;
  name: string;
  format: string;
  model: string;
  source: "task_chain" | "agent_binding" | "global_profile" | "environment" | "global";
  available: boolean;
  reason?: string;
}

export interface TaskLLMResolutions {
  mainagent: TaskLLMResolution;
  planner: TaskLLMResolution;
  worker: TaskLLMResolution;
}

// ---- Agent triggers (P3 scheduling, custom agents only) ----
export interface AgentTrigger {
  id: number;
  agent_key: string;
  enabled: boolean;
  interval_sec: number; // Periodic: every N seconds (0 = no periodic trigger)
  on_finding: boolean; // Fires when any task discovers a finding
  on_goal_met: boolean; // Fires when any task reaches its goal
  on_task_timeout: boolean; // Fires when any task times out
  on_tool_call: boolean; // Fires when the selected tool is invoked (execution completed)
  on_task_create: boolean; // Triggered when any task is created
  interval_message: string; // Independent user messages for each trigger condition
  finding_message: string;
  goal_message: string;
  task_timeout_message: string;
  tool_call_message: string;
  task_create_message: string;
  tool_names: string[]; // on_tool_call: tool key(s) selected (at least one)
  last_fire?: string;
}

// ---- Conversations (chat page) ----
export interface ActiveFindingRetest {
  id: number;
  finding_id: string;
  conversation_id: number;
  status: "pending" | "running";
}

export interface FindingRetest {
  id: number;
  finding_id: number;
  conversation_id: number | null;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
  notes: string;
  summary: string;
  evidence: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Conversation {
  id: number;
  running?: boolean; // live server state, returned with the conversation list
  agent_key: string;
  title: string;
  // Set when the thread is bound to one task (the plan drafter): its tools take
  // the task from the binding rather than from the model.
  task_id?: number;
  llm_profile_id?: number;
  pinned?: boolean;
  pinned_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---- Backend logs (/logs page) ----
export interface LogLine {
  seq: number;
  db_id?: number; // server_logs.id; present for DB-persisted lines
  ts: string;
  level: "info" | "warn" | "error";
  tag: string;
  text: string;
}

export type SessionRole = "mainagent" | "planner" | "worker" | "system";
export type SessionStatus = "running" | "paused" | "done" | "blocked" | "exhausted" | "pending" | "stopped" | "deleted";

// Per-worker token usage (GET /api/exploration/tokens).
export interface TokenUsage {
  worker: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface SessionTokenUsage {
  session: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface BatchControlItem {
  id: string;
  ok: boolean;
  status?: string;
  queued?: boolean;
  error?: string;
}

// Per-task results of the batch category change. Failure can only occur if the task has already been deleted; the category write itself is atomic.
export interface BatchCategoryItem {
  id: string;
  ok: boolean;
  error?: string;
}

// Whole-task (all agents) token aggregate.
export interface TokenTotal {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Global per-profile token spend from the llm_usage ledger (GET /api/tokens/usage).
export interface ProfileUsage {
  profile_name: string;
  calls: number;
  tasks: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  // EUR cost from the profile's stored prices; absent when the profile has no price set.
  cost_eur?: number | null;
}

// One (profile, UTC day) token bucket for the dashboard's daily chart (new source).
export interface ProfileDayUsage {
  profile_name: string;
  date: string; // YYYY-MM-DD
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
}

// Response of GET /api/tokens/usage — the dashboard's "new" (llm_usage) token view.
export interface UsageStats {
  by_profile: ProfileUsage[];
  daily: ProfileDayUsage[];
}

// Per-model token usage for one task (GET /api/llm/records/by-model), from the
// always-on llm_usage metering ledger. calls = number of LLM calls on this model.
export interface ModelTokenStat {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface Session {
  id: string;
  role: SessionRole;
  title: string;
  status: SessionStatus;
  live: boolean;
  last_activity: string;
  intent_id?: string;
  source_task_id?: string;
  inherited?: boolean;
  seg?: number; // main-agent session: which conversation segment (0 = original)
}

// ---- Traffic ----
export interface TrafficExchange {
  id: string;
  ts: string;
  host: string;
  method: string;
  url: string;
  status: number;
  content_type: string;
  resp_len: number;
}

export interface TrafficResp {
  enabled: boolean;
  proxy?: string;
  count?: number; // global total (unfiltered)
  total?: number; // rows matching the current filter (for pagination)
  page?: number;
  size?: number;
  exchanges?: TrafficExchange[];
}

// Full raw request/response of one exchange (lazy-loaded on row select).
export interface TrafficDetail {
  req: string;
  resp: string;
}

// One distinct recorded host with its exchange count (target picker).
export interface TrafficHost {
  host: string;
  count: number;
}

// ---- App settings (runtime toggles) ----
export interface Settings {
  traffic_capture: boolean;
  agent_traffic_binding: boolean; // Automatically binds traffic evidence for the Agent; disabled by default. Does not affect manual binding.
  llm_record: boolean; // LLM recording switch (off by default); when off, no LLM calls are recorded.
  // Web search. brave_key_set / tavily_key_set reflect whether a key is stored
  // (the values are never returned). On PUT, send the corresponding field to set/clear.
  web_search_enabled: boolean;
  web_search_backend: string; // "ddgs" | "brave-free" | "tavily" | "deepseek"
  brave_key_set: boolean;
  tavily_key_set: boolean;
  // write-only: only sent on PUT to store/clear the key.
  brave_search_api_key?: string;
  tavily_search_api_key?: string;
  // Standalone egress proxy (http/https/socks5) used to access search endpoints; unrelated to the MITM proxy that records traffic. Empty = direct connection.
  web_search_proxy?: string;
  // Global egress proxy (http/https/socks5, may include user:pass); all target traffic goes through it. When traffic capture is enabled, it serves as the
  // MITM upstream; when capture is off, inject the agent's bash/WebFetch directly. Empty = direct connection.
  global_proxy?: string;
  python_interpreter?: string; // Python interpreter path for custom script tools (empty = detect at runtime)
  workers?: number; // Number of concurrent worker agents (default 3); applies to tasks started afterward
  // Task concurrency limit: maximum number of tasks running at the same time. Off = unlimited; when on, newly created tasks are queued if the limit is exceeded and start automatically when a slot frees up.
  task_concurrency_enabled?: boolean; // Default false
  task_concurrency_limit?: number; // Default 5 when enabled
  // LLM polling (failover). Off by default; when enabled, agents that do not specify a model are unavailable under the current configuration
  // (insufficient balance / invalid key / rate limiting / service error).
  llm_pool_enabled?: boolean; // Default false
  // Whether an agent/task bound to a specified config falls back to the round-robin chain when it fails. Default false = a binding is exclusive.
  llm_pool_bind_fallback?: boolean;
  llm_refusal_fallback_enabled?: boolean; // default false
  // Scope for injecting operation constraints (all enabled by default): append the task's allow/deny constraints to the system prompt of the corresponding agent.
  constraints_inject_planner?: boolean;
  constraints_inject_worker?: boolean;
  // Experimental: noa model-driven context compression (off by default). When enabled, the four agent types integrated by the platform (planner/
  // worker/main agent/conversation) has noa take over context compaction, replacing the built-in compaction; read once per run, for
  // Takes effect for the run started after this.
  noa_compaction?: boolean;
  // ---- Vulnerability IM push (channels are independent resources, see /api/notify/*; here are only the three global settings) ----
  notify_enabled?: boolean; // Master push switch, on by default; allows push notifications to be stopped with one action during maintenance
  notify_public_base_url?: string; // External access address for the link back to vulnerability details; empty = messages carry no link back
  notify_digest_interval_min?: number; // Digest mode period (minutes), default 30
}

// ---- Vulnerability IM push ----

// NotificationFilter is a channel's filter criteria; all fields are optional, and omitting them means no filtering.
// The backend performs no validation on any field: a malformed configuration is treated as a match (better to over-push than to miss a push).
export interface NotificationFilter {
  min_severity?: string; // "" | low | medium | high | critical
  task_ids?: number[]; // Empty = no restriction; if non-empty, require an intersection with the task the vulnerability belongs to
  asset_ids?: number[]; // Empty = no restriction; if non-empty, require an intersection with the asset the vulnerability is anchored to
  vulnclass_include?: string[]; // Empty = accept all; if non-empty, require the vulnerability type to match any keyword (case-insensitive substring)
  vulnclass_exclude?: string[]; // Matching any keyword excludes the item (exclusion takes precedence over inclusion)
  on_status_change?: boolean; // Whether to also receive vulnerability disposition status change events
}

// NotificationChannel is a channel instance. The fields of config vary by kind,
// and credential fields are replaced with masked values starting with "__masked__" when read; sending the value back unchanged means "do not change".
export interface NotificationChannel {
  id: number;
  name: string;
  kind: string;
  enabled: boolean;
  mode: "realtime" | "digest";
  config: Record<string, unknown>;
  filter: NotificationFilter;
  rate_per_min: number;
  created_at: string;
  updated_at: string;
  // secret_keys is provided by the backend per channel type; the frontend uses it to render password inputs and the "leave blank to keep unchanged" hint,
  // Hardcodes no channel-specific knowledge.
  secret_keys: string[];
}

// NotificationKind is the channel type metadata returned by /api/notify/meta.
export interface NotificationKind {
  kind: string;
  default_rate_per_min: number;
  secret_keys: string[];
}

export interface NotificationMeta {
  kinds: NotificationKind[];
  enabled: boolean;
  public_base_url: string;
  digest_interval_min: string;
  defaults: { digest_interval_min: number };
  stats: {
    channels: number;
    channels_on: number;
    pending: number;
    failed: number;
    sent_today: number;
    backlog_age_ms: number;
  };
}

// NotificationDelivery is a single delivery record, used for delivery history and failed-delivery retries.
export interface NotificationDelivery {
  id: number;
  finding_id: string;
  event_kind: string; // finding_created | finding_status_changed
  channel_id: number;
  channel_name: string;
  channel_kind: string;
  state: "pending" | "sending" | "sent" | "failed" | "skipped";
  attempts: number;
  last_error: string;
  batch_id?: number;
  created_at: string;
  sent_at?: string;
  next_attempt_at: string;
  title: string;
  severity: string;
}

// ---- LLM config ----
export type LLMAuthMethod = "api_key" | "claude_code" | "codex" | "antigravity";

// One /llm/models entry. supported_efforts exists only for SDK catalog models: [] = no reasoning effort; absent = unknown, full list kept.
export interface LLMModelInfo {
  id: string;
  supported_efforts?: string[];
}

export interface LLMRefusalFallbackStep {
  model: string;
  reasoning_effort: string;
}

export interface LLMProfile {
  id: string;
  name: string;
  format: "openai" | "anthropic" | "openai-responses" | "antigravity" | "ollama";
  auth_method: LLMAuthMethod;
  has_grant: boolean;
  grant_email?: string;
  grant_expiry?: string;
  // Set when the SDK is unavailable for subscription login; the profile drawer shows it.
  oauth_error?: string;
  base_url?: string;
  proxy?: string;
  model: string;
  api_key_hint?: string;
  price_input_per_m?: number;
  price_output_per_m?: number;
  price_cache_read_per_m?: number;
  price_cache_write_per_m?: number;
  rate_per_second: number;
  rate_per_minute: number;
  context_window_k?: number;
  // Thinking toggle (thinking.type): ""=not sent (default) | "disabled"=off | "enabled"=on | "adaptive"=adaptive
  thinking_type?: string;
  // Thinking intensity: "" = do not send (default) | "low"/"medium"/"high"/"xhigh"/"max"
  reasoning_effort?: string;
  is_default: boolean;
  // Polling priority: the higher the value, the earlier it is selected. The active configuration always stays at the head of the chain, regardless of this value.
  priority?: number;
  // true = not used as a failover target (can still be explicitly bound for use by an agent/task).
  pool_exclude?: boolean;
  // true (default) = streaming (SSE) | false = true non-streaming (stream:false, returns the full response at once).
  streaming?: boolean;
  // Output token cap for a single reply. 0 = do not send this field; the server-side default applies.
  // Note: distinguish this from context_window_k. The latter is the model's total capacity and is used only locally, for the compaction threshold.
  max_tokens?: number;
  // Which request field name to use for the token cap. Only meaningful when format="openai":
  // "" = max_tokens (default) | "max_completion_tokens" (OpenAI reasoning models only accept this one)
  max_tokens_field?: string;
  // Custom session header name: when non-empty, every request carries this HTTP header, with the value set to the current session/intent id.
  // "" = do not send. Used for gateways that do prompt caching or sticky routing based on the session-id header.
  session_header_key?: string;
  // This config's overrides for retries (connection establishment / empty response / same-provider safety window). Leaving blank or all 0 = follow the global policy.
  retry?: LLMRetryOverride;
  // Ordered refusal fallback models on this profile before advancing the task failover chain.
  refusal_fallback?: LLMRefusalFallbackStep[];
}

// ---- LLM retry policy ----
// Two knobs for one retry layer. For both, 0 = not configured:
//   attempts    0=use the default count | -1=disable retries for this layer | >0=number of retries
//   interval_ms 0=use the default exponential backoff | >0=use this fixed interval in milliseconds instead
export interface LLMRetryRule {
  attempts: number;
  interval_ms: number;
}

// The three layers a single LLM config can override (all of them retry along with the endpoint).
export interface LLMRetryOverride {
  connect: LLMRetryRule; // Connection-establishment retries: connection reset / timeout / 429 / 5xx, before the stream starts
  empty: LLMRetryRule; // Empty-response retry: completed but with no content at all (openai format only)
  stream: LLMRetryRule; // Within the same provider safety window: replay the stream after a mid-stream disconnect, as long as no output has been delivered yet
}

// Global policy = the defaults for the three layers above + two layers that exist only globally:
//   breaker polling circuit breaker (attempts=number of consecutive transient failures before tripping, interval_ms=fixed cooldown duration)
//   intent  Re-run the whole intent after the worker ends with model_error (the entire intent is re-run)
export interface LLMRetryPolicy extends LLMRetryOverride {
  breaker: LLMRetryRule;
  intent: LLMRetryRule;
}

// ---- LLM polling (failover) ----
// A configuration's position in the polling chain and its health status. state:
//   ok       Normal
//   degraded Has consecutive failures but has not reached the circuit-breaker threshold
//   tripped  Circuit breaker open; skipped during the cooldown period (cooldown_secs is the remaining seconds)
export interface LLMPoolMember {
  profile_id: string;
  name: string;
  model: string;
  format: string;
  priority: number;
  active: boolean; // Whether this is the currently active configuration (always the head of the chain)
  excluded: boolean; // pool_exclude: does not participate in polling
  state: "ok" | "degraded" | "tripped";
  fails: number;
  trips: number;
  cooldown_secs: number;
  last_error?: string;
  last_at?: string;
}

export interface LLMPoolStatus {
  enabled: boolean;
  bind_fallback: boolean;
  chain: LLMPoolMember[];
}

// ---- LLM subscription usage ----
export interface LLMUsageWindow {
  id: "five_hour" | "seven_day" | string;
  label: string;
  used_fraction: number; // 0..1
  remaining_fraction: number; // 0..1
  resets_at: string | null; // RFC 3339
}

export interface LLMProfileUsage {
  profile_id: string;
  name: string;
  auth_method: string;
  connected: boolean;
  plan: string | null;
  fetched_at: string | null; // RFC 3339
  stale: boolean;
  windows: LLMUsageWindow[];
  error?: string;
}

export interface LLMUsageResponse {
  profiles: LLMProfileUsage[];
}

// ---- Agents ----
export interface Agent {
  id: string;
  key: string; // Built-in: goals/planner/mainagent/worker; custom: user-defined key
  name: string;
  description?: string;
  role: string;
  builtin: boolean;
  enabled: boolean;
  llm_profile_id?: number | null; // Bound LLM configuration; null/absent = follow task/session/global
  max_turns?: number; // 0 = unlimited
  run_seconds?: number; // Wall-clock limit for a single worker run (seconds); 0 = unlimited
  web_search?: boolean; // Whether web search is enabled (gated by the system-wide global switch)
  interactive_shell?: boolean; // Whether the interactive shell is enabled (persistent PTY session tool family)
  // Post-trigger handling strategy for P3 (only meaningful for custom agent)
  trigger_run_mode?: "serial" | "parallel"; // Serial queuing / each trigger runs its own concurrent session
  trigger_merge_mode?: "by_task" | "all" | "none"; // serial only: merge per task / merge all / no merging
  trigger_max_parallel?: number; // Only parallel: per-agent concurrency limit; 0 = unlimited
  // Binding counts (returned only by list endpoints): visible MCP / visible Skill / bound tools
  mcp_count?: number;
  skill_count?: number;
  tool_count?: number;
}

export interface PromptVar {
  name: string;
  description: string;
  example: string;
  source: "exploration" | "runtime" | "distilled";
}

export interface PromptVersion {
  version: number;
  ts: string;
  note: string;
  template_text: string;
}

export interface AgentDetail {
  agent: Agent;
  prompt: string;
  variables: PromptVar[];
  versions: PromptVersion[];
  visibility: { mcp: number[]; skill: string[] };
  // Candidate LLM configs that can be bound (for the "default model" dropdown); the current binding is in agent.llm_profile_id
  llm_profiles?: { id: number; name: string; model: string; is_default: boolean }[];
  wrapup_prompt?: string; // Saved wrap-up prompt (empty = use built-in default)
  wrapup_default?: string; // Built-in default wrap-up prompt (placeholder / restore default)
  wrapup_max_turns?: number; // Saved wrap-up round count (0 = use built-in default)
  wrapup_max_turns_default?: number; // Built-in default wrap-up turn count (for the "0=default N" hint)
  // Task-level timeout wrap-up wording (worker/planner only; this section is shown only when task_timeout_wrapup_supported=true)
  task_timeout_wrapup_supported?: boolean;
  task_timeout_wrapup_prompt?: string;
  task_timeout_wrapup_default?: string;
  task_timeout_wrapup_max_turns?: number;
  task_timeout_wrapup_max_turns_default?: number;
}

// ---- MCP ----
export interface MCPServer {
  id: number;
  name: string;
  transport: "stdio" | "http" | "sse";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  enabled: boolean;
  insecure?: boolean; // http: skip TLS cert verification (self-signed servers)
  tools?: string[]; // mcp_tools_cache (names only, for the count)
  timeout_seconds?: number; // http/sse: per-request timeout in seconds (default 120)
  last_connect_at?: string | null; // last connect attempt (ISO time)
  last_connect_ok?: boolean | null; // outcome of the last connect attempt
  last_connect_err?: string | null; // failure reason when last_connect_ok is false
}

export interface MCPTool {
  name: string;
  description: string;
}

// ---- Skills ----
// Fields align with the agentskills.io open specification.
// description covers both "what the skill does" and "when to use it".
export interface SkillItem {
  name: string; // unique key = directory name
  description?: string; // required per spec; covers what + when to use
  license?: string; // optional: SPDX identifier or free text
  compatibility?: string; // optional: environment requirements
  mcps?: string[]; // MCP server names this skill unlocks on load
  files: string[]; // files in the skill directory
  // Call statistics (skill_usage ledger). For a skill that has never been called: calls=0, last_used is omitted.
  calls: number;
  tasks: number; // Number of tasks that have loaded it (chat sessions are not counted)
  usage_agents: string[]; // Load the agent key that has been loaded before
  last_used?: string;
}

// SkillCall is one Skill() invocation (the recent call list for a single skill).
export interface SkillCall {
  ts: string;
  agent_key: string;
  task_id: number; // 0 = non-task scenario (conversation session)
  session_id: string;
  args_len: number;
}

// MissingSkill is a skill that was named but does not exist — the gap of "wanted but not available".
export interface MissingSkill {
  skill: string;
  calls: number;
  agents: string[];
  last_used?: string;
}

// ---- Tools (built-in tool catalog) ----
// key + handler live in Go; only these fields are page-editable. system tools lock
// the key and the parameter *structure* (name/type/required) — the per-param
// description/default and the agent binding are what move.
export interface Tool {
  key: string;
  system: boolean;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema: Record<string, any>; // full JSON-Schema (object with properties)
  agents: string[]; // bound agent keys
  enabled: boolean;
  kind?: "builtin" | "shell" | "command" | "script" | "http"; // Custom tool type
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec?: Record<string, any>; // Custom tool execution spec (kind!=builtin)
  deferred?: boolean; // Schema deferred (SearchExtraTools/ExecuteExtraTool)
  calls?: number; // persistent runtime invocation count (older APIs may omit it)
}

// ---- Stats ----
export interface Stats {
  assets: number;
  engine_mode: EngineMode;
  llm_configured: boolean;
  roe_enabled: boolean;
  findings_confirmed: number;
  active_task?: Partial<Task>;
}

// ---- Intercept Rules ----
export type InterceptAction = "allow" | "deny" | "ask";
export type InterceptMatchTarget = "tool_name" | "tool_input";
export type InterceptMatchType = "string" | "regex";

export interface InterceptRule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_target: InterceptMatchTarget;
  match_type: InterceptMatchType;
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
  created_at: string;
  updated_at: string;
}

// ---- Asset Intercept Rules (asset interception: global blocklist) ----
export type AssetInterceptKind =
  | "exact_domain"
  | "exact_ip"
  | "exact_url"
  | "fuzzy_domain"
  | "fuzzy_ip"
  | "fuzzy_url"
  | "cidr";

// action is only used for task-level rules: block=intercept (testing forbidden) allow=permit (allowlist).
export type AssetInterceptAction = "block" | "allow";

// Entry fields for task-level asset block/allow rules (used when creating a task and editing task details).
export interface AssetInterceptRuleInput {
  action: AssetInterceptAction;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  enabled: boolean;
}

// Task credentials (#3): per-task test accounts. An empty password on a user-declared
// entry means "agent generates": the agent registers that account and records it back.
export type TaskCredentialInput = {
  domain: string;
  username: string;
  password: string;
  note?: string;
};

export type TaskCredential = TaskCredentialInput & {
  id: number;
  task_id: number;
  source: "user" | "agent";
  note: string;
  created_at: string;
  updated_at: string;
};

export interface AssetInterceptRule {
  id: number;
  enabled: boolean;
  action?: AssetInterceptAction; // Global rules do not carry this field (always block); task-level rules distinguish block/allow
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface InterceptPending {
  decision_source?: "rule" | "model" | "unknown" | "";
  id: number;
  rule_id?: number;
  conversation_id?: number;
  task_id?: string;
  agent_name: string;
  tool_name: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool_input: Record<string, any>;
  status: "pending" | "allowed" | "denied" | "timeout";
  reason: string; // Rule message or model decision rationale (model decisions have a [Model] prefix)
  decided_at?: string;
  created_at: string;
}

// JudgeConfig: global configuration for model fallback approval (the model decides only when no block rule matches).
export interface JudgeConfig {
  enabled: boolean;
  profile_id: number; // 0 = follow the active/default configuration
  prompt: string; // Judgment prompt; on GET, the backend fills in the full built-in template text if unset
  timeout_seconds: number; // Model call timeout
  fail_action: "allow" | "ask" | "deny"; // Fallback when the model errors, times out, or returns unparseable output
  ask_timeout_seconds: number; // Approval wait timeout after the model's judgment escalates an ask to a human
  ask_timeout_action: "allow" | "deny"; // Default action when approval times out
}

// JudgeUsage: cumulative token usage of model judgment (fallback approval, judge lane) and the daily time series over the last N days.
export interface JudgeDayUsage {
  date: string; // YYYY-MM-DD (UTC)
  calls: number;
  input_tokens: number;
  output_tokens: number;
}
export interface JudgeUsage {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  daily: JudgeDayUsage[];
}

export interface InterceptApprovalFilter {
  status?: InterceptPending["status"];
  decision_source?: "rule" | "model" | "unknown";
}

// InterceptApprovalRow enriches InterceptPending with conversation/task and rule context.
export interface InterceptApprovalRow extends InterceptPending {
  conv_title: string; // "" if no linked conversation
  conv_agent_key: string; // "" if no linked conversation
  rule_name: string; // "" if rule was deleted
}

// ConvTokenSummary — one conversation's token total (+ profile/date) for merging
// chat usage into the dashboard token stats. GET /api/tokens/conversations.
export interface ConvTokenSummary {
  llm_profile_id: number | null;
  created_at: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// ---- Command recording (Bash execution history) ----
export interface CommandRecord {
  id: number;
  exploration_id: number;
  worker: string;
  tool: string;
  command: string; // raw tool input (JSON)
  output: string;
  is_error: boolean;
  created_at: string;
}

// Call statistics for a single tool (/commands/stats); errors is the number of failed calls among them.
export interface ToolStat {
  tool: string;
  total: number;
  errors: number;
}

// ---- LLM recording ----
export interface LLMRecordItem {
  id: number;
  ts: string;
  model: string;
  profile_name: string;
  session_id: string;
  task_id: string;
  worker: string;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read: number;
  cache_write: number;
  status: string;
  error?: string;
}

export interface LLMRecordDetail extends LLMRecordItem {
  request_body: string;
  response_body: string;
  // Raw HTTP traffic actually sent and received by the provider: the request is the full body emitted by buildBody() (including the tool
  // schema), the response is the raw SSE frames. The request_body/response_body above are a normalized view,
  // Discards the tool schema and tool_use blocks. Old records are empty.
  raw_request?: string;
  raw_response?: string;
}

// One distinct task with its LLM-record count (task picker on the records page).
export interface LLMTask {
  task_id: string;
  count: number;
}

// The exact JSON sent to the review model, retained for all model verdicts.
export interface InterceptReviewInput {
  version: number;
  background?: {
    // worker_summary is retained only for immutable v2/v3 snapshots.
    source: "user_message" | "worker_summary";
    text: string;
    truncated?: boolean;
  };
  // Version 1 snapshots are immutable and remain readable in historical audits.
  task?: {
    task_id: number;
    description: string;
    goal: string;
    constraints: { id: number; kind: string; text: string; origin: string; created_at: number }[];
    truncated?: boolean;
  };
  working_directory?: string;
  worker_intent?: string;
  turn_input?: string;
  background_truncated?: boolean;
  // Legacy v1/v2 snapshots only; v3 never sends execution history.
  history?: {
    tool_use_id: string;
    tool: string;
    arguments_preview: string;
    result: string;
    status: "succeeded" | "failed";
    truncated?: boolean;
  }[];
  history_truncated?: boolean;
  correlation?: "exact" | "ambiguous" | "unavailable";
  tool_name: string;
  arguments: Record<string, unknown>;
}

// Immutable review snapshot plus separately recorded execution outcome.
export interface InterceptAudit {
  model_input?: InterceptReviewInput;
  model_input_digest?: string;
  run_id?: string;
  tool_use_id?: string;
  correlation: "exact" | "ambiguous" | "unavailable";
  input_digest: string;
  user_message: string;
  user_truncated?: boolean;
  context:
    | { kind: string; tool?: string; tool_use_id?: string; text: string; is_error?: boolean; truncated?: boolean }[]
    | null;
  context_truncated?: boolean;
  captured_at: string;
  model_fallback?: boolean;
  initial_action: "allow" | "ask" | "deny";
  initial_reason: string;
  effective_action?: "allow" | "deny";
  decision_reason?: string;
  rule_name?: string;
  config_digest?: string;
  profile_id?: number;
  execution_status: "not_started" | "not_executed" | "awaiting_result" | "succeeded" | "failed" | "unknown";
  output?: string;
  output_truncated?: boolean;
  execution_ended_at?: string;
}
export interface InterceptDetail extends InterceptApprovalRow {
  audit: InterceptAudit | null;
}

export type TrafficEvidenceRole = "baseline" | "proof" | "verification" | "supporting";
export interface TrafficEvidenceRef {
  traffic_id: string;
  role?: TrafficEvidenceRole;
  note?: string;
}
export interface TrafficEvidenceSnapshot {
  id: string;
  source_traffic_id: string;
  captured_at: number;
  url: string;
  method: string;
  status: number;
  content_type: string;
  req_head?: string;
  resp_head?: string;
  req_hash: string;
  resp_hash: string;
  req_len: number;
  resp_len: number;
}
export interface FindingTrafficBinding {
  id: string;
  finding_id: string;
  snapshot_id: string;
  role: TrafficEvidenceRole;
  note: string;
  position: number;
  created_at: string;
  snapshot: TrafficEvidenceSnapshot;
}
export interface FindingTraffic {
  finding_id: string;
  version: number;
  report_version: number;
  bindings: FindingTrafficBinding[];
}
export interface EvidenceBodyPreview {
  content: string;
  offset: number;
  total: number;
  next_offset: number;
  truncated: boolean;
  binary: boolean;
}
export interface FindingTrafficDetail {
  binding: FindingTrafficBinding;
  request: EvidenceBodyPreview;
  response: EvidenceBodyPreview;
}

// Original execution selected from an approval, never submitted to the reviewer.
export interface InterceptExecution {
  conversation_id: number | null;
  task_id: string | null;
  session: string;
  seq: number;
  items: Activity[];
}

// ---- Knowledge base + reflection pool (operator management) ----
// Mirrors db/knowledge.go: the operator sees every scope, an agent may only
// write a task-scoped candidate, and promotion is the operator's action.
export type KnowledgeScope = "global" | "environment" | "company" | "task";
export type KnowledgeKind = "technique" | "tool" | "opsec" | "indicator" | "playbook" | "lead" | "note";
export type KnowledgeStatus = "candidate" | "adopted" | "retired";
export type KnowledgeSource = "operator" | "agent" | "reflection";
export type KnowledgeSort = "created" | "updated" | "title";
export type KnowledgeUsageSurface = "task_start" | "round" | "recall" | "chat";

export interface KnowledgeEntry {
  id: number;
  scope: KnowledgeScope;
  company_id?: number;
  task_id?: number;
  kind: KnowledgeKind;
  title: string;
  body: string;
  tags: string[];
  status: KnowledgeStatus;
  source: KnowledgeSource;
  origin_task_id?: number;
  origin_intent_id?: number; // intent that wrote it; 0/absent for planner and operator writes
  created_at: string;
  updated_at: string;
}

export interface KnowledgePage {
  entries: KnowledgeEntry[];
  total: number;
  count: number;
  relaxed: boolean;
  limit: number;
  offset: number;
}

export interface KnowledgeStats {
  total: number;
  by_scope: Record<string, number>;
  by_status: Record<string, number>;
  by_kind: Record<string, number>;
  by_source: Record<string, number>;
}

export interface KnowledgeUsageRow {
  task_id: number;
  surface: KnowledgeUsageSurface;
  shown_at: string;
}

export interface KnowledgeUsage {
  hits: number;
  last_used: string; // RFC3339, empty when the entry was never injected
  usage: KnowledgeUsageRow[];
}

export interface KnowledgeInput {
  scope: KnowledgeScope;
  company_id?: number;
  task_id?: number;
  kind: KnowledgeKind;
  title: string;
  body: string;
  tags: string[];
}

export interface KnowledgePatch {
  title?: string;
  body?: string;
  kind?: KnowledgeKind;
  tags?: string[];
  status?: KnowledgeStatus;
}

export type BulkKnowledgeAction = "promote" | "retire" | "delete" | "adopt";

export interface BulkKnowledgeResult {
  id: number;
  ok: boolean;
  error?: string;
}

// Query shapes for the two list endpoints; lib/memory-query.ts turns them into
// query strings so the parameter rules live in one tested place.
export interface KnowledgeQuery {
  scope?: KnowledgeScope | "";
  kind?: KnowledgeKind | "";
  status?: KnowledgeStatus | "";
  source?: KnowledgeSource | "";
  tag?: string;
  origin_task_id?: number | null;
  company_id?: number | null;
  task_id?: number | null;
  q?: string;
  created_after?: string; // RFC3339
  created_before?: string; // RFC3339
  sort?: KnowledgeSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export type ReflectionKind = "opsec" | "noise" | "lookfor" | "learning" | "mistake";

export interface Reflection {
  id: number;
  task_id: number;
  intent_id?: number;
  kind: ReflectionKind;
  source: string; // engine | worker | planner
  dedupe_key?: string;
  summary: string;
  detail: string;
  signal?: unknown;
  created_at: string;
  updated_at?: string;
}

export interface ReflectionPage {
  reflections: Reflection[];
  total: number;
  count: number;
  limit: number;
  offset: number;
}

export interface ReflectionStats {
  total: number;
  by_kind: Record<string, number>;
  by_source: Record<string, number>;
  by_task: { task_id: number; count: number }[];
}

export interface ReflectionQuery {
  task_id?: number | null;
  kind?: ReflectionKind[] | string; // repeatable on the wire
  source?: string;
  q?: string;
  since?: string; // RFC3339
  limit?: number;
  offset?: number;
}

export interface MemoryPreview {
  mode: "inject" | "off";
  start_block: string;
  round_block: string;
  knowledge_ids: number[];
  reflection_ids: number[];
  intent_id: number; // 0 when the preview was not asked for one intent
  as_of: string; // RFC3339 render time of the launch block; "" when not intent-scoped
}

// The promotion queue: one task's candidates with the evidence an operator needs
// to decide, ordered by what the origin intent actually produced.
export type KnowledgeReviewOutcome = "finding" | "fact" | "none" | "unknown";

export interface KnowledgeReviewItem {
  entry: KnowledgeEntry;
  origin_intent_id: number;
  origin_outcome: KnowledgeReviewOutcome;
  redactions: number; // identifiers a promotion would generalise
  nearest_adopted: { id: number; title: string } | null; // likely duplicate
}

export interface KnowledgeReview {
  items: KnowledgeReviewItem[];
  total: number;
}

// Per-task candidate counts for the in-app review notice; tasks with none are
// absent from the map.
export type KnowledgeReviewCounts = Record<string, number>;

// A drafted engagement plan. The drafting assistant proposes it; the operator
// reviews, then applies or discards it. Nothing here is in the graph yet, which
// is why the preview must show every part before Apply is reachable.
export type PlanDraftStatus = "draft" | "applied" | "discarded";

export interface PlanGoal {
  ref: string;
  text: string;
  vulnclass?: string;
}

export interface PlanIntent {
  ref: string;
  summary: string;
  goal: string; // ref of the goal this intent serves; "" = none
  asset_ids?: number[];
  depends_on?: string[]; // intent refs that must run first
}

export interface PlanHint {
  text: string;
  asset_ids?: number[];
  rule?: boolean; // true = a constraint the planner must not contradict
}

export interface PlanScope {
  effect: "include" | "exclude"; // include widens the task scope and needs allow_include
  kind: string; // company / root_domain / subdomain / ip / cidr / icp / keyword
  value: string;
  note?: string;
}

export interface PlanProposal {
  summary: string;
  goals: PlanGoal[];
  intents: PlanIntent[];
  hints: PlanHint[];
  scope: PlanScope[];
}

export interface PlanDraft {
  id: number;
  task_id: number;
  status: PlanDraftStatus;
  summary: string;
  proposal: PlanProposal;
  created_node_ids?: number[]; // graph nodes the apply step wrote
  created_at: string;
  applied_at?: string;
}

export interface PlanDraftList {
  items: PlanDraft[];
}

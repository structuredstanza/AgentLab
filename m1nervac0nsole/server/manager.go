package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/enrich"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/gateway"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/guard"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/intercept"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
	actool "github.com/structuredstanza/norma/tool"
)

// Task is one engagement: a description + goal + its own exploration store,
// sharing the process-wide asset store. ID is the PG task id as a string; ExpID
// is the exploration the task owns.
type Task struct {
	ID           string `json:"id"`
	ExpID        int64  `json:"exploration_id"`
	Name         string `json:"name"` // Optional task name; empty = unnamed
	CategoryID   *int64 `json:"category_id,omitempty"`
	CategoryName string `json:"category_name,omitempty"`
	PinnedAt     int64  `json:"pinned_at,omitempty"`
	Description  string `json:"description"`
	Goal         string `json:"goal"`
	CreatedAt    int64  `json:"created_at"`
	CompletedAt  int64  `json:"completed_at,omitempty"` // unix seconds upon entering a terminal state; 0 = not finished
	Paused       bool   `json:"paused"`
	Queued       bool   `json:"queued"` // Suspended because the concurrency limit has been reached; automatically starts once a slot frees up. true = has not started running yet
	// QueuedAt is an internal Unix-nanosecond ordering key. It is deliberately
	// finer than CreatedAt so several tasks enqueued in the same second retain
	// their real FIFO order.
	QueuedAt           int64   `json:"queued_at,omitempty"`
	QueueMode          string  `json:"queue_mode,omitempty"`
	ParentRef          string  `json:"parent_ref,omitempty"`     // Parent task id (orchestration spawn record)
	LLMProfileID       *int64  `json:"llm_profile_id,omitempty"` // Specifies the LLM config used to run this task's planner/worker; nil = use the globally active config
	LLMProfileIDs      []int64 `json:"llm_profile_ids,omitempty"`
	ActiveLLMProfileID *int64  `json:"active_llm_profile_id,omitempty"`
	LLMChainRevision   int64   `json:"-"`
	LLMFailoverState   string  `json:"llm_failover_state,omitempty"`
	// LLMRotate (#85): per-intent round-robin over the task's LLM chain heads.
	LLMRotate         bool `json:"llm_rotate,omitempty"`
	rotateMu          sync.Mutex
	rotateNext        int
	LLMFailoverReason string  `json:"llm_failover_reason,omitempty"`
	SourceTaskIDs     []int64 `json:"source_task_ids,omitempty"`
	CompanyIDs        []int64 `json:"company_ids,omitempty"`
	PausedAt          int64   `json:"paused_at,omitempty"`
	Status            string  `json:"status"` // Persisted lifecycle status (done/failed/timeout are terminal states; empty or other values are derived from runtime state)
	// Task-level timeouts (see docs/\u4efb\u52a1\u7ea7\u8d85\u65f6\u4e0e\u6536\u5c3e\u8bbe\u8ba1.md). DeadlineAt/FirstRunAt are Unix seconds; 0 = unset/not yet run.
	TimeoutSeconds       int                    `json:"timeout_seconds"`
	PlanHeartbeatSeconds int                    `json:"plan_heartbeat_seconds"` // Planner heartbeat trigger interval (seconds)
	PlanQuietMode        bool                   `json:"plan_quiet_mode"`        // planner quiet-mode switch (#86), editable mid-run
	CoverageEnabled      bool                   `json:"coverage_enabled"`       // Asset coverage feature toggle (set at creation time, default on)
	FirstRunAt           int64                  `json:"first_run_at,omitempty"`
	DeadlineAt           int64                  `json:"deadline_at,omitempty"`
	Store                *pgdb.ExplorationStore `json:"-"`
	Guard                *guard.Guard           `json:"-"`
	notify               chan struct{}
	lifecycleMu          sync.RWMutex
	llmMu                sync.RWMutex

	// pendingTriggers accumulates the concrete changes (worker done / finding) that
	// fired planning rounds since the last one consumed them. The debounce coalesces
	// a burst into one round, so several may pile up before drainTriggers() clears them.
	trigMu          sync.Mutex
	pendingTriggers []agent.TriggerEvent
	churnFired      map[int64]bool // assets already announced as churned (one trigger per asset per task)
}

// taskLifecycleState is an internally consistent view of the mutable task
// lifecycle and inherited-scope context. Callers must use lifecycleSnapshot and
// updateLifecycle instead of reading or writing the corresponding Task fields
// directly after the task has been published by Manager.
type taskLifecycleState struct {
	Name          string
	PinnedAt      int64
	Status        string
	Paused        bool
	PausedAt      int64
	Queued        bool
	QueuedAt      int64
	QueueMode     string
	CompletedAt   int64
	FirstRunAt    int64
	DeadlineAt    int64
	SourceTaskIDs []int64
	CompanyIDs    []int64
	CategoryID    *int64
	CategoryName  string
}

func (t *Task) lifecycleSnapshot() taskLifecycleState {
	if t == nil {
		return taskLifecycleState{}
	}
	t.lifecycleMu.RLock()
	defer t.lifecycleMu.RUnlock()
	return t.lifecycleSnapshotLocked()
}

func (t *Task) lifecycleSnapshotLocked() taskLifecycleState {
	return taskLifecycleState{
		Name:          t.Name,
		PinnedAt:      t.PinnedAt,
		Status:        t.Status,
		Paused:        t.Paused,
		PausedAt:      t.PausedAt,
		Queued:        t.Queued,
		QueuedAt:      t.QueuedAt,
		QueueMode:     t.QueueMode,
		CompletedAt:   t.CompletedAt,
		FirstRunAt:    t.FirstRunAt,
		DeadlineAt:    t.DeadlineAt,
		SourceTaskIDs: append([]int64(nil), t.SourceTaskIDs...),
		CompanyIDs:    append([]int64(nil), t.CompanyIDs...),
		CategoryID:    cloneInt64Ptr(t.CategoryID),
		CategoryName:  t.CategoryName,
	}
}

func (t *Task) updateLifecycle(update func(*taskLifecycleState)) {
	if t == nil || update == nil {
		return
	}
	t.lifecycleMu.Lock()
	state := t.lifecycleSnapshotLocked()
	update(&state)
	t.Name = state.Name
	t.PinnedAt = state.PinnedAt
	t.Status = state.Status
	t.Paused = state.Paused
	t.PausedAt = state.PausedAt
	t.Queued = state.Queued
	t.QueuedAt = state.QueuedAt
	t.QueueMode = state.QueueMode
	t.CompletedAt = state.CompletedAt
	t.FirstRunAt = state.FirstRunAt
	t.DeadlineAt = state.DeadlineAt
	t.SourceTaskIDs = append(t.SourceTaskIDs[:0], state.SourceTaskIDs...)
	t.CompanyIDs = append(t.CompanyIDs[:0], state.CompanyIDs...)
	t.CategoryID = cloneInt64Ptr(state.CategoryID)
	t.CategoryName = state.CategoryName
	t.lifecycleMu.Unlock()
}

type taskLLMState struct {
	ProfileID      *int64
	ProfileIDs     []int64
	ActiveID       *int64
	ChainRevision  int64
	FailoverState  string
	FailoverReason string
}

func cloneInt64Ptr(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (t *Task) llmStateSnapshot() taskLLMState {
	t.llmMu.RLock()
	defer t.llmMu.RUnlock()
	return taskLLMState{
		ProfileID:      cloneInt64Ptr(t.LLMProfileID),
		ProfileIDs:     append(make([]int64, 0, len(t.LLMProfileIDs)), t.LLMProfileIDs...),
		ActiveID:       cloneInt64Ptr(t.ActiveLLMProfileID),
		ChainRevision:  t.LLMChainRevision,
		FailoverState:  t.LLMFailoverState,
		FailoverReason: t.LLMFailoverReason,
	}
}

func (t *Task) setLLMState(profileID, activeID *int64, profileIDs []int64, revision int64, state, reason string) bool {
	t.llmMu.Lock()
	defer t.llmMu.Unlock()
	if revision < t.LLMChainRevision {
		return false
	}
	t.LLMProfileID = cloneInt64Ptr(profileID)
	t.ActiveLLMProfileID = cloneInt64Ptr(activeID)
	t.LLMProfileIDs = append(t.LLMProfileIDs[:0], profileIDs...)
	t.LLMChainRevision = revision
	t.LLMFailoverState = state
	t.LLMFailoverReason = reason
	return true
}

// nextRotatedProfile returns the chain head for the NEXT claimed worker
// intent under per-intent rotation (#85): strict round-robin over the task's
// chain. The active head stays authoritative for every non-worker role and for
// failover ordering; rotation only distributes worker lanes across heads.
func (t *Task) nextRotatedProfile() (int64, bool) {
	t.rotateMu.Lock()
	defer t.rotateMu.Unlock()
	// Read the chain through llmStateSnapshot, not the field: setLLMState
	// rewrites the slice under llmMu while this holds only rotateMu, and an
	// append that reallocates can be observed as a new length with the old
	// backing array, which indexes out of range and panics the process.
	ids := t.llmStateSnapshot().ProfileIDs
	if len(ids) == 0 {
		return 0, false
	}
	pick := ids[t.rotateNext%len(ids)]
	t.rotateNext++
	return pick, true
}

// DeleteTaskOptions controls cleanup of data stored outside the task's own
// exploration graph. All options default to false for backward compatibility.
type DeleteTaskOptions struct {
	DeleteAssets     bool `json:"delete_assets"`
	DeleteTraffic    bool `json:"delete_traffic"`
	DeleteFiles      bool `json:"delete_files"`
	DeleteFindings   bool `json:"delete_findings"`
	DeleteLLMRecords bool `json:"delete_llm_records"`
}

// DeleteTaskResult makes destructive cleanup auditable to API callers.
type DeleteTaskResult struct {
	Deleted           string `json:"deleted"`
	AssetsDeleted     int64  `json:"assets_deleted"`
	AssetsDetached    int64  `json:"assets_detached"`
	TrafficDeleted    int64  `json:"traffic_deleted"`
	FilesDeleted      bool   `json:"files_deleted"`
	FindingsDeleted   int64  `json:"findings_deleted"`
	LLMRecordsDeleted int64  `json:"llm_records_deleted"`
	CleanupWarning    string `json:"cleanup_warning,omitempty"`
}

// Manager owns the PostgreSQL data source (asset graph + every task's exploration
// graph + config) and the in-memory set of task handles.
type Manager struct {
	dir         string
	pg          *pgdb.DB
	assets      *pgdb.AssetStore
	traffic     *traffic.Traffic       // process-wide recording proxy (may be nil)
	enrich      *enrich.Engine         // engine-side asset auto-completion (DNS/HTTP)
	interceptor *intercept.Interceptor // user-configured tool-call interception rules
	// gw is the origin transport the recorder dials through: policy, DNS
	// pinning, the exit and the origin TLS handshake. Nil when no recorder runs.
	gw *gateway.Transport
	// sessions maps a gateway credential to the session it was issued for. The
	// credential is the only thing a tool holds: it names no task, purpose or
	// revision, so a tool cannot widen its own authority by editing it.
	sessMu   sync.RWMutex
	sessions map[string]netpolicy.Session

	// profCache memoizes task speed profiles for maskFor (see profileTTL);
	// readProfile is a test seam, nil reads PostgreSQL.
	profMu      sync.Mutex
	profCache   map[int64]profileEntry
	readProfile func(context.Context, int64) (string, error)

	companyMu sync.Mutex // serializes task/company-scope commits with live handle registration
	// taskStateMu preserves commit order between PostgreSQL lifecycle writes and
	// their in-memory mirrors. lifecycleMu makes snapshots race-free, but without
	// this outer write lock an older request could commit first and publish last.
	taskStateMu sync.Mutex
	mu          sync.RWMutex
	tasks       map[string]*Task
	active      string
	trafficOn   bool // Traffic capture toggle (default off; settings.traffic_capture)
	llmRecOn    bool // LLM recording switch (default off; settings.llm_record)
	// Web search toggle and provider (default off; settings.web_search_*). brave-free requires braveKey; tavily requires tavilyKey.
	// webSearchProxy is an independent egress proxy (http/https/socks5), unrelated to the MITM proxy used for traffic recording.
	webSearchOn      bool
	webSearchBackend string
	braveKey         string
	tavilyKey        string
	webSearchProxy   string
	// globalProxy is the egress proxy all target traffic routes through
	// (http/https/socks5, optional user:pass). Empty = direct. When traffic
	// capture is on it becomes the MITM's upstream; when capture is off it is
	// injected into agent bash env / WebFetch directly. See ProxyAddr.
	globalProxy string
}

// Settings keys the UI toggles at runtime.
const (
	settingTrafficCapture      = "traffic_capture"
	settingAgentTrafficBinding = "agent_traffic_binding"
	settingWebSearchOn         = "web_search_enabled"
	settingWebSearchBackend    = "web_search_backend"
	settingBraveKey            = "brave_search_api_key"
	settingTavilyKey           = "tavily_search_api_key"
	settingWebSearchProxy      = "web_search_proxy"
	// settingGlobalProxy is the global egress proxy for all target traffic
	// (http/https/socks5). Empty = direct. Distinct from web_search_proxy (which
	// only routes the search backend) and the per-profile LLM proxy.
	settingGlobalProxy = "global_proxy"
	settingWorkers     = "workers"
	settingLLMRecord   = "llm_record"
	// LLM polling (failover). Disabled by default — when enabled, the agent that uses the "globally active config" runs on the current config
	// when the current configuration becomes unavailable (insufficient balance / invalid key / rate limiting / service errors).
	// settingLLMPoolBindFallback is only meaningful when round-robin is enabled: it defaults to off, i.e. the agent/task explicitly
	// bound to a specific configuration, it uses only that configuration and fails outright on error. When enabled, a failing bound configuration also falls back to the polling chain.
	settingLLMPoolOn           = "llm_pool_enabled"
	settingLLMPoolBindFallback = "llm_pool_bind_fallback"
	settingLLMRefusalFallback  = "llm_refusal_fallback_enabled"
	// Task concurrency limit: a switch plus a limit count. Off by default; when enabled, the default limit is 5 (see defaultConcurrencyLimit).
	settingConcurrencyOn    = "task_concurrency_enabled"
	settingConcurrencyLimit = "task_concurrency_limit"
	// Experimental feature: noa model-driven context compression (norma v0.4.0). Disabled by default — when enabled, the four classes of platform-connected
	// agents (planner/worker/main agent/conversation) have their context compression handled by noa, replacing built-in compaction.
	// Read once per run; toggling only affects runs started afterward.
	settingNoaCompaction = "noa_compaction"
	// defaultWebSearchBackend is used when web search is on but no backend was picked.
	defaultWebSearchBackend = "ddgs"
	// deepSeekWebSearchBackend borrows the active LLM profile instead of its own
	// key, so it only works on an anthropic-format profile pointed at DeepSeek.
	deepSeekWebSearchBackend = "deepseek"
	// defaultWorkers is the concurrent work-agent count when the setting is unset.
	defaultWorkers = 3
	// defaultConcurrencyLimit is the simultaneous-running-task cap when the feature
	// is enabled but no explicit limit was saved.
	defaultConcurrencyLimit = 5
)

// ConcurrencyLimit returns whether the simultaneous-running-task cap is enabled and
// its limit (default 5 when enabled but unset). limit is always >=1 when enabled.
func (m *Manager) ConcurrencyLimit() (enabled bool, limit int) {
	on, _, _ := m.pg.GetSetting(settingConcurrencyOn)
	if strings.TrimSpace(on) != "true" {
		return false, 0
	}
	limit = defaultConcurrencyLimit
	if v, ok, _ := m.pg.GetSetting(settingConcurrencyLimit); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 {
			limit = n
		}
	}
	return true, limit
}

// SetConcurrency persists the running-task concurrency cap. limit<1 is clamped to 1.
func (m *Manager) SetConcurrency(enabled bool, limit int) error {
	if limit < 1 {
		limit = defaultConcurrencyLimit
	}
	if err := m.pg.SetSetting(settingConcurrencyLimit, strconv.Itoa(limit)); err != nil {
		return err
	}
	return m.pg.SetSetting(settingConcurrencyOn, strconv.FormatBool(enabled))
}

// Workers returns the configured concurrent work-agent count (default 3). Read
// per-task at engine.Run, so a change applies to tasks started afterwards.
func (m *Manager) Workers() int {
	v, ok, err := m.pg.GetSetting(settingWorkers)
	if err != nil || !ok {
		return defaultWorkers
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return defaultWorkers
	}
	return n
}

// errWorkersPositive is shown as-is in the settings UI when the work agent
// count is less than one.
const errWorkersPositive = "the work agent count must be 1 or more"

// SetWorkers persists the concurrent work-agent count. Values <=0 are rejected.
func (m *Manager) SetWorkers(n int) error {
	if n <= 0 {
		return errors.New(errWorkersPositive)
	}
	return m.pg.SetSetting(settingWorkers, strconv.Itoa(n))
}

// Enrich returns the asset auto-completion engine (may be nil if init failed).
func (m *Manager) Enrich() *enrich.Engine { return m.enrich }

// NewManager connects to PostgreSQL and, if proxyAddr is non-empty, starts the
// traffic-recording proxy. PostgreSQL is required (it is the single data source).
func NewManager(dir, proxyAddr string) (*Manager, error) {
	// Resolve the data dir to an ABSOLUTE path up front. Every data path derives
	// from it — notably the MITM CA cert, whose path is injected into worker shells
	// (SSL_CERT_FILE/CURL_CA_BUNDLE) and read by WebFetch. A relative path (the
	// default is "./data" under `go run`) only resolves when the current working
	// directory happens to match, so curl/WebFetch in a different CWD fail to load
	// the CA → TLS to the proxy breaks (curl 000 / EOF). Absolute makes it CWD-proof.
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dsn, source, err := pgdb.DSN()
	if err != nil {
		return nil, err
	}
	log.Printf("[pg] database configuration source: %s", source)
	pg, err := pgdb.Open(dsn)
	if err != nil {
		return nil, err
	}
	if err := pg.RecoverFindingRetests(); err != nil {
		pg.Close()
		return nil, fmt.Errorf("recover finding retests: %w", err)
	}
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		log.Printf("[llmrec] create table: %v", err)
	}
	if err := pg.EnsureLLMUsageTable(); err != nil {
		log.Printf("[llmusage] create table: %v", err)
	}
	m := &Manager{dir: dir, pg: pg, assets: pg.Assets(), tasks: map[string]*Task{}, interceptor: intercept.New(pg)}
	if proxyAddr != "" {
		// The recorder dials every origin through the gateway hook. A recorder
		// that cannot start is a startup failure: the alternative is a recorder
		// that either dials directly or silently stops recording, and both are
		// the unrecorded path the boundary forbids.
		gw := m.newGatewayTransport()
		tr, err := openRecorder(filepath.Join(dir, "traffic"), proxyAddr, gw)
		if err != nil {
			_ = pg.Close()
			return nil, err
		}
		if err := tr.RecoverHostDeleteStages(func(_ int64, taskID int64) (bool, error) {
			if taskID <= 0 {
				// This is an internal consistency error in the recovery-traffic callback during startup. NewManager
				// Wrapped as fmt.Errorf("recover traffic delete staging: %w", err) so the startup failure
				// It is an operator startup log that reaches neither writeErr nor actool,
				// so it is outside the scope of F3b (user-facing writeErr), and the original text is preserved (Z2 family).
				return false, errors.New("archive traffic staging log is missing a task ID")
			}
			task, taskErr := pg.GetTask(taskID)
			if taskErr != nil {
				return false, taskErr
			}
			// Archived/permanently deleted tasks are hidden from GetTask. A
			// restored task is visible and needs the staged traffic put back.
			return task == nil, nil
		}); err != nil {
			_ = tr.Close()
			_ = pg.Close()
			return nil, fmt.Errorf("recover traffic delete staging: %w", err)
		}
		m.gw = gw
		m.traffic = tr
		go func() {
			log.Printf("[traffic] recording proxy on %s (set HTTP_PROXY=%s + trust _ca CA)", proxyAddr, tr.ProxyAddr())
			if err := tr.Start(); err != nil {
				log.Printf("[traffic] proxy stopped: %v", err)
			}
		}()
		log.Printf("[gateway] origin transport ready: every recorded request needs a session credential issued by the backend (agent, chat and curator callers); an unknown or absent credential is refused")
	}
	// Asset auto-completion engine (§5) is created at the end of startup, once the
	// egress configuration is settled. Traffic capture toggle (default off).
	m.trafficOn = pg.GetBool(settingTrafficCapture, false)
	// LLM recording switch (default off). The recorder reads this flag on each call.
	m.llmRecOn = pg.GetBool(settingLLMRecord, false)
	// Load persisted web-search config (default: off, ddgs).
	m.webSearchOn = pg.GetBool(settingWebSearchOn, false)
	if v, ok, _ := pg.GetSetting(settingWebSearchBackend); ok && v != "" {
		m.webSearchBackend = v
	} else {
		m.webSearchBackend = defaultWebSearchBackend
	}
	if v, ok, _ := pg.GetSetting(settingBraveKey); ok {
		m.braveKey = v
	}
	if v, ok, _ := pg.GetSetting(settingTavilyKey); ok {
		m.tavilyKey = v
	}
	if v, ok, _ := pg.GetSetting(settingWebSearchProxy); ok {
		m.webSearchProxy = v
	}
	// Global egress proxy (default: direct). When capture is on, feed it to the
	// MITM as its upstream so recorded traffic exits through it; when capture is
	// off, ProxyAddr hands it to agents directly (bash env / WebFetch).
	if v, ok, _ := pg.GetSetting(settingGlobalProxy); ok {
		m.globalProxy = strings.TrimSpace(v)
	}
	// Recorder exit path: the operator's global proxy when set, else direct.
	m.applyRecorderExit()
	// Asset auto-completion engine (§5). HTTP probes go through the recorder
	// under a per-probe backend-issued session (enrichRoute); with capture off
	// there is no recorder and no probe, never a direct one.
	m.enrich = enrich.New(m.assets, enrich.Options{Workers: 4, Route: m.enrichRoute, Authorizer: netpolicy.NewAuthorizer(pg)})
	return m, nil
}

// TrafficEnabled reports whether traffic capture is on (default off). When off,
// no proxy/traffic tools/prompt are injected into agents (nothing is recorded).
func (m *Manager) TrafficEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.trafficOn
}

// SetTrafficEnabled persists and applies the traffic-capture toggle. Callers must
// rebuild the agents afterwards so the new proxy/tools/prompt take hold.
func (m *Manager) SetTrafficEnabled(on bool) error {
	if err := m.pg.SetBool(settingTrafficCapture, on); err != nil {
		return err
	}
	m.mu.Lock()
	m.trafficOn = on
	m.mu.Unlock()
	return nil
}

// LLMRecordEnabled reports whether LLM request/response recording is on
// (default off; settings.llm_record). The recorder consults this per call, so the
// toggle takes effect immediately without rebuilding agents.
func (m *Manager) LLMRecordEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.llmRecOn
}

// SetLLMRecordEnabled persists and applies the LLM-record toggle. Effective at
// once, since the recorder reads the flag on every call.
func (m *Manager) SetLLMRecordEnabled(on bool) error {
	if err := m.pg.SetBool(settingLLMRecord, on); err != nil {
		return err
	}
	m.mu.Lock()
	m.llmRecOn = on
	m.mu.Unlock()
	return nil
}

// NoaCompactionEnabled reports whether the experimental noa context-compression
// mechanism is on (default off; settings.noa_compaction). Read per agent run via the
// injected resolver, so a toggle takes effect on the next run without rebuild.
func (m *Manager) NoaCompactionEnabled() bool {
	return m.pg.GetBool(settingNoaCompaction, false)
}

// SetNoaCompaction persists the noa toggle. Effective on the next agent run —
// the resolver reads it per run, so no rebuild is needed.
func (m *Manager) SetNoaCompaction(on bool) error {
	return m.pg.SetBool(settingNoaCompaction, on)
}

// LLMPoolEnabled reports whether LLM failover ("polling") is on (default off;
// settings.llm_pool_enabled). Read when the provider chain is built,
// so a change requires a rebuild — putSettings does that.
func (m *Manager) LLMPoolEnabled() bool {
	if m.pg == nil {
		return false
	}
	return m.pg.GetBool(settingLLMPoolOn, false)
}

// SetLLMPoolEnabled persists the failover toggle. Callers rebuild agents
// afterwards so it takes effect.
func (m *Manager) SetLLMPoolEnabled(on bool) error { return m.pg.SetBool(settingLLMPoolOn, on) }

func (m *Manager) LLMRefusalFallbackEnabled() bool {
	if m.pg == nil {
		return false
	}
	return m.pg.GetBool(settingLLMRefusalFallback, false)
}

func (m *Manager) SetLLMRefusalFallbackEnabled(on bool) error {
	return m.pg.SetBool(settingLLMRefusalFallback, on)
}

// LLMPoolBindFallback reports whether an agent/task that is BOUND to a specific
// profile still falls back to the chain when that profile fails (default off: binding means exclusive,
// i.e. failure means failure). Only meaningful while LLMPoolEnabled.
func (m *Manager) LLMPoolBindFallback() bool {
	if m.pg == nil {
		return false
	}
	return m.pg.GetBool(settingLLMPoolBindFallback, false)
}

// SetLLMPoolBindFallback persists the bound-profile fallback toggle. Callers
// rebuild agents afterwards.
func (m *Manager) SetLLMPoolBindFallback(on bool) error {
	return m.pg.SetBool(settingLLMPoolBindFallback, on)
}

// WebSearch returns the current web-search config: whether it is enabled, the
// backend ("ddgs" | "brave-free" | "tavily"), the Brave API key, the Tavily API
// key (each empty unless set), and the dedicated egress proxy (empty = direct).
func (m *Manager) WebSearch() (on bool, backend, braveKey, tavilyKey, proxy string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	backend = m.webSearchBackend
	if backend == "" {
		backend = defaultWebSearchBackend
	}
	return m.webSearchOn, backend, m.braveKey, m.tavilyKey, m.webSearchProxy
}

// WebSearchOpts returns the config as the agent-package struct the server pushes
// into each agent. Disabled when off, or when a keyed backend is selected without
// its key (so a half-configured backend never silently drops the tool at session build).
func (m *Manager) WebSearchOpts() agent.WebSearchOpts {
	on, backend, braveKey, tavilyKey, proxy := m.WebSearch()
	if on && backend == "brave-free" && strings.TrimSpace(braveKey) == "" {
		on = false
	}
	if on && backend == "tavily" && strings.TrimSpace(tavilyKey) == "" {
		on = false
	}
	o := agent.WebSearchOpts{Enabled: on, Backend: backend, BraveKey: braveKey, TavilyKey: tavilyKey, Proxy: proxy}
	if backend == deepSeekWebSearchBackend {
		o.DeepSeekBaseURL, o.DeepSeekAPIKey, o.DeepSeekModel = m.deepSeekSearchCreds()
	}
	return o
}

// deepSeekSearchCreds resolves the credentials the "deepseek" search backend
// borrows from the active LLM profile (it has no key of its own). Whether that
// profile can actually drive server-side search — DeepSeek exposes it only on
// the Anthropic-format endpoint — is deliberately NOT validated here: the UI
// states the requirement and the user decides. A profile that can't serve it
// simply fails at search time (or at the settings page's Test button), which is
// the same feedback every other backend gives for a bad key.
func (m *Manager) deepSeekSearchCreds() (baseURL, apiKey, model string) {
	p, err := m.pg.ActiveProfile()
	if err != nil || p == nil {
		return "", "", ""
	}
	return p.BaseURL, p.APIKey, p.Model
}

// SetWebSearch persists and applies the web-search settings. braveKey, tavilyKey, and
// proxy are each left untouched when nil (so toggling the switch doesn't wipe a saved
// key/proxy; pass a pointer to "" to clear). Callers must rebuild agents
// afterwards so the settings take effect.
func (m *Manager) SetWebSearch(on bool, backend string, braveKey, tavilyKey, proxy *string) error {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		backend = defaultWebSearchBackend
	}
	if err := m.pg.SetBool(settingWebSearchOn, on); err != nil {
		return err
	}
	if err := m.pg.SetSetting(settingWebSearchBackend, backend); err != nil {
		return err
	}
	m.mu.Lock()
	m.webSearchOn = on
	m.webSearchBackend = backend
	m.mu.Unlock()
	if braveKey != nil {
		if err := m.pg.SetSetting(settingBraveKey, *braveKey); err != nil {
			return err
		}
		m.mu.Lock()
		m.braveKey = *braveKey
		m.mu.Unlock()
	}
	if tavilyKey != nil {
		if err := m.pg.SetSetting(settingTavilyKey, *tavilyKey); err != nil {
			return err
		}
		m.mu.Lock()
		m.tavilyKey = *tavilyKey
		m.mu.Unlock()
	}
	if proxy != nil {
		p := strings.TrimSpace(*proxy)
		if err := m.pg.SetSetting(settingWebSearchProxy, p); err != nil {
			return err
		}
		m.mu.Lock()
		m.webSearchProxy = p
		m.mu.Unlock()
	}
	return nil
}

func decodeStrSlice(raw json.RawMessage) []string {
	var out []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func decodeStrMap(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func encodeJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// HostTools are runtime host-provided tools added to EVERY agent's base list (via
// ToolAugment); the tools table then filters them per-agent binding. Currently the
// traffic tools, gated by the global capture switch: empty when capture is off, so
// no agent gets traffic_search/traffic_get regardless of binding.
func (m *Manager) HostTools() []actool.CoreTool {
	if m.traffic == nil || !m.TrafficEnabled() {
		return nil
	}
	return m.traffic.Tools()
}

func (m *Manager) Assets() *pgdb.AssetStore  { return m.assets }
func (m *Manager) PG() *pgdb.DB              { return m.pg }
func (m *Manager) Traffic() *traffic.Traffic { return m.traffic }

// ProxyAddr returns the egress proxy address agents route target traffic through:
//   - capture ON  → the recording MITM proxy (which itself exits via the global
//     proxy when one is set); agents also get its CA (see ProxyCACert).
//   - capture OFF → the global egress proxy directly (empty CA — real target
//     certs), or "" when no global proxy is set (direct, no recording).
//
// So the global proxy takes effect in both modes: at the MITM's upstream when
// capturing, in the agent's own bash env / WebFetch when not.
func (m *Manager) ProxyAddr() string {
	if m.traffic != nil && m.TrafficEnabled() {
		return m.traffic.ProxyAddr()
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.globalProxy
}

// ProxyCACert returns the CA cert path agents must trust to verify HTTPS through
// the egress proxy. Non-empty ONLY when traffic capture is on (the MITM re-signs
// certs): the global proxy used directly (capture off) is a plain forwarder that
// preserves real target certs, so no custom CA is needed there. Its emptiness is
// also the worker's "recording off" signal (see workerSystem).
func (m *Manager) ProxyCACert() string {
	if m.traffic == nil || !m.TrafficEnabled() {
		return ""
	}
	return m.traffic.CACertPath()
}

// GlobalProxy returns the configured global egress proxy URL (empty = direct).
func (m *Manager) GlobalProxy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.globalProxy
}

// SetGlobalProxy validates, persists and applies the global egress proxy
// (http/https/socks5, optional user:pass; empty = direct). It updates the
// recorder's exit immediately; callers must rebuild agents afterwards so the
// capture-off path (bash env / WebFetch) picks up the change too.
func (m *Manager) SetGlobalProxy(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		if _, err := traffic.ValidateProxyURL(raw); err != nil {
			return err
		}
	}
	if err := m.pg.SetSetting(settingGlobalProxy, raw); err != nil {
		return err
	}
	m.mu.Lock()
	m.globalProxy = raw
	m.mu.Unlock()
	// The recorder exits through the operator's proxy; clearing the setting
	// means a direct exit.
	m.applyRecorderExit()
	return nil
}

// applyRecorderExit points the recorder's origin transport at the operator's
// global proxy, or at no proxy (direct) when none is set. Clearing the setting
// therefore means direct; nothing else is substituted.
//
// The exit is the gateway's, not the recorder's own dial target: policy, DNS
// pinning and the origin handshake stay in the gateway, and only the last hop
// changes.
func (m *Manager) applyRecorderExit() {
	if m.gw == nil {
		return
	}
	m.mu.RLock()
	exit := strings.TrimSpace(m.globalProxy)
	m.mu.RUnlock()
	if exit != "" {
		// The gateway refuses an unusable exit at dial time rather than dialing
		// direct, so say why here instead of leaving the operator with bare 502s.
		if _, err := traffic.ValidateProxyURL(exit); err != nil {
			log.Printf("[proxy] recorder exit %s is not a usable proxy URL; the gateway will refuse origin dials until it is fixed", enrich.RedactProxyURL(exit))
		}
	}
	m.gw.SetExit(netpolicy.Exit{ProxyURL: exit})
}

// openRecorder starts the recording proxy with the gateway origin transport. A
// recorder without the hook would dial origins directly, so a missing one is a
// startup failure rather than a silent direct path.
func openRecorder(dir, addr string, gw *gateway.Transport) (*traffic.Traffic, error) {
	if gw == nil {
		return nil, errors.New("the recording proxy needs the gateway origin transport")
	}
	return traffic.OpenWithTransport(dir, addr, gw)
}

// newGatewayTransport builds the origin transport the recorder dials through.
// Its authorizer refuses every request when it has no policy source, so a
// transport without a database is still fail-closed rather than a direct dial.
func (m *Manager) newGatewayTransport() *gateway.Transport {
	return gateway.New(gateway.Config{
		Authorizer:    netpolicy.NewAuthorizer(m.pg),
		SessionFor:    m.gatewaySession,
		CertException: m.certException,
		HostsFor:      m.taskHostAddrs,
		MaskFor:       m.maskFor,
	})
}

// taskHostAddrs maps a hostname the task recorded to its recorded addresses,
// for testing sessions only. A failed lookup maps nothing, so the name is
// judged and resolved as usual.
func (m *Manager) taskHostAddrs(s netpolicy.Session, host string) []net.IP {
	if m.pg == nil || s.Purpose != netpolicy.PurposeTesting || s.TaskID <= 0 {
		return nil
	}
	ips, err := m.pg.Assets().TaskHostAddrs(s.TaskID, host)
	if err != nil {
		return nil
	}
	return ips
}

// Gateway returns the origin transport the recorder dials through (nil when no
// recorder runs). The supervisor reads its Exit to configure a session's packet
// boundary.
func (m *Manager) Gateway() *gateway.Transport { return m.gw }

// gatewayCredential reads the session credential from the proxy authorization
// header. A proxy URL of the form http://<credential>@host:port arrives as Basic
// auth with the credential as the user name; a client may also send it as a
// bearer token.
func gatewayCredential(req *http.Request) string {
	if req == nil {
		return ""
	}
	v := strings.TrimSpace(req.Header.Get("Proxy-Authorization"))
	if v == "" {
		return ""
	}
	scheme, rest, _ := strings.Cut(v, " ")
	rest = strings.TrimSpace(rest)
	switch {
	case strings.EqualFold(scheme, "basic"):
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return ""
		}
		user, _, _ := strings.Cut(string(raw), ":")
		return user
	case strings.EqualFold(scheme, "bearer"):
		return rest
	}
	return ""
}

// gatewaySession resolves the session a proxied request runs under from the
// credential the backend issued. An absent or unknown credential is refused:
// there is no anonymous session and no default one to fall back to.
func (m *Manager) gatewaySession(req *http.Request) (netpolicy.Session, bool) {
	cred := gatewayCredential(req)
	if cred == "" {
		return netpolicy.Session{}, false
	}
	m.sessMu.RLock()
	defer m.sessMu.RUnlock()
	s, ok := m.sessions[cred]
	return s, ok
}

// maxGatewaySessions bounds the credential map. A session that was never revoked
// is a caller bug, and evicting a live one silently would end an unrelated
// session's authority, so the issuer refuses instead.
const maxGatewaySessions = 4096

// IssueSession registers a backend-issued session and returns it, credential
// included. Purpose, task, conversation and policy revision are fixed here from
// server-side state, so a request cannot change any of them. The credential is
// what the gateway resolves the session from; it reaches a run only inside the
// proxy URL that run's tool environment carries (see ToolProxyURL).
func (m *Manager) IssueSession(ctx context.Context, caller netpolicy.Caller, taskID, conversationID int64, purpose netpolicy.Purpose) (netpolicy.Session, error) {
	s, err := netpolicy.NewIssuer(m.pg).Issue(ctx, caller, taskID, conversationID, purpose)
	if err != nil {
		return netpolicy.Session{}, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return netpolicy.Session{}, fmt.Errorf("gateway: session credential: %w", err)
	}
	cred := hex.EncodeToString(raw[:])

	m.sessMu.Lock()
	defer m.sessMu.Unlock()
	if m.sessions == nil {
		m.sessions = make(map[string]netpolicy.Session)
	}
	if len(m.sessions) >= maxGatewaySessions {
		log.Printf("[gateway] refusing to issue a session: %d credentials are live; a session was never revoked", len(m.sessions))
		return netpolicy.Session{}, fmt.Errorf("gateway: %d live sessions, refusing to issue another", len(m.sessions))
	}
	s.Credential = cred
	m.sessions[cred] = s
	return s, nil
}

// ToolProxyURL returns the proxy URL a run's tool environment carries: the
// gateway address with the session credential the gateway resolves the run from.
// It is empty when the run has no session or no proxy is configured, so a tool
// gets no proxy rather than a bare address the gateway would refuse.
//
// With capture off the address is the operator's global proxy, a plain forwarder
// with no session concept; the credential in the URL is then meaningless and
// ignored, and a socks5 or authenticated exit keeps its own credentials.
func (m *Manager) ToolProxyURL(sess netpolicy.Session) string {
	return netpolicy.ProxyURL(sess, m.ProxyAddr())
}

// RevokeSession ends one session: the credential stops resolving and every
// pooled origin connection is dropped, so a revoke ends the connections that
// session was already using instead of only blocking new requests. The hook
// exposes no per-session drop, so other sessions re-dial once; correctness is
// unaffected because every request is re-authorized.
func (m *Manager) RevokeSession(cred string) {
	if cred == "" {
		return
	}
	m.sessMu.Lock()
	delete(m.sessions, cred)
	m.sessMu.Unlock()
	if m.gw != nil {
		m.gw.CloseIdleConnections()
	}
}

// certException reports whether the operator approved skipping origin
// certificate verification for this session's task and authority. An unknown or
// unreadable exception set is strict: verification stays on.
func (m *Manager) certException(s netpolicy.Session, authority string) bool {
	if s.TaskID <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exceptions, err := m.pg.ListCertExceptions(ctx, s.TaskID)
	if err != nil {
		log.Printf("[gateway] cert exceptions for task %d are unreadable; verification stays strict", s.TaskID)
		return false
	}
	authority = strings.ToLower(strings.TrimSpace(authority))
	for _, e := range exceptions {
		if strings.EqualFold(e.Authority, authority) {
			return true
		}
	}
	return false
}

// enrichSessionPrefix marks the gateway sessions an enrichment probe runs
// under, so maskFor can give them the browser-shaped navigation headers.
const enrichSessionPrefix = "enrich:"

// enrichRoute is the enrichment engine's recorder route: a testing session for
// the task being enriched, the recorder's address and CA, and its revoke. The
// recorder stores each exchange itself, attributed to that task. No recorder,
// no session or no credential means no probe; there is no direct path.
func (m *Manager) enrichRoute(ctx context.Context, taskID int64) (string, string, func(), error) {
	if m.traffic == nil || !m.TrafficEnabled() {
		return "", "", nil, errors.New("traffic capture is off, so there is no recording proxy to probe through")
	}
	s, err := m.IssueSession(ctx, netpolicy.CallerAgent, taskID, 0, netpolicy.PurposeTesting)
	if err != nil {
		return "", "", nil, err
	}
	// The ID is what maskFor reads; the credential is unchanged.
	m.sessMu.Lock()
	s.ID = enrichSessionPrefix + s.ID
	m.sessions[s.Credential] = s
	m.sessMu.Unlock()
	proxy := netpolicy.ProxyURL(s, m.traffic.ProxyAddr())
	if proxy == "" {
		m.RevokeSession(s.Credential)
		return "", "", nil, errors.New("the enrichment session carries no credential")
	}
	return proxy, m.ProxyCACert(), func() { m.RevokeSession(s.Credential) }, nil
}

// maskFor picks the gateway's header masking level for a session: enrichment
// probes get navigation headers; any other session follows its task's speed
// profile, and a session with no task (research, install) gets the default.
func (m *Manager) maskFor(s netpolicy.Session) gateway.MaskLevel {
	if strings.HasPrefix(s.ID, enrichSessionPrefix) {
		return gateway.MaskNavigation
	}
	profile := pgdb.SpeedProfileStandard
	if s.TaskID > 0 {
		profile = m.taskProfile(s.TaskID)
	}
	return maskForProfile(profile)
}

// profileTTL bounds how stale a cached speed profile may be: an operator's
// profile change applies within 5s, and the gateway does not query PostgreSQL per request.
const profileTTL = 5 * time.Second

type profileEntry struct {
	profile string
	expires time.Time
}

// taskProfile returns the task's speed profile from a short-lived cache; a read
// error or missing manager database reads as standard (and is cached briefly too).
func (m *Manager) taskProfile(taskID int64) string {
	now := time.Now()
	m.profMu.Lock()
	if e, ok := m.profCache[taskID]; ok && now.Before(e.expires) {
		m.profMu.Unlock()
		return e.profile
	}
	m.profMu.Unlock()

	read := m.readProfile
	if read == nil && m.pg != nil {
		read = m.pg.TaskSpeedProfileContext
	}
	profile := pgdb.SpeedProfileStandard
	if read != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		p, err := read(ctx, taskID)
		cancel()
		if err == nil {
			profile = p
		}
	}
	m.profMu.Lock()
	defer m.profMu.Unlock()
	// A read that started later must not lose its result to a slower one.
	expires := now.Add(profileTTL)
	if e, ok := m.profCache[taskID]; ok && expires.Before(e.expires) {
		return e.profile
	}
	if m.profCache == nil || len(m.profCache) >= 1024 {
		m.profCache = make(map[int64]profileEntry)
	}
	m.profCache[taskID] = profileEntry{profile, expires}
	return profile
}

// maskForProfile maps a speed profile to its masking level. Unknown values
// read as standard.
func maskForProfile(profile string) gateway.MaskLevel {
	if profile == pgdb.SpeedProfileStealth {
		return gateway.MaskNavigation
	}
	return gateway.MaskUA
}

func (m *Manager) Close() error {
	// Stop enrichment first and OUTSIDE m.mu: a starting probe takes m.mu.RLock
	// in enrichRoute, and Close waits for probes to finish, so holding the lock
	// here would deadlock. It also guarantees no enrichment job is still writing
	// when the database closes below.
	if m.enrich != nil {
		m.enrich.Close()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.traffic != nil {
		m.traffic.Close()
	}
	return m.pg.Close()
}

// isTerminalStatus reports whether a task status is terminal (done/failed/timeout).
// Package-local shim over db.IsTerminal so all server files share one definition.
func isTerminalStatus(status string) bool { return pgdb.IsTerminal(status) }

// unixOrZero returns t's unix seconds, or 0 when the time is nil.
func unixOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

func unixNanoOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixNano()
}

func taskFromPG(pt *pgdb.Task, store *pgdb.ExplorationStore, ic *intercept.Interceptor, assets *pgdb.AssetStore) *Task {
	return &Task{
		ID: strconv.FormatInt(pt.ID, 10), ExpID: pt.ExplorationID,
		Name:       pt.Name,
		CategoryID: cloneInt64Ptr(pt.CategoryID), CategoryName: pt.CategoryName,
		PinnedAt:    unixOrZero(pt.PinnedAt),
		Description: pt.Description, Goal: pt.Goal, CreatedAt: pt.CreatedAt.Unix(), Paused: pt.Paused, Queued: pt.Queued,
		PausedAt: unixOrZero(pt.PausedAt),
		QueuedAt: unixNanoOrZero(pt.QueuedAt), QueueMode: pt.QueueMode,
		CompletedAt: unixOrZero(pt.CompletedAt), Status: pt.Status, ParentRef: pt.ParentRef,
		LLMProfileID:  pt.LLMProfileID,
		LLMProfileIDs: append([]int64(nil), pt.LLMProfileIDs...), ActiveLLMProfileID: pt.ActiveLLMProfileID, LLMRotate: pt.LLMRotate,
		LLMChainRevision: pt.LLMChainRevision,
		LLMFailoverState: pt.LLMFailoverState, LLMFailoverReason: pt.LLMFailoverReason,
		SourceTaskIDs:  append([]int64(nil), pt.SourceTaskIDs...),
		CompanyIDs:     append([]int64(nil), pt.CompanyIDs...),
		TimeoutSeconds: pt.TimeoutSeconds, PlanHeartbeatSeconds: pt.PlanHeartbeatSeconds,
		PlanQuietMode:   pt.PlanQuietMode,
		CoverageEnabled: pt.CoverageEnabled,
		FirstRunAt:      unixOrZero(pt.FirstRunAt), DeadlineAt: unixOrZero(pt.DeadlineAt),
		Store: store, Guard: guard.NewWithInterceptor(ic).WithScope(pgdb.NewTaskScopeChecker(assets, pt.ID)),
		notify: make(chan struct{}, 1),
	}
}

// UpdateTaskMetadata changes list-only task metadata without interrupting any
// planner, main-agent, or worker call.
func (m *Manager) UpdateTaskMetadata(taskID string, patch pgdb.TaskPatch) (*Task, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return nil, nil
	}
	updated, err := m.pg.UpdateTask(id, patch)
	if err != nil || updated == nil {
		return nil, err
	}
	m.mu.RLock()
	task := m.tasks[taskID]
	m.mu.RUnlock()
	if task == nil {
		return nil, nil
	}
	task.updateLifecycle(func(state *taskLifecycleState) {
		state.Name = updated.Name
		state.PinnedAt = unixOrZero(updated.PinnedAt)
	})
	// Live switch (#86): runRound reads the flag per round, so the next
	// planning round (edge or heartbeat) already respects the new value.
	task.PlanQuietMode = updated.PlanQuietMode
	return task, nil
}

// CreateTask creates a task + its exploration and makes it active.
// timeoutSeconds is the task-level wall-clock budget (0 = no time limit).
func (m *Manager) CreateTask(description, goal string, llmProfileID *int64, timeoutSeconds, planHeartbeatSeconds int) (*Task, error) {
	var ids []int64
	if llmProfileID != nil {
		ids = []int64{*llmProfileID}
	}
	return m.CreateTaskWithOptions(description, goal, pgdb.TaskCreateOptions{
		LLMProfileIDs: ids, TimeoutSeconds: timeoutSeconds, PlanHeartbeatSeconds: planHeartbeatSeconds,
	})
}

func (m *Manager) CreateTaskWithOptions(description, goal string, opts pgdb.TaskCreateOptions) (*Task, error) {
	if len(opts.CompanyIDs) > 0 {
		m.companyMu.Lock()
		defer m.companyMu.Unlock()
	}
	pt, err := m.pg.CreateTaskWithOptions(description, goal, opts)
	if err != nil {
		return nil, err
	}
	t := taskFromPG(pt, m.pg.Exploration(pt.ExplorationID), m.interceptor, m.assets)
	m.mu.Lock()
	m.tasks[t.ID] = t
	m.active = t.ID
	m.mu.Unlock()
	return t, nil
}

// RenameTaskCategory persists a category name and refreshes every live task DTO
// that references it. taskStateMu keeps this ordered with task reassignment.
func (m *Manager) RenameTaskCategory(id int64, name string) (*pgdb.TaskCategory, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	category, err := m.pg.RenameTaskCategory(id, name)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, task := range m.tasks {
		task.updateLifecycle(func(state *taskLifecycleState) {
			if state.CategoryID != nil && *state.CategoryID == id {
				state.CategoryName = category.Name
			}
		})
	}
	return category, nil
}

// DeleteTaskCategory moves all affected live tasks to the uncategorized bucket.
func (m *Manager) DeleteTaskCategory(id int64) (bool, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	deleted, err := m.pg.DeleteTaskCategory(id)
	if err != nil || !deleted {
		return deleted, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, task := range m.tasks {
		task.updateLifecycle(func(state *taskLifecycleState) {
			if state.CategoryID != nil && *state.CategoryID == id {
				state.CategoryID = nil
				state.CategoryName = ""
			}
		})
	}
	return true, nil
}

// SetTaskCategory updates one live task without interrupting its runtime.
func (m *Manager) SetTaskCategory(taskID string, categoryID *int64) (*pgdb.TaskCategory, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return nil, pgdb.ErrTaskCategoryTaskNotFound
	}
	category, err := m.pg.SetTaskCategory(id, categoryID)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	task := m.tasks[taskID]
	m.mu.RUnlock()
	if task != nil {
		task.updateLifecycle(func(state *taskLifecycleState) {
			state.CategoryID = cloneInt64Ptr(categoryID)
			state.CategoryName = ""
			if category != nil {
				state.CategoryName = category.Name
			}
		})
	}
	return category, nil
}

// SetTasksCategory applies one category change to several tasks at once. The
// database write and the in-memory refresh share taskStateMu, so a concurrent
// single-task update cannot interleave and leave a live DTO stale. The returned
// set holds the ids that were actually moved; callers report the rest as gone.
func (m *Manager) SetTasksCategory(taskIDs []string, categoryID *int64) (map[string]bool, *pgdb.TaskCategory, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	numeric := make([]int64, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		id, err := strconv.ParseInt(taskID, 10, 64)
		if err != nil || id <= 0 {
			return nil, nil, pgdb.ErrTaskCategoryTaskNotFound
		}
		numeric = append(numeric, id)
	}
	updatedIDs, category, err := m.pg.SetTasksCategory(numeric, categoryID)
	if err != nil {
		return nil, nil, err
	}
	categoryName := ""
	if category != nil {
		categoryName = category.Name
	}
	updated := make(map[string]bool, len(updatedIDs))
	m.mu.RLock()
	tasks := make([]*Task, 0, len(updatedIDs))
	for _, id := range updatedIDs {
		taskID := strconv.FormatInt(id, 10)
		updated[taskID] = true
		if task := m.tasks[taskID]; task != nil {
			tasks = append(tasks, task)
		}
	}
	m.mu.RUnlock()
	for _, task := range tasks {
		task.updateLifecycle(func(state *taskLifecycleState) {
			state.CategoryID = cloneInt64Ptr(categoryID)
			state.CategoryName = categoryName
		})
	}
	return updated, category, nil
}

// DeleteCompanyWithAssets keeps the database cascade and live task handles in
// one manager-level critical section. This closes the gap where a task could
// commit its company scope immediately before registration and miss the
// post-delete in-memory sweep.
func (m *Manager) DeleteCompanyWithAssets(id int64, deleteAssets bool) (int64, error) {
	m.companyMu.Lock()
	defer m.companyMu.Unlock()
	assetsDeleted, err := m.pg.Companies().DeleteCompanyWithAssets(id, deleteAssets)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	for _, task := range m.tasks {
		task.updateLifecycle(func(state *taskLifecycleState) {
			companyIDs := make([]int64, 0, len(state.CompanyIDs))
			for _, companyID := range state.CompanyIDs {
				if companyID != id {
					companyIDs = append(companyIDs, companyID)
				}
			}
			state.CompanyIDs = companyIDs
		})
	}
	m.mu.Unlock()
	return assetsDeleted, nil
}

// ReplaceTaskLLMProfiles resets a task's ordered provider chain and mirrors the
// committed state onto the live task handle. Terminal tasks are editable too —
// their main Agent conversation keeps running on the chain after the task finishes.
func (m *Manager) ReplaceTaskLLMProfiles(id string, profileIDs []int64, activeProfileID int64) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return 0, err
	}
	if err := m.pg.ReplaceTaskLLMProfiles(n, profileIDs, activeProfileID); err != nil {
		return 0, err
	}
	pt, err := m.pg.GetTask(n)
	if err != nil || pt == nil {
		return 0, err
	}
	m.mu.Lock()
	if task := m.tasks[id]; task != nil {
		task.setLLMState(pt.LLMProfileID, pt.ActiveLLMProfileID, pt.LLMProfileIDs, pt.LLMChainRevision, pt.LLMFailoverState, pt.LLMFailoverReason)
	}
	m.mu.Unlock()
	// Terminal-state tasks do not reopen quota-blocked intents: the task no longer has a worker running, so reopening it would only move it from
	// blocked moved to open——there nobody executes it, and it no longer meets the rerunnable conditions of "rerun intent",
	// To run a terminal-state task again, use the rerun intent or add a new goal. That path re-queues the task.
	// admit back into the running state.
	if pgdb.IsTerminal(pt.Status) {
		return 0, nil
	}
	if task, ok := m.Task(id); ok {
		var reopened int64
		for _, reason := range []string{pgdb.IntentBlockedLLMQuota, pgdb.IntentBlockedLLMRefused} {
			n, reopenErr := task.Store.ReopenIntentsByBlockedReason(reason)
			if reopenErr != nil {
				return reopened + n, reopenErr
			}
			reopened += n
		}
		return reopened, nil
	}
	return 0, nil
}

// LoadExisting rebuilds in-memory task handles from the PG task registry.
func (m *Manager) LoadExisting() []*Task {
	pts, err := m.pg.ListTasks()
	if err != nil {
		log.Printf("[manager] reload: %v", err)
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var loaded []*Task
	for _, pt := range pts {
		id := strconv.FormatInt(pt.ID, 10)
		if _, ok := m.tasks[id]; ok {
			continue
		}
		t := taskFromPG(pt, m.pg.Exploration(pt.ExplorationID), m.interceptor, m.assets)
		m.tasks[id] = t
		loaded = append(loaded, t)
	}
	if m.active == "" {
		var newest *Task
		for _, t := range m.tasks {
			if newest == nil || t.CreatedAt > newest.CreatedAt {
				newest = t
			}
		}
		if newest != nil {
			m.active = newest.ID
		}
	}
	if len(loaded) > 0 {
		log.Printf("[manager] reloaded %d task(s) from PG", len(loaded))
	}
	return loaded
}

// SetTaskPaused persists a task's paused state.
func (m *Manager) SetTaskPaused(id string, paused bool) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	if err := m.pg.SetPaused(n, paused); err != nil {
		return err
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Paused = paused
		})
	}
	m.mu.Unlock()
	return nil
}

// ApplyTaskAdmission atomically commits the lifecycle fields controlled by the
// concurrency scheduler. Keeping status, paused and queue metadata in one UPDATE
// prevents a failed resume from leaving a task half-revived (for example running
// but still user-paused, or dequeued without an Engine start).
//
// preservePosition applies only when the row is already queued. A repeated
// admission keeps its FIFO timestamp; a task that was explicitly paused and is
// now re-queued receives a fresh tail position.
func (m *Manager) ApplyTaskAdmission(id, expectedStatus, status string, queued bool, mode string, preservePosition bool) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	if queued {
		if mode != "bootstrap" && mode != "resume" {
			return fmt.Errorf("invalid queue mode %q", mode)
		}
	} else {
		mode = ""
	}

	var queuedAt, completedAt, firstRunAt, deadlineAt sql.NullTime
	var committedMode string
	err = m.pg.QueryRow(`UPDATE tasks
	SET status=$2,
	    completed_at=CASE
	        WHEN $2 IN ('done','failed','timeout') THEN COALESCE(completed_at, now())
	        ELSE NULL
	    END,
	    paused=false,
	    -- Admission into any other status answers the block, so the reason must
	    -- not survive it and label a task that is running again.
	    blocked_reason=CASE WHEN $2='needs_operator' THEN blocked_reason ELSE '' END,
	    queued=$3,
	    queued_at=CASE
	        WHEN NOT $3 THEN NULL
	        WHEN $5 AND queued THEN COALESCE(queued_at, now())
	        ELSE now()
	    END,
	    queue_mode=CASE
	        WHEN NOT $3 THEN ''
	        WHEN ($5 AND queued AND queue_mode='bootstrap') OR $4='bootstrap' THEN 'bootstrap'
	        ELSE 'resume'
	    END,
	    first_run_at=CASE
	        WHEN $6='timeout' AND $2 NOT IN ('done','failed','timeout') THEN NULL
	        ELSE first_run_at
	    END,
	    deadline_at=CASE
	        WHEN $6='timeout' AND $2 NOT IN ('done','failed','timeout') THEN NULL
	        WHEN paused_at IS NOT NULL AND deadline_at IS NOT NULL THEN deadline_at + (now() - paused_at)
	        ELSE deadline_at
	    END,
	    paused_at=NULL
	WHERE id=$1 AND deleted_at IS NULL AND status=$6
	RETURNING queued_at, queue_mode, completed_at, first_run_at, deadline_at`, n, status, queued, mode, preservePosition, expectedStatus).
		Scan(&queuedAt, &committedMode, &completedAt, &firstRunAt, &deadlineAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("task %s lifecycle changed before admission (expected status %q)", id, expectedStatus)
	}
	if err != nil {
		return err
	}

	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Status = status
			state.Paused = false
			state.PausedAt = 0
			state.Queued = queued
			state.QueueMode = committedMode
			state.QueuedAt = 0
			if queuedAt.Valid {
				state.QueuedAt = queuedAt.Time.UnixNano()
			}
			state.CompletedAt = 0
			if completedAt.Valid {
				state.CompletedAt = completedAt.Time.Unix()
			}
			state.FirstRunAt = 0
			if firstRunAt.Valid {
				state.FirstRunAt = firstRunAt.Time.Unix()
			}
			state.DeadlineAt = 0
			if deadlineAt.Valid {
				state.DeadlineAt = deadlineAt.Time.Unix()
			}
		})
	}
	m.mu.Unlock()
	return nil
}

// ApplyTaskPause atomically removes a task from the admission queue and records
// the user pause. queue_mode is intentionally retained so resuming a never-run
// bootstrap task still performs goal decomposition, but the next enqueue receives
// a new queued_at timestamp and therefore moves to the FIFO tail.
func (m *Manager) ApplyTaskPause(id string) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	var mode string
	var pausedAt sql.NullTime
	err = m.pg.QueryRow(`UPDATE tasks
		SET paused=true, paused_at=COALESCE(paused_at, now()), queued=false, queued_at=NULL
		WHERE id=$1 AND deleted_at IS NULL AND paused=false
		  AND status NOT IN ('done','failed','timeout')
		RETURNING COALESCE(queue_mode,''), paused_at`, n).Scan(&mode, &pausedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("task %s is unavailable for pause", id)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Paused = true
			if pausedAt.Valid {
				state.PausedAt = pausedAt.Time.Unix()
			}
			state.Queued = false
			state.QueuedAt = 0
			state.QueueMode = mode
		})
	}
	m.mu.Unlock()
	return nil
}

// EnqueueTask persists the concurrency hold and syncs the in-memory handle.
func (m *Manager) EnqueueTask(id, mode string) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	if mode != "bootstrap" && mode != "resume" {
		return fmt.Errorf("invalid queue mode %q", mode)
	}
	var queuedAt time.Time
	var committedMode string
	err = m.pg.QueryRow(`UPDATE tasks
		SET queued=true,
		    queued_at=CASE WHEN queued THEN COALESCE(queued_at, now()) ELSE now() END,
		    queue_mode=CASE
		        WHEN queue_mode='bootstrap' OR $2='bootstrap' THEN 'bootstrap'
		        ELSE 'resume'
		    END
		WHERE id=$1 AND deleted_at IS NULL
		RETURNING queued_at, queue_mode`, n, mode).Scan(&queuedAt, &committedMode)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("task %s is unavailable for enqueue", id)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.QueuedAt = queuedAt.UnixNano()
			state.Queued = true
			state.QueueMode = committedMode
		})
	}
	m.mu.Unlock()
	return nil
}

// DequeueTask removes the concurrency hold. clearMode=false is used when a user
// pauses a queued task so a later resume still knows whether bootstrap is needed.
func (m *Manager) DequeueTask(id string, clearMode bool) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	if err := m.pg.Dequeue(n, clearMode); err != nil {
		return err
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Queued = false
			state.QueuedAt = 0
			if clearMode {
				state.QueueMode = ""
			}
		})
	}
	m.mu.Unlock()
	return nil
}

// TaskStatus returns a task's current in-memory status (empty if unknown).
func (m *Manager) TaskStatus(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t := m.tasks[id]; t != nil {
		return t.lifecycleSnapshot().Status
	}
	return ""
}

// StampTaskFirstRun stamps first_run_at + deadline_at on the first real run (idempotent
// in DB) and mirrors deadline_at on the live handle. Returns the deadline unix (0 = no limit).
func (m *Manager) StampTaskFirstRun(id string) (int64, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return 0, err
	}
	m.mu.RLock()
	timeout := 0
	if t := m.tasks[id]; t != nil {
		timeout = t.TimeoutSeconds
	}
	m.mu.RUnlock()
	dl, err := m.pg.StampFirstRun(n, timeout)
	if err != nil {
		return 0, err
	}
	var dlUnix int64
	if dl != nil {
		dlUnix = dl.Unix()
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			if state.FirstRunAt == 0 {
				state.FirstRunAt = time.Now().Unix()
			}
			state.DeadlineAt = dlUnix
		})
	}
	m.mu.Unlock()
	return dlUnix, nil
}

// SetTaskStatusGuarded sets a TERMINAL status only if the task isn't already terminal
// (resolves the completed↔timeout race — first terminal writer wins). Reflects the
// won status on the live handle. won=false means another terminal already stuck.
func (m *Manager) SetTaskStatusGuarded(id, status string) (won bool, err error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return false, err
	}
	won, err = m.pg.SetTerminalStatusGuarded(n, status)
	if err != nil || !won {
		return won, err
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Status = status
			if state.CompletedAt == 0 {
				state.CompletedAt = time.Now().Unix()
			}
		})
	}
	m.mu.Unlock()
	// Hints are consumed only on a successful finish: failed and timeout tasks
	// can be revived (addGoal → reviveTask) and must resume with the operator's
	// standing guidance.
	if status == "done" {
		m.consumeActiveHints(id)
	}
	m.extractLessons(n)
	m.deriveTaskReflections(n)
	return true, nil
}

// SetTaskStatus persists a task's lifecycle status (e.g. "done") and reflects it
// on the in-memory handle so the derived DTO status shows it without a reload.
func (m *Manager) SetTaskStatus(id, status string) error {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}
	if err := m.pg.SetStatus(n, status); err != nil {
		return err
	}
	m.mu.Lock()
	if t := m.tasks[id]; t != nil {
		t.updateLifecycle(func(state *taskLifecycleState) {
			state.Status = status
			// Mirror the DB's completed_at stamp on the live handle so the DTO shows
			// the finish time without a reload (terminal -> stamp once; else clear).
			if pgdb.IsTerminal(status) {
				if state.CompletedAt == 0 {
					state.CompletedAt = time.Now().Unix()
				}
			} else {
				state.CompletedAt = 0
			}
		})
	}
	m.mu.Unlock()
	if pgdb.IsTerminal(status) {
		if status == "done" {
			m.consumeActiveHints(id)
		}
		m.extractLessons(n)
		m.deriveTaskReflections(n)
	}
	return nil
}

// consumeActiveHints retires every still-active hint once the task finishes
// successfully: a done engagement has no planner left to read them, and a later
// revival must not replay guidance from the previous run. Failed and timeout
// tasks are excluded because they can be revived and must keep the guidance.
func (m *Manager) consumeActiveHints(id string) {
	m.mu.RLock()
	t := m.tasks[id]
	m.mu.RUnlock()
	if t == nil || t.Store == nil {
		return
	}
	hints, err := t.Store.ListByKindState(pgdb.KindHint, "active", 0)
	if err != nil {
		log.Printf("[hints] task %s: could not list active hints for terminal wrap-up: %v", id, err)
		return
	}
	for _, h := range hints {
		if err := t.Store.SetNodeState(h.ID, "consumed"); err != nil {
			log.Printf("[hints] task %s: could not consume hint %d: %v", id, h.ID, err)
		}
	}
}

// extractLessons derives RSI candidate lessons from a task that just reached a
// terminal status. It is best-effort: a lesson failure must never fail a status
// update. The extraction is idempotent (evidence unique key), so a restart or a
// manual backfill cannot inflate support.
func (m *Manager) extractLessons(taskID int64) {
	if _, err := m.pg.ExtractLessonsForTask(context.Background(), taskID); err != nil {
		log.Printf("[rsi] lesson extraction failed for task %d: %v", taskID, err)
	}
}

// deriveTaskReflections records the deterministic end-of-task reflections
// (noise, learning, lookfor) next to lesson extraction. Best-effort like it:
// bounded to 5s, log-only, never fails or delays the status update beyond the
// budget.
func (m *Manager) deriveTaskReflections(taskID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.pg.DeriveTaskReflections(ctx, taskID); err != nil {
		log.Printf("[memory] task reflection derivation failed for task %d: %v", taskID, err)
	}
}

// DeleteTask removes a task and optionally its related global data. Traffic is
// selected by task_id, the ownership the recorder wrote with each exchange, so a
// task delete never removes another run's exchanges or unattributed history,
// even when they share a host. Files are staged before the database operation;
// traffic is staged while PostgreSQL excludes asset/anchor writers. Both are
// restored on a database failure and purged only after its commit.
func (m *Manager) DeleteTask(id string, opts DeleteTaskOptions) (DeleteTaskResult, error) {
	result := DeleteTaskResult{Deleted: id}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return result, err
	}
	registered, err := m.pg.GetTask(n)
	if err != nil {
		return result, err
	}
	if registered == nil {
		m.forgetTask(id, n)
		return result, nil
	}

	var fileStage *taskFileDeleteStage
	if opts.DeleteFiles {
		fileStage, err = stageTaskFiles(m.dir, id, registered.ExplorationID)
		if err != nil {
			return result, err
		}
		result.FilesDeleted = fileStage.deleted
	}

	var trafficStage *traffic.HostDeleteStage
	var prepare func(pgdb.TaskDeletePreparation) error
	if opts.DeleteTraffic && m.traffic != nil {
		// Unconditional: ownership is the task id, not an asset-derived host
		// list, so a run that captured traffic at a host with no registered
		// asset is still cleaned up.
		prepare = func(pgdb.TaskDeletePreparation) error {
			trafficStage, err = m.traffic.StageDeleteTask(n)
			if err != nil {
				return err
			}
			result.TrafficDeleted = trafficStage.Deleted()
			return nil
		}
	}

	dbResult, err := m.pg.DeleteTaskCascadePrepared(
		n, opts.DeleteAssets, opts.DeleteFindings, opts.DeleteLLMRecords, prepare,
	)
	if err != nil {
		return result, rollbackTaskDelete(err, trafficStage, fileStage)
	}
	result.AssetsDeleted = dbResult.AssetsDeleted
	result.AssetsDetached = dbResult.AssetsDetached
	result.FindingsDeleted = dbResult.FindingsDeleted
	result.LLMRecordsDeleted = dbResult.LLMRecordsDeleted

	// PostgreSQL is now authoritative: finalize the staged external deletion and
	// forget the live task even if a final purge reports an error. Such errors are
	// typed so the HTTP layer can still tear down the task runtime instead of
	// incorrectly reviving a task whose database row is already gone.
	var finalizeErrs []error
	if trafficStage != nil {
		if err := trafficStage.Commit(); err != nil {
			finalizeErrs = append(finalizeErrs, fmt.Errorf("finalize traffic deletion: %w", err))
		}
	}
	if fileStage != nil {
		if err := fileStage.commit(); err != nil {
			finalizeErrs = append(finalizeErrs, fmt.Errorf("finalize task file deletion: %w", err))
		}
	}
	m.forgetTask(id, n)
	if err := errors.Join(finalizeErrs...); err != nil {
		return result, &taskDeleteCommittedError{err: err}
	}
	return result, nil
}

// taskDeleteCommittedError means PostgreSQL deletion succeeded but purging one
// of the recoverable staging directories failed. The task must stay deleted.
type taskDeleteCommittedError struct{ err error }

func (e *taskDeleteCommittedError) Error() string {
	return "task deletion committed; external cleanup incomplete: " + e.err.Error()
}

func (e *taskDeleteCommittedError) Unwrap() error { return e.err }

func rollbackTaskDelete(cause error, trafficStage *traffic.HostDeleteStage, fileStage *taskFileDeleteStage) error {
	errs := []error{cause}
	// Reverse the preparation order. Both restorations are attempted even if the
	// first one fails, and errors.Join preserves the original PostgreSQL error.
	if trafficStage != nil {
		if err := trafficStage.Rollback(); err != nil {
			errs = append(errs, fmt.Errorf("restore traffic after task delete failure: %w", err))
		}
	}
	if fileStage != nil {
		if err := fileStage.rollback(); err != nil {
			errs = append(errs, fmt.Errorf("restore task files after task delete failure: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) forgetTask(id string, numericID int64) {
	m.mu.Lock()
	delete(m.tasks, id)
	for _, task := range m.tasks {
		task.updateLifecycle(func(state *taskLifecycleState) {
			kept := make([]int64, 0, len(state.SourceTaskIDs))
			for _, sourceID := range state.SourceTaskIDs {
				if sourceID != numericID {
					kept = append(kept, sourceID)
				}
			}
			state.SourceTaskIDs = kept
		})
	}
	if m.active == id {
		m.active = ""
		for _, t := range m.tasks {
			m.active = t.ID
			break
		}
	}
	m.mu.Unlock()
}

type stagedTaskPath struct {
	source string
	staged string
}

type taskFileDeleteStage struct {
	stageDir string
	moves    []stagedTaskPath
	deleted  bool
	done     bool
}

// stageTaskFiles atomically renames the task workspace and owned transcripts to
// a same-filesystem staging directory. The trailing dash in the transcript
// prefix is significant: exploration 12 must not match exploration 123.
func stageTaskFiles(dataDir, taskID string, explorationID int64) (*taskFileDeleteStage, error) {
	stage := &taskFileDeleteStage{}
	var targets []string
	taskDir := filepath.Join(dataDir, "tasks", taskID)
	if _, err := os.Lstat(taskDir); err == nil {
		targets = append(targets, taskDir)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	transcriptDir := filepath.Join(dataDir, "transcripts")
	entries, err := os.ReadDir(transcriptDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		entries = nil
	}
	prefix := fmt.Sprintf("exp%d-", explorationID)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || (!entry.IsDir() && !strings.HasSuffix(name, ".jsonl")) {
			continue
		}
		targets = append(targets, filepath.Join(transcriptDir, name))
	}
	if len(targets) == 0 {
		stage.done = true
		return stage, nil
	}

	parent := filepath.Join(dataDir, ".delete-staging")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	stage.stageDir, err = os.MkdirTemp(parent, "task-"+taskID+"-")
	if err != nil {
		return nil, err
	}
	for _, source := range targets {
		staged := filepath.Join(stage.stageDir, fmt.Sprintf("%d-%s", len(stage.moves), filepath.Base(source)))
		if err := os.Rename(source, staged); err != nil {
			cause := fmt.Errorf("stage task file %s: %w", source, err)
			if restoreErr := stage.rollback(); restoreErr != nil {
				return nil, errors.Join(cause, fmt.Errorf("restore partially staged task files: %w", restoreErr))
			}
			return nil, cause
		}
		stage.moves = append(stage.moves, stagedTaskPath{source: source, staged: staged})
	}
	stage.deleted = true
	return stage, nil
}

func (s *taskFileDeleteStage) commit() error {
	if s == nil || s.done {
		return nil
	}
	err := os.RemoveAll(s.stageDir)
	s.done = true
	return err
}

func (s *taskFileDeleteStage) rollback() error {
	if s == nil || s.done {
		return nil
	}
	var errs []error
	for i := len(s.moves) - 1; i >= 0; i-- {
		move := s.moves[i]
		if _, err := os.Lstat(move.source); err == nil {
			errs = append(errs, fmt.Errorf("restore destination already exists: %s", move.source))
			continue
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("inspect restore destination %s: %w", move.source, err))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(move.source), 0o755); err != nil {
			errs = append(errs, fmt.Errorf("create restore parent for %s: %w", move.source, err))
			continue
		}
		if err := os.Rename(move.staged, move.source); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", move.source, err))
		}
	}
	if len(errs) == 0 && s.stageDir != "" {
		if err := os.RemoveAll(s.stageDir); err != nil {
			errs = append(errs, fmt.Errorf("remove task file stage: %w", err))
		}
	}
	s.done = true
	return errors.Join(errs...)
}

// deleteTaskFiles retains the standalone helper contract used by focused tests.
func deleteTaskFiles(dataDir, taskID string, explorationID int64) (bool, error) {
	stage, err := stageTaskFiles(dataDir, taskID, explorationID)
	if err != nil {
		return false, err
	}
	deleted := stage.deleted
	if err := stage.commit(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (m *Manager) Task(id string) (*Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	return t, ok
}

// ActiveTask returns the currently active task (or nil).
func (m *Manager) ActiveTask() *Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == "" {
		return nil
	}
	return m.tasks[m.active]
}

// SetActive switches the active task. Returns false if the id is unknown.
func (m *Manager) SetActive(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tasks[id]; !ok {
		return false
	}
	m.active = id
	return true
}

func (m *Manager) ResolveTask(id string) *Task {
	if id == "" || id == "active" {
		return m.ActiveTask()
	}
	t, _ := m.Task(id)
	return t
}

func (m *Manager) List() []*Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		out = append(out, t)
	}
	// Pinned tasks come first, ordered by pin time descending within the group; regular tasks are ordered by id descending. m.tasks is a map,
	// so it must be re-sorted on every poll, and id provides a stable, unique fallback order for tasks created at the same moment.
	sort.Slice(out, func(i, j int) bool {
		iState := out[i].lifecycleSnapshot()
		jState := out[j].lifecycleSnapshot()
		if (iState.PinnedAt > 0) != (jState.PinnedAt > 0) {
			return iState.PinnedAt > 0
		}
		if iState.PinnedAt != jState.PinnedAt {
			return iState.PinnedAt > jState.PinnedAt
		}
		ai, _ := strconv.ParseInt(out[i].ID, 10, 64)
		aj, _ := strconv.ParseInt(out[j].ID, 10, 64)
		return ai > aj
	})
	return out
}

// Notify signals that the asset/exploration graph changed (debounced consumer
// wakes the planner). Non-blocking.
func (t *Task) Notify() {
	select {
	case t.notify <- struct{}{}:
	default:
	}
}

// NotifyDone is Notify plus a hint: a worker just finished intentID and that is
// what triggered this wake-up. The planner reads the accumulated triggers next
// round so it can spell out which intent finished (+ its output). Events pile up
// (debounce) until the round drains them via drainTriggers.
func (t *Task) NotifyDone(intentID int64) {
	if intentID > 0 {
		t.trigMu.Lock()
		t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "done", IntentID: intentID})
		t.trigMu.Unlock()
	}
	t.Notify()
}

// NotifyFinding records that a worker reported a finding on intentID (summary),
// then wakes the planner — so the round spells out which intent found what.
func (t *Task) NotifyFinding(intentID int64, summary string) {
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "finding", IntentID: intentID, Detail: summary})
	t.trigMu.Unlock()
	t.Notify()
}

// NotifyGoal records that one OR MORE goals were added in a single set_goals call —
// by the human via the main agent — then wakes the planner, so the next round spells
// out "the human added N goal(s): …" instead of the planner having to spot new open goals in
// the overview. One call → one trigger event (a batch from set_goals counts as one, not one per goal, to avoid flooding).
// The event survives an early-returning terminal round (drain happens after the gate),
// so a set_goals that revives a done task still surfaces it once the task is running.
func (t *Task) NotifyGoal(texts []string) {
	if len(texts) == 0 {
		return
	}
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "goal", Goals: texts})
	t.trigMu.Unlock()
	t.Notify()
}

// NotifyHint records that one OR MORE hints were added in a single add_hint call —
// by the human via the main agent, or by cross-task orchestration — then wakes the
// planner, so the next round is told "the human added N strategy hint(s): …" and looks at them
// directly instead of having to spot the new hint folded into the graph overview.
// One call → one trigger event (a batched add_hint counts as one, not one per hint).
func (t *Task) NotifyHint(texts []string) {
	if len(texts) == 0 {
		return
	}
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "hint", Hints: texts})
	t.trigMu.Unlock()
	t.Notify()
}

// NotifyChurn records that one asset accumulated enough exhausted intents, then
// wakes the planner so the round tells it to change technique or deprioritise
// the asset instead of re-issuing a variant. One trigger per asset per task.
func (t *Task) NotifyChurn(assetID int64, count int) {
	if assetID <= 0 || count <= 0 {
		return
	}
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "churn", AssetID: assetID, Count: count})
	t.trigMu.Unlock()
	t.Notify()
}

// markChurnFired claims the one churn trigger allowed per asset and reports
// whether this caller won it.
func (t *Task) markChurnFired(assetID int64) bool {
	t.trigMu.Lock()
	defer t.trigMu.Unlock()
	if t.churnFired == nil {
		t.churnFired = map[int64]bool{}
	}
	if t.churnFired[assetID] {
		return false
	}
	t.churnFired[assetID] = true
	return true
}

// NotifyGoalDeleted records that the human deleted a goal (via the goal management in the overview), then
// wakes the planner so the next round spells out which goal was removed. The event
// survives an early-returning terminal round (drain happens after the gate).
func (t *Task) NotifyGoalDeleted(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "goal_deleted", Detail: text})
	t.trigMu.Unlock()
	t.Notify()
}

// NotifyGoalEdited records that the human edited a goal (via the goal management in the Overview), then wakes
// the planner so the next round spells out the old→new change. The event survives an
// early-returning terminal round (drain happens after the gate).
func (t *Task) NotifyGoalEdited(oldText, newText string) {
	oldText, newText = strings.TrimSpace(oldText), strings.TrimSpace(newText)
	if newText == "" {
		return
	}
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "goal_edited", OldGoal: oldText, NewGoal: newText})
	t.trigMu.Unlock()
	t.Notify()
}

// NotifyCancelled records that the human deleted intentID (reason = deletion reason), then
// wakes the planner so the next round spells out which intent was removed and why.
// summary is the intent's text captured before deletion — needed for hard delete,
// where the node is gone by the time the planner reads the trigger. Applies to both
// soft (state='deleted') and hard (physical cascade) delete.
func (t *Task) NotifyCancelled(intentID int64, summary, reason string) {
	if intentID > 0 {
		t.trigMu.Lock()
		t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "cancelled", IntentID: intentID, Summary: summary, Detail: reason})
		t.trigMu.Unlock()
	}
	t.Notify()
}

// discardTriggersExceptChurn drops the accumulated triggers of a skipped round
// but keeps churn events: markChurnFired already spent their one-shot claim, so
// discarding one here would lose it for the rest of the task.
func (t *Task) discardTriggersExceptChurn() {
	t.trigMu.Lock()
	defer t.trigMu.Unlock()
	kept := t.pendingTriggers[:0]
	for _, ev := range t.pendingTriggers {
		if ev.Kind == "churn" {
			kept = append(kept, ev)
		}
	}
	t.pendingTriggers = kept
}

// drainTriggers returns and clears the trigger events accumulated since the last round.
func (t *Task) drainTriggers() []agent.TriggerEvent {
	t.trigMu.Lock()
	defer t.trigMu.Unlock()
	ev := t.pendingTriggers
	t.pendingTriggers = nil
	return ev
}

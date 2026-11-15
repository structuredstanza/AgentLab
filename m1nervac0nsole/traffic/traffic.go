// Package traffic implements the request-recording subsystem (docs §10): an
// embedded go-mitmproxy proxy whose addon writes every target HTTP exchange into
// a human-browsable file tree, with a sidecar SQLite index for paged queries.
// Full capture, plaintext (no redaction), target HTTP only; the gateway's own
// Proxy-Authorization header is the one thing not recorded.
package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/norma/permission"
	actool "github.com/structuredstanza/norma/tool"
	_ "modernc.org/sqlite"
)

const indexSchema = `
CREATE TABLE IF NOT EXISTS exchanges (
  id           TEXT PRIMARY KEY,
  ts           INTEGER,
  host         TEXT,
  method       TEXT,
  url_template TEXT,
  url          TEXT,
  status       INTEGER,
  content_type TEXT,
  req_len      INTEGER,
  resp_len     INTEGER,
  path         TEXT,
  task_id      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ex_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_ex_tmpl ON exchanges(host, url_template);
CREATE INDEX IF NOT EXISTS idx_ex_ts   ON exchanges(ts);
CREATE INDEX IF NOT EXISTS idx_ex_status ON exchanges(status);
CREATE INDEX IF NOT EXISTS idx_ex_resp   ON exchanges(resp_len);

CREATE TABLE IF NOT EXISTS exchange_bodies (
  id        TEXT PRIMARY KEY,
  req_head  TEXT NOT NULL DEFAULT '',
  req_body  BLOB,
  req_blob  TEXT,
  resp_head TEXT NOT NULL DEFAULT '',
  resp_body BLOB,
  resp_blob TEXT
);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash        TEXT NOT NULL,
  exchange_id TEXT NOT NULL,
  PRIMARY KEY (hash, exchange_id)
);
CREATE INDEX IF NOT EXISTS idx_blob_refs_ex ON blob_refs(exchange_id);
`

// ftsSchema is applied separately from indexSchema: a driver build without FTS5
// must degrade to "no full-text search" rather than take the whole recorder down.
// trigram (not the default unicode61) is required for two reasons this subsystem
// depends on: it matches arbitrary substrings — "ssw0r" finds "P@ssw0rd" — and it
// handles CJK, which unicode61 does not tokenize. Contentless (content=”) keeps
// only the index, since the text itself lives in exchange_bodies; contentless_delete
// lets rows be deleted without replaying the original text back in.
const ftsSchema = `CREATE VIRTUAL TABLE IF NOT EXISTS ex_fts USING fts5(
  content, tokenize='trigram', content='', contentless_delete=1
);`

const (
	// maxInlineBody is the cutoff between a body stored inline (SQLite column) and
	// one spilled to the content-addressed blob store.
	maxInlineBody = 256 * 1024
	// blobPreview is how much of a spilled body stays inline so readers can tell
	// what it is (JSON shape, SQL dump header, ZIP magic) without fetching it.
	blobPreview = 8 * 1024
	// maxIndexBody caps a single body's contribution to the full-text index. Text
	// is indexed in full below this; binary never reaches the index at all.
	maxIndexBody = 4 * 1024 * 1024
	// minTrigram is the shortest term the trigram tokenizer can match; shorter
	// queries fall back to metadata LIKE.
	minTrigram = 3
	// maxBlobRead caps one traffic_blob read so paging through a large body never
	// floods the agent's context.
	maxBlobRead = 8 * 1024
	// autoVacuumIncremental is SQLite's numeric value for auto_vacuum=incremental.
	autoVacuumIncremental = 2
	// reclaimChunkPages bounds how much index space one locked step returns to the
	// filesystem (pages are 4KiB, so ~32MB). Reclamation holds the write lock, and
	// record() runs before go-mitmproxy replies to the client, so an unbounded
	// pass would stall the very requests being recorded.
	reclaimChunkPages = 8192
	// reclaimMergePages bounds the full-text merge done alongside each chunk.
	// Deleting from a contentless_delete index only writes tombstones; merging is
	// what discards them, and left undone the index grows on every deletion.
	reclaimMergePages = 256
	// reclaimMergeSteps bounds how many merges one reclamation performs. fts5
	// offers no way to ask whether an index has settled — its special INSERT
	// registers a row change of its own, so change counting cannot tell a real
	// merge from a no-op — so the budget is simply spent down, and whatever is
	// left over falls to the next deletion.
	reclaimMergeSteps = 16
	// reclaimMaxSteps backstops the loop. Both merging and incremental_vacuum are
	// documented to stop making progress eventually, but a reclamation that cannot
	// converge must give up rather than spin holding the write lock.
	reclaimMaxSteps = 512
	// reclaimBudget caps one background reclamation. Deleting a busy host can free
	// gigabytes, and the next deletion resumes wherever this one stopped.
	reclaimBudget = 5 * time.Minute
	// maxStreamEvents caps what a streamed flow retains in memory. That is the
	// live view only: the cap keeps a long SSE stream or WebSocket from growing
	// without bound, while the client still receives every byte and Dropped
	// counts the rest. What is persisted is spooled to disk instead, so this
	// never bounds a stored body.
	maxStreamEvents = 256
	// streamCheckBytes is how much the store spools between free-space checks. The
	// check is a statfs, so it runs per MiB of store-wide writes rather than per
	// 32 KiB read; a body that ends mid-interval overshoots the reserve by at most
	// one read per active writer.
	streamCheckBytes = 1 << 20
	// captureReserveFloorBytes and captureReservePct are the standalone defaults
	// for the capture filesystem reserve: keep a fifth of the volume free, never
	// less than 1536 MiB, for Postgres, the binary, the DB WAL and the next
	// session's writes. In the deployed lab these numbers have one authority,
	// deployment/guest-start.py, which also sizes the packet ring from them and
	// passes them here as M1NERVAC0NSOLE_CAPTURE_RESERVE_MB/_PCT; the constants
	// below are what a run outside the lab uses. The reserve is a floor this
	// recorder keeps for its own writers, not a cross-process quota: another
	// process can still fill the volume, and no writer here can prove otherwise.
	captureReserveFloorBytes = 1536 << 20
	captureReservePct        = 20
)

// TrafficSearchDescription is persisted into the tool catalog for new and
// upgraded installations. Keep it in the traffic package so the runtime tool
// and the catalog migration cannot drift apart.
const TrafficSearchDescription = "Query target traffic that the recording proxy has captured (host is required; accepts a bare host, host:port, or a full URL, and can be further filtered by URL substring or body keyword). Specifying a port returns only that service's traffic, so traffic from different ports on the same IP is not mixed. body_contains runs full-text search over captured request/response headers and bodies, supporting any substring and Chinese (at least 3 characters). Returns only a lightweight index (id/method/url/status/resp_len) without response content. After a non-empty result, you must verify each request/response with traffic_get, then pass only the IDs that really support the current vulnerability to bind_finding_traffic. By default it returns 3 results (at most 10 per page); use page to paginate when there are many results."

// taskSource is the origin transport's own answer to which task a proxied
// request belongs to. The gateway implements it from the session it already
// authorized the request with, so an exchange is attributed to the run that made
// it instead of being guessed from the host or a time window. A transport that
// does not implement it (the nil test hook) records NULL.
type taskSource interface {
	TaskID(connCtx *mproxy.ConnContext, req *http.Request) int64
}

// Traffic runs the recording proxy and owns the file tree + index.
type Traffic struct {
	dir   string
	addr  string
	db    *sql.DB
	wmu   sync.Mutex // serializes record() vs DeleteHost (incl. blob GC)
	seq   atomic.Int64
	proxy *mproxy.Proxy
	// taskOf resolves the task an exchange belongs to; nil records NULL.
	taskOf taskSource
	// taskIDs remembers the task of a live client connection. A tunnel's inner
	// requests carry no proxy credential, and the gateway retires its own
	// per-connection state with the origin connection, which can close before the
	// exchange is recorded, so the task is taken once at ServerConnected and
	// dropped with the client connection.
	taskIDs sync.Map // conn id -> int64
	// fts reports whether the full-text index is available. False on a driver
	// build without FTS5: recording and metadata search still work, body search
	// degrades to unsupported rather than erroring.
	fts bool
	// reaping tracks background reclamation of legacy trees and index space, so
	// shutdown and tests can wait for it instead of racing it.
	reaping sync.WaitGroup
	// incrementalVacuum reports whether the index can return freed pages to the
	// filesystem on its own. False on a database created before this was the
	// default: PRAGMA incremental_vacuum is a silent no-op there, so deletions
	// reclaim nothing until an explicit full compaction converts the file.
	incrementalVacuum bool
	// reclaiming keeps a single background reclamation in flight. Concurrent ones
	// would only contend for wmu, never finish sooner.
	reclaiming atomic.Bool
	// closed is shut by Close so a reclamation abandons its remaining budget
	// instead of holding shutdown open for minutes. Nil on the zero value, which
	// stopping() treats as "not closing".
	closed    chan struct{}
	closeOnce sync.Once
	// free measures the free and total bytes of the filesystem holding dir. A
	// field rather than a direct call so a test can trip the capture reserve
	// without filling a disk. Nil means the platform has no probe at all, which
	// keeps capture running (see captureSpace).
	free func(dir string) (free, total int64, err error)
	// reserveFloor and reservePct are the reserve kept free on the capture
	// filesystem, read once at open from the environment guest-start.py sets.
	reserveFloor int64
	reservePct   int64
	// spooled counts bytes written to capture artifacts store-wide since the last
	// free-space probe. One counter for the whole store, not one per writer, so N
	// concurrent writers probe N times less often.
	spooled atomic.Int64
	// probed records that the filesystem has been measured at least once, so the
	// first capture write of a run is never written without a measurement.
	probed atomic.Bool
	// spaceStop holds the reason capture was disabled, "" while it is enabled. A
	// probe that finds the reserve reached or cannot measure latches here, so
	// every writer stops at its next check instead of probing again.
	spaceStop atomic.Value // string
	spaceMu   sync.Mutex
	// wsSpools holds the transcript being written for each live WebSocket flow,
	// from WebSocketStart to WebSocketEnd.
	wsSpools sync.Map // *mproxy.Flow -> *wsSpool
}

// OpenWithTransport initializes the traffic tree, blob store and SQLite index
// under dir. A nil hook keeps go-mitmproxy's own dial/TLS/round-trip path; a
// hook owns origin authorization, the exit, the TLS handshake and connection
// pooling. Production always passes one: a recorder built without it dials
// origins directly, which is the unrecorded path the boundary forbids.
func OpenWithTransport(dir, addr string, ot mproxy.OriginTransport) (*Traffic, error) {
	streams := filepath.Join(dir, "_streams")
	// A spool is renamed into the blob store or removed when its flow ends, so
	// anything still here was left by a crash and was never indexed.
	_ = os.RemoveAll(streams)
	for _, d := range []string{dir, filepath.Join(dir, "_index"), filepath.Join(dir, "_blobs"), filepath.Join(dir, "_ca"), streams} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// busy_timeout is a per-connection setting, so it belongs in the DSN rather
	// than in a one-off Exec: the pool opens connections on demand, and an Exec
	// only configures whichever one happened to serve it — leaving every other
	// connection to fail instantly the moment a writer holds the database.
	// The driver splits the DSN at the first '?', so a data directory containing
	// one would silently name a different file; that path falls back to a bare
	// DSN, where initIndex still applies the pragmas to its own connection.
	index := filepath.Join(dir, "_index", "index.sqlite")
	dsn := index
	if !strings.ContainsRune(index, '?') {
		dsn = "file:" + index + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	t := &Traffic{dir: dir, addr: addr, db: db, closed: make(chan struct{}), free: filesystemSpace}
	t.reserveFloor, t.reservePct = captureReserve()
	// The origin transport is where the session was resolved, so the recorder
	// takes an exchange's task from it instead of parsing proxy credentials
	// itself. A transport that cannot answer records NULL.
	if ts, ok := ot.(taskSource); ok {
		t.taskOf = ts
	}
	if err := t.initIndex(); err != nil {
		db.Close()
		return nil, err
	}

	p, err := mproxy.NewProxy(&mproxy.Options{
		Addr:        addr,
		SslInsecure: true,
		CaRootPath:  filepath.Join(dir, "_ca"),
		// A nil hook keeps go-mitmproxy's own origin path; a hook owns origin
		// authorization, TLS, the exit and pooling (see gateway.Transport).
		OriginTransport: ot,
		// Bounded retention for streamed flows: what is persisted is spooled to
		// disk, so this cap only bounds the flow's in-memory live view.
		MaxStreamEvents: maxStreamEvents,
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	// The nil-hook path dials targets DIRECTLY: go-mitmproxy's own default
	// upstream uses http.ProxyFromEnvironment, so an HTTP_PROXY/HTTPS_PROXY in
	// the environment (a VPN/system proxy) would make it forward target requests
	// through that external proxy — which can't reach the target → 502. The
	// operator's global proxy is the gateway's exit, not the recorder's own.
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return nil, nil })
	p.AddAddon(&sink{t: t})
	t.proxy = p
	return t, nil
}

// initIndex applies the schema on a single pinned connection. Pinning is what
// makes auto_vacuum reliable: it can only be set while the database still holds
// no tables, and only the VACUUM that follows writes it into the file header —
// two steps a pooled *sql.DB is free to route to different connections, which
// would silently drop the setting.
//
// auto_vacuum=incremental is what lets a deletion hand freed pages back to the
// filesystem. Without it SQLite merely chains them onto its freelist, so the
// index file never shrinks no matter how much traffic is deleted — and since
// every body below maxInlineBody lives in that file, plus a trigram index
// roughly twice the size of the text it covers, a capture-heavy install ends up
// holding gigabytes for traffic it no longer has. On a database that already has
// tables the pragma is a documented no-op, so installs created before this keep
// auto_vacuum=0 until a full compaction converts the file; incrementalVacuum
// records that so reclaim can say so instead of pretending to reclaim.
func (t *Traffic) initIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Re-applied rather than left to the DSN so the bare-DSN fallback in Open is
	// still correct: journal_mode persists in the file header, which is what every
	// later connection reads.
	for _, p := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	var tables int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		for _, p := range []string{`PRAGMA auto_vacuum=incremental`, `VACUUM`} {
			if _, err := conn.ExecContext(ctx, p); err != nil {
				return err
			}
		}
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	t.incrementalVacuum = mode == autoVacuumIncremental
	if !t.incrementalVacuum {
		log.Printf("[traffic] index database is not in incremental-vacuum mode (auto_vacuum=%d): deleting traffic will not shrink index.sqlite; run one storage compaction to convert it", mode)
	}
	if _, err := conn.ExecContext(ctx, indexSchema); err != nil {
		return err
	}
	// task_id postdates shipped installs, and CREATE TABLE IF NOT EXISTS leaves
	// an existing table alone. SQLite has no ADD COLUMN IF NOT EXISTS, so the
	// column is added only when it is missing: re-applying this is a no-op, which
	// is what makes it safe on every start. Rows recorded before it existed keep
	// NULL, which is the same value a run with no session records.
	var hasTaskID int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('exchanges') WHERE name='task_id'`).Scan(&hasTaskID); err != nil {
		return err
	}
	if hasTaskID == 0 {
		if _, err := conn.ExecContext(ctx, `ALTER TABLE exchanges ADD COLUMN task_id INTEGER`); err != nil {
			return err
		}
	}
	// After the column, never inside indexSchema: on an install that predates
	// task_id the index would name a column the table does not have yet and take
	// the whole recorder down at startup.
	if _, err := conn.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_ex_task ON exchanges(task_id)`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, ftsSchema); err != nil {
		log.Printf("[traffic] full-text index unavailable; body search is disabled (metadata search is unaffected): %v", err)
		return nil
	}
	t.fts = true
	return nil
}

// ProxyAddr returns the address workers should set as HTTP(S)_PROXY. A bare
// ":port" means "bind all interfaces" (legacy default), so map it to loopback.
func (t *Traffic) ProxyAddr() string {
	if strings.HasPrefix(t.addr, ":") {
		return "http://127.0.0.1" + t.addr
	}
	return "http://" + t.addr
}

// ValidateProxyURL parses and checks a proxy URL (http/https/socks5, optional
// user:pass), returning the parsed URL. Exposed so callers can validate a global
// proxy before persisting it even when the traffic proxy itself is disabled.
func ValidateProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse proxy address %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	case "":
		return nil, fmt.Errorf("proxy %q is missing a scheme (use http://, https://, or socks5://)", raw)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, or socks5)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy %q is missing a host address", raw)
	}
	return u, nil
}

// CACertPath returns the PEM CA cert clients must trust to verify HTTPS through
// the MITM proxy (go-mitmproxy writes it here on first start).
func (t *Traffic) CACertPath() string {
	return filepath.Join(t.dir, "_ca", "mitmproxy-ca-cert.pem")
}

// Start runs the proxy (blocking); run in a goroutine.
func (t *Traffic) Start() error { return t.proxy.Start() }

// Close waits for background tree reclamation to finish before closing the
// index, so shutdown never leaves a goroutine unlinking files out from under a
// removed data directory. Index-space reclamation is signalled to stop first:
// it holds a whole minutes-long budget, and finishing it is never worth delaying
// shutdown for — the next deletion resumes it.
func (t *Traffic) Close() error {
	if t.closed != nil {
		t.closeOnce.Do(func() { close(t.closed) })
	}
	t.reaping.Wait()
	return t.db.Close()
}

// stopping reports whether Close has been called. A nil channel (the zero value)
// is never ready, so this reads as "not closing" without a separate guard.
func (t *Traffic) stopping() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
func (t *Traffic) DB() *sql.DB { return t.db }

// sink is the go-mitmproxy addon that records completed exchanges.
type sink struct {
	mproxy.BaseAddon
	t *Traffic
}

func (s *sink) Response(f *mproxy.Flow) {
	if f.Request == nil || f.Response == nil {
		return
	}
	s.t.record(f)
}

// ServerConnected remembers the task the tunnel was opened for. A tunnel's inner
// requests carry no proxy credential, and the gateway retires its per-connection
// state with the origin connection, so this is the one point the recorder can
// learn the task before any exchange on that connection is stored.
func (s *sink) ServerConnected(connCtx *mproxy.ConnContext) {
	if s.t.taskOf == nil || connCtx == nil {
		return
	}
	if id := s.t.taskOf.TaskID(connCtx, nil); id != 0 {
		s.t.taskIDs.Store(connCtx.Id(), id)
	}
}

// ClientDisconnected drops the connection's task with the connection, so the
// map stays bounded by live client connections.
func (s *sink) ClientDisconnected(c *mproxy.ClientConn) {
	if c != nil {
		s.t.taskIDs.Delete(c.Id)
	}
}

// taskFor returns the task a flow's exchange belongs to, 0 when none: the
// session its connection was opened under, otherwise the one its own credential
// resolves (a plain-HTTP request, or a refused CONNECT).
func (t *Traffic) taskFor(f *mproxy.Flow) int64 {
	if f == nil {
		return 0
	}
	if f.ConnContext != nil {
		if id, ok := t.taskIDs.Load(f.ConnContext.Id()); ok {
			return id.(int64)
		}
	}
	if t.taskOf == nil || f.Request == nil {
		return 0
	}
	return t.taskOf.TaskID(f.ConnContext, f.Request.Raw())
}

// streamedMarker is the line a stored response head carries when its body could
// not be captured at all: a streamed body whose spool failed to store, or a
// WebSocket flow whose transcript was never started. The name follows the
// gateway's attribution header style, which also makes the reason searchable.
const streamedMarker = "X-M1nervac0nsole-Capture: body not captured: streamed"

// StreamResponseModifier spools a streamed body to disk as it passes to the
// client. A streamed flow never reaches Response — the proxy refuses to buffer
// it — so this hook is the only place its bytes exist, and the spooled file is
// what keeps a 6 MiB body or a long SSE stream from being recorded as metadata
// only.
func (s *sink) StreamResponseModifier(f *mproxy.Flow, in io.Reader) io.Reader {
	if !f.Stream {
		return in
	}
	sp := &streamSpool{t: s.t, f: f, r: in, taskID: s.t.taskFor(f)}
	// f.Done() closes when the exchange ends, which is the one point every way
	// of ending a stream passes through: EOF, a client disconnect and a
	// shutdown alike.
	go func() {
		<-f.Done()
		sp.finish()
	}()
	return sp
}

// wsTranscriptType names the stored body of a WebSocket flow: one JSON object
// per line, frames in the order the proxy saw them. It is an ordinary blob, so
// archive, export, evidence and traffic_get carry it with no change.
const wsTranscriptType = "application/x-m1nervac0nsole-ws+jsonl"

// wsTranscriptHeader is the first line of every transcript. The two directions
// are independent TCP streams, so proxy arrival order is the only order that
// exists. gorilla consumes ping and pong inside ReadMessage, so control frames
// are not observable at this layer and the transcript says so rather than
// implying a completeness it cannot have.
const wsTranscriptHeader = `{"v":1,"kind":"ws-transcript","order":"proxy-arrival","control_frames":"not-observable"}` + "\n"

// WebSocket close codes (RFC 6455 7.4.1). Named here so the recorder does not
// import the proxy's websocket library for two integers.
const (
	wsCloseNormal   = 1000
	wsCloseAbnormal = 1006
)

// wsFrameLine is one forwarded WebSocket message. Data is base64 in JSON.
type wsFrameLine struct {
	Seq  int64  `json:"seq"`
	TS   int64  `json:"ts_ns"`
	Dir  string `json:"dir"`
	Type string `json:"type"`
	Len  int    `json:"len"`
	Data []byte `json:"data"`
}

// wsCloseLine is one direction's end: the close frame a peer sent, or the
// transport error that ended it.
type wsCloseLine struct {
	Seq   int64   `json:"seq"`
	TS    int64   `json:"ts_ns"`
	Dir   string  `json:"dir"`
	Close wsClose `json:"close"`
}

type wsClose struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
	// Frame is true only when the peer sent a close frame. An end without one
	// is a cut-short session, whatever error the transport reported.
	Frame bool `json:"-"`
	// Teardown is true when the connection ended because the proxy closed it
	// after the other direction ended. That is a consequence of the session
	// ending, not evidence of why it ended, so it decides nothing.
	Teardown bool `json:"-"`
}

// WebSocketStart opens the transcript for a WebSocket flow. The task is taken
// here, while the connection that opened it is still live, exactly as a streamed
// HTTP body does.
func (s *sink) WebSocketStart(f *mproxy.Flow) {
	if f == nil || f.Request == nil || f.Request.URL == nil {
		return
	}
	sp := &wsSpool{t: s.t, f: f, taskID: s.t.taskFor(f)}
	sp.open()
	s.t.wsSpools.Store(f, sp)
}

// WebSocketFrame writes one forwarded message to the flow's transcript. The proxy
// calls it before forwarding, so the transcript is never behind the peers.
func (s *sink) WebSocketFrame(f *mproxy.Flow, m *mproxy.WebSocketMessage) {
	if m == nil {
		return
	}
	if sp := s.t.wsSpoolFor(f); sp != nil {
		sp.frame(m)
	}
}

// WebSocketClosed records one direction's end, including the close code or the
// error that ended it.
func (s *sink) WebSocketClosed(f *mproxy.Flow, fromClient bool, err error) {
	if sp := s.t.wsSpoolFor(f); sp != nil {
		sp.closed(fromClient, err)
	}
}

// WebSocketEnd finalizes the transcript and writes the exchange row.
func (s *sink) WebSocketEnd(f *mproxy.Flow) {
	if f == nil || f.Request == nil || f.Request.URL == nil {
		return
	}
	sp, ok := s.t.wsSpools.LoadAndDelete(f)
	if !ok {
		// No start was seen, so no frame was captured: keep the metadata row
		// rather than losing the exchange, and say the body is missing.
		s.t.recordStreamed(f, wsStatus(f), 0, storedBody{}, streamedMarker, s.t.taskFor(f))
		return
	}
	sp.(*wsSpool).finish()
}

// wsSpoolFor returns the transcript being written for a flow, nil when none is.
func (t *Traffic) wsSpoolFor(f *mproxy.Flow) *wsSpool {
	if f == nil {
		return nil
	}
	sp, ok := t.wsSpools.Load(f)
	if !ok {
		return nil
	}
	return sp.(*wsSpool)
}

// wsSpool writes one WebSocket flow's transcript while its frames are forwarded.
// Each frame is written before it is forwarded, so the transcript is never behind
// the peers, and nothing is retained in memory: the file is the only copy, so no
// per-exchange cap applies and the capture reserve is the one bound.
//
// kept and keptFrames count what reached the file; payload and frames count what
// the peers exchanged, so a partial capture can say what it kept of what. stopped
// is why capture ended early, closedBy the directions that ended with a close
// frame, and abnormal those that did not.
type wsSpool struct {
	t      *Traffic
	f      *mproxy.Flow
	taskID int64

	// mu guards both directions' writes and keeps seq in file order.
	mu   sync.Mutex
	file *os.File
	path string
	sum  hash.Hash
	seq  int64
	// head keeps the first blobPreview bytes for the inline preview.
	head []byte

	kept       int64
	payload    int64
	frames     int64
	keptFrames int64
	stopped    string
	closedBy   []string
	abnormal   []string
}

// open starts the transcript. A failure to open it is not fatal: the row is still
// written, labelled with why the body is missing.
func (s *wsSpool) open() {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.CreateTemp(filepath.Join(s.t.dir, "_streams"), "ws-")
	if err != nil {
		s.stopLocked("opening the capture failed: " + err.Error())
		return
	}
	s.file, s.path, s.sum = f, f.Name(), sha256.New()
	s.writeLocked([]byte(wsTranscriptHeader))
}

// writeLocked appends one complete line to the transcript, stopping at the
// capture filesystem's reserve or on a write failure. The caller holds s.mu.
func (s *wsSpool) writeLocked(line []byte) {
	if s.stopped != "" {
		return
	}
	if reason := s.t.captureSpace(int64(len(line))); reason != "" {
		s.stopLocked(reason)
		return
	}
	n, err := s.file.Write(line)
	s.sum.Write(line[:n])
	s.kept += int64(n)
	if room := blobPreview - len(s.head); room > 0 {
		s.head = append(s.head, line[:min(n, room)]...)
	}
	if err != nil {
		s.stopLocked("writing the capture failed: " + err.Error())
	}
}

func (s *wsSpool) stopLocked(reason string) {
	s.stopped = reason
	log.Printf("[traffic] WebSocket transcript not captured in full: %s", reason)
}

// frame records one forwarded message. The sequence number is assigned here, in
// proxy arrival order, which is the only order two independent directions have.
func (s *wsSpool) frame(m *mproxy.WebSocketMessage) {
	// gorilla's data opcodes: 1 text, 2 binary. Named here rather than imported so
	// the recorder does not depend on the proxy's websocket library.
	typ := "binary"
	if m.Type == 1 {
		typ = "text"
	}
	dir := "s2c"
	if m.FromClient {
		dir = "c2s"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames++
	s.payload += int64(len(m.Content))
	if s.stopped != "" {
		return
	}
	s.seq++
	line, err := json.Marshal(wsFrameLine{Seq: s.seq, TS: m.Timestamp.UnixNano(), Dir: dir, Type: typ, Len: len(m.Content), Data: m.Content})
	if err != nil {
		s.stopLocked("encoding the capture failed: " + err.Error())
		return
	}
	s.writeLocked(append(line, '\n'))
	if s.stopped == "" {
		s.keptFrames++
	}
}

// closed records one direction's end. A peer's close frame ends the session by
// agreement; a direction that ends without one means the conversation was cut
// short, so the row is labelled rather than reading as a whole session. The
// proxy tears down the other direction as soon as one ends, so the direction
// that follows a close frame reports our own teardown error and is not treated
// as a cut-short conversation.
func (s *wsSpool) closed(fromClient bool, err error) {
	dir := "s2c"
	if fromClient {
		dir = "c2s"
	}
	cl := wsCloseOf(err)
	s.mu.Lock()
	defer s.mu.Unlock()
	// A direction the proxy closed after the other one ended says nothing about
	// why the session ended, so it decides nothing. A close frame means the
	// peers agreed; a real transport error means the session was cut short.
	if !cl.Teardown {
		if cl.Frame {
			s.closedBy = append(s.closedBy, dir)
		} else {
			s.abnormal = append(s.abnormal, fmt.Sprintf("%s ended with code %d: %s", dir, cl.Code, cl.Error))
		}
	}
	if s.stopped != "" {
		return
	}
	s.seq++
	line, merr := json.Marshal(wsCloseLine{Seq: s.seq, TS: time.Now().UnixNano(), Dir: dir, Close: cl})
	if merr != nil {
		s.stopLocked("encoding the capture failed: " + merr.Error())
		return
	}
	s.writeLocked(append(line, '\n'))
}

// wireCloseCode reports whether a close code can appear in a close frame on the
// wire. 1004, 1005 (no status), 1006 (abnormal) and 1015 (TLS) are reserved for
// local reporting, so a CloseError carrying one describes a torn-down
// connection, not an agreement between the peers (RFC 6455 7.4.1).
func wireCloseCode(code int) bool {
	switch {
	case code >= 1000 && code <= 1003:
		return true
	case code >= 1007 && code <= 1011:
		return true
	case code >= 3000 && code <= 4999:
		return true
	}
	return false
}

// wsCloseOf describes one direction's end: the close frame a peer sent, or the
// transport error that ended it.
func wsCloseOf(err error) wsClose {
	var ce *mproxy.WebSocketCloseError
	switch {
	case errors.As(err, &ce) && wireCloseCode(ce.Code):
		return wsClose{Code: ce.Code, Reason: ce.Text, Frame: true}
	case errors.As(err, &ce):
		return wsClose{Code: ce.Code, Error: ce.Text}
	case errors.Is(err, net.ErrClosed):
		// The proxy closed this connection because the other direction ended
		// first. The session's cause is the other direction's, not this one's.
		return wsClose{Code: wsCloseAbnormal, Error: err.Error(), Teardown: true}
	case err != nil:
		return wsClose{Code: wsCloseAbnormal, Error: err.Error()}
	default:
		// The goroutine ended without a close frame and without an error: the
		// session was torn down, not agreed.
		return wsClose{Code: wsCloseAbnormal, Error: "ended without a close frame"}
	}
}

// finish stores the transcript and writes the exchange row. resp_len is the
// transcript's own length on disk, not the payload the frames carried: the blob
// is what an archive, an evidence read and a restore compare, so the two must
// agree. Payload totals live in the capture marker only.
func (s *wsSpool) finish() {
	s.mu.Lock()
	if s.file != nil {
		s.file.Close()
	}
	kept, payload, frames, keptFrames := s.kept, s.payload, s.frames, s.keptFrames
	path, sum, head := s.path, s.sum, s.head
	reasons := []string{}
	if s.stopped != "" {
		reasons = append(reasons, s.stopped)
	}
	// A real transport error means the session was cut short; without one, a
	// close frame means the peers agreed.
	if len(s.abnormal) > 0 {
		reasons = append(reasons, s.abnormal...)
	} else if len(s.closedBy) == 0 {
		reasons = append(reasons, "neither direction sent a close frame")
	}
	s.mu.Unlock()

	mark := ""
	if len(reasons) > 0 {
		mark = fmt.Sprintf("%s (%s, kept %d of %d messages, %d of %d bytes)", partialMarker, strings.Join(reasons, "; "), keptFrames, frames, kept, payload)
	}
	s.t.wmu.Lock()
	defer s.t.wmu.Unlock()
	var body storedBody
	if kept > 0 {
		var err error
		if body, err = s.t.storeStreamed(path, sum, head, wsTranscriptType); err != nil {
			mark = fmt.Sprintf("%s (storing the WebSocket transcript failed: %v)", partialMarker, err)
		}
	} else if path != "" {
		os.Remove(path) // opened but nothing was written
	}
	s.t.recordStreamedLocked(s.f, wsStatus(s.f), kept, body, mark, s.taskID)
}

// wsStatus is the status a WebSocket exchange is recorded with: the origin's
// answer to the upgrade when the flow carries one, otherwise 101, which is what
// the client was told.
func wsStatus(f *mproxy.Flow) int {
	if f.Response != nil {
		return f.Response.StatusCode
	}
	return http.StatusSwitchingProtocols
}

// streamSpool captures one streamed body to disk while it is passed to the
// client. Nothing is held in memory beyond the preview, so an exchange has no
// size cap of its own: the only bound is the capture filesystem's reserve.
type streamSpool struct {
	t *Traffic
	f *mproxy.Flow
	r io.Reader

	// taskID is taken when the stream starts, while the connection it belongs to
	// is still live: a stream normally ends with the client disconnecting, which
	// retires the connection's task before the row is written.
	taskID int64

	file *os.File
	path string
	sum  hash.Hash

	n    int64  // bytes the client received
	kept int64  // bytes written to the artifact
	head []byte // first blobPreview bytes, for the inline preview

	// stopped says why spooling ended early; the row is labelled partial when it
	// is set. eof records that the origin's body ended, so a stream cut short by
	// a client disconnect is labelled too instead of reading as a whole body.
	stopped string
	eof     bool
}

func (s *streamSpool) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.n += int64(n)
		s.write(p[:n])
	}
	if errors.Is(err, io.EOF) {
		s.eof = true
	}
	return n, err
}

// write appends p to the artifact, stopping at the capture filesystem's reserve
// or on a write failure. Stopping never fails the read: the client still gets
// every byte, and the row records what was kept. A short write is a write error
// here: os.File reports one whenever it accepts fewer bytes than offered.
func (s *streamSpool) write(p []byte) {
	if s.stopped != "" {
		return
	}
	if s.file == nil && !s.open() {
		return
	}
	if reason := s.t.captureSpace(int64(len(p))); reason != "" {
		s.stop(reason)
		return
	}
	n, err := s.file.Write(p)
	s.sum.Write(p[:n])
	s.kept += int64(n)
	if room := blobPreview - len(s.head); room > 0 {
		s.head = append(s.head, p[:min(n, room)]...)
	}
	if err != nil {
		s.stop("writing the capture failed: " + err.Error())
	}
}

func (s *streamSpool) open() bool {
	f, err := os.CreateTemp(filepath.Join(s.t.dir, "_streams"), "stream-")
	if err != nil {
		s.stop("opening the capture failed: " + err.Error())
		return false
	}
	s.file, s.path, s.sum = f, f.Name(), sha256.New()
	return true
}

func (s *streamSpool) stop(reason string) {
	s.stopped = reason
	log.Printf("[traffic] streamed body not captured in full: %s", reason)
}

// finish stores the spooled body and writes the exchange row. The write lock
// covers the rename and the row, exactly as record() covers spill and insert:
// blob GC runs under the same lock and would otherwise delete a blob that has
// no reference yet.
func (s *streamSpool) finish() {
	if s.file != nil {
		s.file.Close()
	}
	ct := ""
	if s.f.Response != nil {
		ct = s.f.Response.Header.Get("Content-Type")
	}
	mark := ""
	switch {
	case s.stopped != "":
		mark = fmt.Sprintf("%s (%s, kept %d of %d bytes)", partialMarker, s.stopped, s.kept, s.n)
	case !s.eof && s.n > 0:
		mark = fmt.Sprintf("%s (the stream ended before the origin finished, kept %d bytes)", partialMarker, s.n)
	}
	s.t.wmu.Lock()
	defer s.t.wmu.Unlock()
	var body storedBody
	if s.kept > 0 {
		var err error
		if body, err = s.t.storeStreamed(s.path, s.sum, s.head, ct); err != nil {
			mark = fmt.Sprintf("%s (storing the streamed body failed: %v)", streamedMarker, err)
		}
	} else if s.path != "" {
		os.Remove(s.path) // opened but nothing was written
	}
	s.t.recordStreamedLocked(s.f, 0, s.n, body, mark, s.taskID)
}

// captureReserve reads the capture filesystem reserve once: the floor in MiB and
// the percentage of the volume. deployment/guest-start.py owns these numbers in
// the deployed lab and passes them to this process, so the packet ring and the
// recorder stop at the same floor; an unset or unusable value falls back to the
// standalone defaults rather than disabling the guard.
func captureReserve() (floorBytes, pct int64) {
	floorBytes, pct = captureReserveFloorBytes, captureReservePct
	if raw := strings.TrimSpace(os.Getenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_MB")); raw != "" {
		if mb, err := strconv.ParseInt(raw, 10, 64); err == nil && mb > 0 {
			floorBytes = mb << 20
		} else {
			log.Printf("[traffic] M1NERVAC0NSOLE_CAPTURE_RESERVE_MB=%q is not a positive integer; using %d MiB", raw, floorBytes>>20)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 && v < 100 {
			pct = v
		} else {
			log.Printf("[traffic] M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT=%q is not a percentage in 1..99; using %d", raw, pct)
		}
	}
	return floorBytes, pct
}

// reserveBytes is the free space this recorder keeps on its capture filesystem:
// pct of the volume, never less than the floor. Same formula as
// deployment/guest-start.py's ring_reserve_mb, from the same numbers.
func (t *Traffic) reserveBytes(total int64) int64 {
	return max(t.reserveFloor, total*t.reservePct/100)
}

// captureSpace records n bytes about to be written to a capture artifact and
// reports why capture must stop, "" while it may continue. The probe runs at most
// once per streamCheckBytes of store-wide writes, so the reserve costs one statfs
// per MiB rather than one per writer.
//
// A probe that finds the reserve reached, or that cannot measure at all, disables
// capture for the process: the answer cannot improve on its own, every writer
// must stop at its next check instead of probing a filesystem already at its
// floor, and continuing would be the unbounded fallback this guard exists to
// prevent. A restart measures again. A platform with no probe at all
// (t.free == nil) keeps capturing: there is nothing to measure, which is a
// platform limit, not a reserve decision.
//
// This is a floor this recorder keeps for its own writers, not a cross-process
// quota: another process can still fill the volume.
func (t *Traffic) captureSpace(n int64) string {
	if t.free == nil {
		return ""
	}
	if reason, _ := t.spaceStop.Load().(string); reason != "" {
		return reason
	}
	if t.probed.Load() && t.spooled.Add(n) < streamCheckBytes {
		return ""
	}
	t.spaceMu.Lock()
	defer t.spaceMu.Unlock()
	if reason, _ := t.spaceStop.Load().(string); reason != "" {
		return reason
	}
	// Another writer may have probed while this one waited for the lock: its
	// answer covers the bytes counted since.
	if t.probed.Load() && t.spooled.Load() < streamCheckBytes {
		return ""
	}
	t.probed.Store(true)
	t.spooled.Store(0)
	free, total, err := t.free(t.dir)
	var reason string
	switch {
	case err != nil:
		reason = fmt.Sprintf("capture filesystem unmeasurable: %v", err)
	case free < t.reserveBytes(total):
		reason = fmt.Sprintf("capture filesystem reserve reached (%d MiB free, reserve %d MiB)", free>>20, t.reserveBytes(total)>>20)
	}
	if reason != "" {
		t.spaceStop.Store(reason)
		log.Printf("[traffic] capture disabled: %s", reason)
	}
	return reason
}

// storeStreamed moves a finished spool into the content-addressed blob store and
// returns the body record for it: the hash names the blob and only the preview
// stays inline, exactly as spill does for a buffered body. The bytes are never
// held in memory, so a body of any size costs the same.
func (t *Traffic) storeStreamed(path string, sum hash.Hash, head []byte, contentType string) (storedBody, error) {
	defer os.Remove(path) // no-op once renamed into the store
	h := hex.EncodeToString(sum.Sum(nil))
	blobDir := filepath.Join(t.dir, "_blobs", "sha256", h[:2])
	dest := filepath.Join(blobDir, h+".bin")
	if _, err := os.Stat(dest); err == nil {
		// Content-addressed: identical bytes are already stored.
	} else if err := os.MkdirAll(blobDir, 0o755); err != nil {
		return storedBody{}, err
	} else if err := os.Rename(path, dest); err != nil {
		return storedBody{}, err
	}
	if isBinaryBody(contentType, head) {
		return storedBody{hash: h, inline: []byte(binaryTag(contentType, head))}, nil
	}
	return storedBody{hash: h, inline: []byte(truncateUTF8(head, blobPreview))}, nil
}

// recordStreamed stores one exchange whose body was streamed past the recorder.
// status 0 takes the flow's own response status; respLen is the length of the
// body that was stored (what the client received, or the transcript's own length
// for a WebSocket); respB is the spooled body, empty when none was captured; mark
// is a capture line appended to the stored response head, so a row never reads as
// a whole body it does not have.
func (t *Traffic) recordStreamed(f *mproxy.Flow, status int, respLen int64, respB storedBody, mark string, taskID int64) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.recordStreamedLocked(f, status, respLen, respB, mark, taskID)
}

// recordStreamedLocked is recordStreamed with the write lock already held, so a
// caller that also stores a blob keeps the two under one lock.
func (t *Traffic) recordStreamedLocked(f *mproxy.Flow, status int, respLen int64, respB storedBody, mark string, taskID int64) {
	if f == nil || f.Request == nil || f.Request.URL == nil || t.stopping() {
		return
	}
	u := f.Request.URL
	var respHeader http.Header
	if f.Response != nil {
		respHeader = f.Response.Header
		if status == 0 {
			status = f.Response.StatusCode
		}
	}
	reqHead := fmt.Sprintf("%s %s %s\n%s", f.Request.Method, u.RequestURI(), f.Request.Proto, requestHeaderLines(f.Request))
	respHead := fmt.Sprintf("HTTP %d\n%s", status, headerLines(respHeader))
	if mark != "" {
		respHead += mark + "\n"
	}

	n := t.seq.Add(1)
	now := time.Now()
	id := fmt.Sprintf("%d-%08d", now.Unix(), n) // no modulo: keeps every id unique
	if err := t.insertExchange(id, now.Unix(), taskID, u.Hostname(), f.Request.Method, db.TemplatePath(u.EscapedPath()), u.String(), status, respHeader.Get("Content-Type"), len(f.Request.Body), int(respLen), reqHead, storedBody{}, respHead, respB); err != nil {
		log.Printf("[traffic] failed to record streamed exchange %s: %v", u.String(), err)
	}
}

// RequestError fires when a request through an established MITM tunnel fails.
// The recorder stores the attempt instead of tunneling the host transparently:
// a passthrough skipped both policy and capture, so a proxy-caused error used to
// turn every later request to that host into an unrecorded one.
func (s *sink) RequestError(f *mproxy.Flow, err error) {
	if err == nil || f == nil || f.Request == nil || f.Request.URL == nil {
		return
	}
	s.t.recordFailure(f, err, 0)
}

// HTTPConnectError fires when a CONNECT never produced a tunnel: the gateway
// refused it (policy, dns, dial, tls) before any request reached the origin.
// Without this row an HTTPS refusal was invisible, while the same refusal on a
// plain-HTTP target was recorded by RequestError. Nothing is flagged: the host
// stays intercepted, exactly as after a recorded request failure.
func (s *sink) HTTPConnectError(f *mproxy.Flow, err error) {
	if err == nil || f == nil || f.Request == nil || f.Request.URL == nil {
		return
	}
	// The status the client was answered with, matching writeOriginError's
	// default of 502 for an unclassified failure.
	status := http.StatusBadGateway
	var oe *mproxy.OriginError
	if errors.As(err, &oe) && oe.Status != 0 {
		status = oe.Status
	}
	s.t.recordFailure(f, err, status)
}

// recordFailure stores one attempt that produced no usable origin response,
// through the same spill/blob/index path as a completed exchange. The stage
// comes from the gateway's OriginError so policy, dns, dial, tls and transport
// failures stay distinguishable in the index. status 0 means no response was
// seen at all; a non-zero status is the gateway's own answer to a refused
// CONNECT.
func (t *Traffic) recordFailure(f *mproxy.Flow, err error, status int) {
	stage := "transport"
	var oe *mproxy.OriginError
	if errors.As(err, &oe) && oe.Stage != "" {
		stage = oe.Stage
	}
	u := f.Request.URL
	taskID := t.taskFor(f)
	respHeader := http.Header{"X-M1nervac0nsole-Gateway": {stage}}
	// A response header already seen means the failure came after the origin
	// answered, so keep its status and headers and only add the stage.
	if f.Response != nil {
		status = f.Response.StatusCode
		respHeader = f.Response.Header
		respHeader.Set("X-M1nervac0nsole-Gateway", stage)
	}
	reqHead := fmt.Sprintf("%s %s %s\n%s", f.Request.Method, u.RequestURI(), f.Request.Proto, requestHeaderLines(f.Request))
	respHead := fmt.Sprintf("HTTP %d\n%s", status, headerLines(respHeader))
	if f.Response == nil {
		respHead = fmt.Sprintf("(no response) %s: %v\n%s", stage, err, headerLines(respHeader))
		if status != 0 {
			// The client was answered with the gateway's own status: name both,
			// so the row cannot read as a target answer.
			respHead = fmt.Sprintf("HTTP %d (no origin response) %s: %v\n%s", status, stage, err, headerLines(respHeader))
		}
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()
	reqB := t.spill(f.Request.Body, f.Request.Header.Get("Content-Type"))
	respHead += cutMarker(reqB, storedBody{})
	n := t.seq.Add(1)
	now := time.Now()
	id := fmt.Sprintf("%d-%08d", now.Unix(), n) // no modulo: keeps every id unique
	if ierr := t.insertExchange(id, now.Unix(), taskID, u.Hostname(), f.Request.Method, db.TemplatePath(u.EscapedPath()), u.String(), status, "", len(f.Request.Body), 0, reqHead, reqB, respHead, storedBody{}); ierr != nil {
		log.Printf("[traffic] failed to record failed exchange %s: %v", u.String(), ierr)
	}
}

// record persists one exchange entirely in SQLite: metadata, bodies and the
// full-text index. Nothing is written to a per-request directory — only bodies
// above maxInlineBody spill to the content-addressed blob store.
func (t *Traffic) record(f *mproxy.Flow) {
	// The write lock covers blob + index writes, so DeleteHost (and its blob GC)
	// can run under the same lock without racing a concurrent record.
	t.wmu.Lock()
	defer t.wmu.Unlock()
	host := f.Request.URL.Hostname()
	method := f.Request.Method
	tmpl := db.TemplatePath(f.Request.URL.EscapedPath())
	taskID := t.taskFor(f)
	n := t.seq.Add(1)
	now := time.Now()
	id := fmt.Sprintf("%d-%08d", now.Unix(), n) // no modulo: keeps every id unique

	ct := f.Response.Header.Get("Content-Type")
	url := f.Request.URL.String()
	reqHead := fmt.Sprintf("%s %s %s\n%s", method, f.Request.URL.RequestURI(), f.Request.Proto, requestHeaderLines(f.Request))
	respHead := fmt.Sprintf("HTTP %d\n%s", f.Response.StatusCode, headerLines(f.Response.Header))
	// Bodies are spilled before the transaction opens: blob writes are filesystem
	// work and must not sit inside the SQLite write lock.
	reqB := t.spill(f.Request.Body, f.Request.Header.Get("Content-Type"))
	respB := t.spill(f.Response.Body, ct)
	// A body stored as a preview only says so in the head, so the row never reads
	// as a whole body it does not have. resp_len still carries the full length.
	respHead += cutMarker(reqB, respB)

	tx, err := t.db.Begin()
	if err != nil {
		log.Printf("[traffic] failed to record %s (begin transaction): %v", url, err)
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	// path stays empty for db-resident exchanges; a non-empty path marks a legacy
	// row whose bodies still live in the old on-disk tree (see Get).
	res, err := tx.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,task_id,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?,'')`,
		id, now.Unix(), nullIfZero(taskID), host, method, tmpl, url, f.Response.StatusCode, ct,
		len(f.Request.Body), len(f.Response.Body))
	if err != nil {
		log.Printf("[traffic] failed to record %s (write index): %v", url, err)
		return
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		log.Printf("[traffic] failed to record %s (get rowid): %v", url, err)
		return
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`,
		id, reqHead, reqB.inline, nullIfEmpty(reqB.hash), respHead, respB.inline, nullIfEmpty(respB.hash)); err != nil {
		log.Printf("[traffic] failed to record %s (write body): %v", url, err)
		return
	}

	for _, h := range []string{reqB.hash, respB.hash} {
		if h == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, id); err != nil {
			log.Printf("[traffic] failed to record %s (register blob reference): %v", url, err)
			return
		}
	}

	if t.fts {
		// The index is fed from memory, so a body that spilled to _blobs is still
		// fully searchable even though only its preview is stored inline.
		idx := strings.Join([]string{url, reqHead, reqB.index, respHead, respB.index}, "\n")
		if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			log.Printf("[traffic] failed to record %s (write full-text index): %v", url, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[traffic] failed to record %s (commit): %v", url, err)
	}
}

// storedBody is one body after the inline/spill decision: inline is what goes in
// the SQLite column (the whole body, or a preview when spilled), hash names the
// blob when it spilled, index is the text handed to FTS (empty for binary), and
// partial says why the body was stored as a preview only, so the row can say so
// instead of reading as a whole body.
type storedBody struct {
	inline  []byte
	hash    string
	index   string
	partial string
}

// cutMarker names each body that was stored as a preview only. A row carrying it
// never reads as a whole body it does not have, and an archive accepts the prefix
// instead of refusing the export as truncated.
func cutMarker(reqB, respB storedBody) string {
	var b strings.Builder
	for _, side := range []struct {
		name string
		body storedBody
	}{{"request", reqB}, {"response", respB}} {
		if side.body.partial != "" {
			b.WriteString(fmt.Sprintf("%s (%s body: %s)\n", partialMarker, side.name, side.body.partial))
		}
	}
	return b.String()
}

// spill decides where one body lives. Small bodies stay inline. Large ones are
// written to the content-addressed store and keep a readable preview inline so a
// reader can identify them without fetching the blob. Either way, text bodies
// are handed to the full-text index in full (up to maxIndexBody) — indexing is
// independent of where the bytes end up.
func (t *Traffic) spill(body []byte, contentType string) storedBody {
	if len(body) == 0 {
		return storedBody{}
	}
	text := !isBinaryBody(contentType, body)
	indexText := func() string {
		if !text {
			return ""
		}
		return string(clipBytes(body, maxIndexBody))
	}
	if len(body) <= maxInlineBody {
		return storedBody{inline: body, index: indexText()}
	}
	// A buffered body above the inline cutoff is the other place the recorder
	// writes to the capture filesystem, so it stops at the same reserve as a
	// streamed one: the preview stays inline and the row says the body is a
	// prefix rather than writing a blob the volume cannot hold.
	if reason := t.captureSpace(int64(len(body))); reason != "" {
		log.Printf("[traffic] buffered body not stored in full: %s", reason)
		return storedBody{inline: clipBytes(body, blobPreview), index: indexText(), partial: reason}
	}

	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	// One bucket level (256 buckets) is enough to keep any single directory small;
	// the store only ever holds bodies above maxInlineBody, deduplicated by hash.
	blobDir := filepath.Join(t.dir, "_blobs", "sha256", h[:2])
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		log.Printf("[traffic] failed to create blob directory: %v", err)
		return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
	}
	blobPath := filepath.Join(blobDir, h+".bin")
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		if err := os.WriteFile(blobPath, body, 0o644); err != nil {
			log.Printf("[traffic] failed to write blob %s: %v", h, err)
			return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
		}
	}
	sb := storedBody{hash: h, index: indexText()}
	if text {
		sb.inline = []byte(truncateUTF8(body, blobPreview))
	} else {
		sb.inline = []byte(binaryTag(contentType, body))
	}
	return sb
}

// binaryTypes are content-type prefixes whose bodies are never worth indexing or
// previewing as text. Anything not listed is treated as text (with a NUL-byte
// check as backstop), so unusual-but-searchable types like application/sql or a
// bare text/* are not silently dropped from the index.
var binaryTypes = []string{
	"image/", "audio/", "video/", "font/",
	"application/octet-stream", "application/zip", "application/gzip",
	"application/x-gzip", "application/x-tar", "application/x-7z-compressed",
	"application/x-rar", "application/pdf", "application/x-msdownload",
	"application/vnd.android.package-archive", "application/java-archive",
	"application/wasm", "application/x-shockwave-flash",
}

func isBinaryBody(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, p := range binaryTypes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	// Backstop for mislabeled or absent content types: real text does not carry
	// NUL bytes, so a NUL in the head of the body means binary regardless.
	return bytes.IndexByte(clipBytes(body, 512), 0) >= 0
}

// binaryTag describes a spilled binary body in one line, including the leading
// magic bytes so a reader can recognize the format without downloading it.
func binaryTag(contentType string, body []byte) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		ct = "application/octet-stream"
	}
	magic := hex.EncodeToString(clipBytes(body, 4))
	return fmt.Sprintf("[binary %s, %d bytes, magic=%s]", ct, len(body), magic)
}

func clipBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// truncateUTF8 cuts b to at most n bytes without splitting a multi-byte rune,
// so a preview never ends in half a CJK character.
func truncateUTF8(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	b = b[:n]
	// A rune is at most 4 bytes, so backing off 3 bytes always finds the boundary
	// (unless the input was already invalid UTF-8, in which case we keep the cut).
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		if r, size := utf8.DecodeLastRune(b); r != utf8.RuneError || size != 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullIfZero stores "no task" as NULL rather than 0, so a row that belongs to no
// run is distinguishable from a task id that could never exist.
func nullIfZero(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func headerLines(h map[string][]string) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// requestHeaderLines restores the HTTP Host header, which net/http stores on
// Request.Host rather than in Header. Keeping it in request.http makes the raw
// capture complete and directly replayable.
//
// Proxy-Authorization is the one header dropped: it carries the run's gateway
// session credential, the gateway consumes it, and the capture is a plaintext
// file tree served back through the traffic API.
func requestHeaderLines(req *mproxy.Request) string {
	headers := req.Header.Clone()
	headers.Del("Host")
	headers.Del("Proxy-Authorization")
	host := req.URL.Host
	if raw := req.Raw(); raw != nil && strings.TrimSpace(raw.Host) != "" {
		host = raw.Host
	}
	var b strings.Builder
	if host = strings.TrimSpace(host); host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteByte('\n')
	}
	b.WriteString(headerLines(headers))
	return b.String()
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	out := r.Replace(s)
	if out == "" || out == "_" {
		return "root"
	}
	// The store keeps its own directories (_index, _blobs, _ca,
	// _delete_staging) beside the host directories, so no host may claim an
	// underscore-prefixed name: a host called "_index" would otherwise map onto
	// the store's own index, which a delete or archive then moves away.
	if strings.HasPrefix(out, "_") {
		out = "host" + out
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

var blobHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// blobPath locates a stored blob. Current writes use one bucket level; blobs
// written before that change used two, so both layouts are probed rather than
// migrated.
func (t *Traffic) blobPath(hash string) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	// Validated as pure hex before touching the filesystem, so a crafted hash can
	// never traverse out of the blob directory.
	if !blobHashRe.MatchString(hash) {
		return "", fmt.Errorf("invalid blob hash")
	}
	for _, p := range []string{
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin"),
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("blob %s does not exist", hash)
}

// Blob opens a spilled body for streaming; the caller must close the file.
// Streaming matters here: the driver exposes no incremental BLOB API, so keeping
// large bodies on disk is what lets them be served without loading them whole.
func (t *Traffic) Blob(hash string) (*os.File, int64, error) {
	p, err := t.blobPath(hash)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// BlobRange reads at most length bytes of a blob from offset, and reports the
// blob's total size. Used by the agent tool to page through a large body without
// pulling all of it into the model's context.
func (t *Traffic) BlobRange(hash string, offset, length int64) (data []byte, total int64, err error) {
	f, size, err := t.Blob(hash)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if offset < 0 {
		offset = 0
	}
	if offset >= size {
		return nil, size, nil
	}
	if length <= 0 || offset+length > size {
		length = size - offset
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, size, err
	}
	return buf[:n], size, nil
}

// ExchangeMeta is one row of the index (returned by Page and query).
type ExchangeMeta struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	RespLen     int    `json:"resp_len"`
	Path        string `json:"path"`
	// TaskID is the engagement task whose run made the request, 0 when no run
	// owns it (an ingested exchange, or one recorded before this was captured).
	TaskID int64 `json:"task_id,omitempty"`
}

// ftsFilter builds the SQL condition restricting rows to those whose indexed
// text matches term. ok is false when full-text search cannot serve the term —
// no FTS index on this build, or fewer than three characters, which the trigram
// tokenizer cannot match — leaving callers to fall back to metadata matching.
func (t *Traffic) ftsFilter(term string) (cond string, arg any, ok bool) {
	term = strings.TrimSpace(term)
	if !t.fts || utf8.RuneCountInString(term) < minTrigram {
		return "", nil, false
	}
	return `rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)`, ftsQuote(term), true
}

// ftsQuote wraps a term as an FTS5 string literal so that punctuation and query
// operators inside it (quotes, AND/OR/NEAR, *, ^) are matched literally instead
// of being parsed as query syntax.
func ftsQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// PageQuery bundles the optional filters and sort order for Page. Every filter
// is combined with AND; an empty string skips that filter, and a non-positive
// RespMin/RespMax skips the response-size bound, so the zero value lists
// everything. An empty Sort/Order defaults to newest-first by timestamp.
type PageQuery struct {
	Host    string // host substring
	TaskID  int64  // exact task id; 0 skips
	Method  string // exact method (case-insensitive)
	Query   string // broad search box: metadata columns OR captured text
	Body    string // content box: captured request/response text only (full-text)
	Path    string // url_template substring — the vulnerability's path
	Status  string // exact code ("404") or class bucket ("4xx")
	RespMin int64  // minimum resp_len, or <=0 when unset
	RespMax int64  // maximum resp_len, or <=0 when unset
	Sort    string // ts | status | resp_len (default ts)
	Order   string // asc | desc (default desc)
}

// sortColumns whitelists the columns Page may order by, so the caller-supplied
// Sort can never reach the SQL as anything but one of these fixed names.
var sortColumns = map[string]string{"ts": "ts", "status": "status", "resp_len": "resp_len"}

// statusFilter turns a status token into a SQL condition: an exact code ("404")
// matches that status, an "Nxx" class ("4xx") matches the whole hundreds band.
// ok is false for an empty or unrecognized token.
func statusFilter(s string) (cond string, args []any, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil, false
	}
	if len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] == 'x' && s[2] == 'x' {
		base := int(s[0]-'0') * 100
		return "status>=? AND status<?", []any{base, base + 100}, true
	}
	if n, err := strconv.Atoi(s); err == nil {
		return "status=?", []any{n}, true
	}
	return "", nil, false
}

// Page returns one page of exchange metadata for the traffic list, filtered by
// the criteria in f (all optional, combined with AND) and ordered by the
// requested column. Query is the broad search box (metadata columns OR, when the
// term is long enough for the trigram index, captured request/response text);
// Body narrows to exchanges whose captured text matches, via that same index.
// Also returns the total number of rows matching the filter (for the UI's
// pagination). Bodies are never included in the rows.
func (t *Traffic) Page(f PageQuery, page, size int) (rows []ExchangeMeta, total int, err error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	if page < 0 {
		page = 0
	}
	where := ""
	var args []any
	add := func(cond string, vs ...any) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += cond
		args = append(args, vs...)
	}
	if h := strings.TrimSpace(f.Host); h != "" {
		add("host LIKE ?", "%"+h+"%")
	}
	if f.TaskID > 0 {
		add("task_id=?", f.TaskID)
	}
	if m := strings.TrimSpace(f.Method); m != "" {
		add("method=?", strings.ToUpper(m))
	}
	if p := strings.TrimSpace(f.Path); p != "" {
		add("url_template LIKE ?", "%"+p+"%")
	}
	if cond, sargs, ok := statusFilter(f.Status); ok {
		add(cond, sargs...)
	}
	if f.RespMin > 0 {
		add("resp_len>=?", f.RespMin)
	}
	if f.RespMax > 0 {
		add("resp_len<=?", f.RespMax)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + s + "%"
		const meta = "host LIKE ? OR url LIKE ? OR url_template LIKE ? OR method LIKE ? OR content_type LIKE ? OR CAST(status AS TEXT) LIKE ?"
		// Metadata match OR full-text match: one search box, widest recall. Terms
		// too short for trigram silently fall back to metadata only.
		if cond, arg, ok := t.ftsFilter(s); ok {
			add("(("+meta+") OR "+cond+")", like, like, like, like, like, like, arg)
		} else {
			add("("+meta+")", like, like, like, like, like, like)
		}
	}
	// Body is the dedicated content box: it only searches captured request/response
	// text, so it goes straight to the full-text index with no metadata fallback. A
	// term too short for the trigram tokenizer cannot be served and is skipped
	// rather than guessed at — the UI hints at the three-character minimum.
	if b := strings.TrimSpace(f.Body); b != "" {
		if cond, arg, ok := t.ftsFilter(b); ok {
			add(cond, arg)
		}
	}
	if err = t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	col := sortColumns[strings.ToLower(strings.TrimSpace(f.Sort))]
	if col == "" {
		col = "ts"
	}
	dir := "DESC"
	if strings.EqualFold(strings.TrimSpace(f.Order), "asc") {
		dir = "ASC"
	}
	// id embeds capture timestamp + sequence, so a trailing id DESC makes the order
	// total and pagination stable even when the sort column has many ties.
	sel := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path,COALESCE(task_id,0) FROM exchanges` +
		where + ` ORDER BY ` + col + ` ` + dir + `, id DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), size, page*size)
	rs, err := t.db.Query(sel, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var m ExchangeMeta
		if err := rs.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path, &m.TaskID); err != nil {
			return nil, 0, err
		}
		rows = append(rows, m)
	}
	return rows, total, rs.Err()
}

// Get returns the full request/response text of one exchange. Bodies come from
// the database; rows recorded before bodies moved into SQLite carry a non-empty
// path and are read from the legacy on-disk tree instead, so history stays
// readable without being migrated.
func (t *Traffic) Get(id string) (req, resp string, err error) {
	var reqHead, respHead string
	var reqBody, respBody []byte
	var reqBlob, respBlob sql.NullString
	var reqLen, respLen int
	err = t.db.QueryRow(`SELECT b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob,e.req_len,e.resp_len
FROM exchange_bodies b JOIN exchanges e ON e.id=b.id WHERE b.id=?`, id).
		Scan(&reqHead, &reqBody, &reqBlob, &respHead, &respBody, &respBlob, &reqLen, &respLen)
	if err == nil {
		return assembleRaw(reqHead, reqBody, reqBlob, reqLen), assembleRaw(respHead, respBody, respBlob, respLen), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}

	var rel string
	if err = t.db.QueryRow(`SELECT path FROM exchanges WHERE id=?`, id).Scan(&rel); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(rel) == "" {
		return "", "", fmt.Errorf("exchange %s has no body record", id)
	}
	rb, _ := os.ReadFile(filepath.Join(t.dir, rel, "request.http"))
	pb, _ := os.ReadFile(filepath.Join(t.dir, rel, "response.http"))
	return string(rb), string(pb), nil
}

// assembleRaw rebuilds one side's raw HTTP text: head, blank line, body. A body
// that spilled to the blob store shows its inline preview followed by the blob
// pointer, so the reader can see what it is and fetch the rest by hash.
func assembleRaw(head string, body []byte, blob sql.NullString, total int) string {
	var b strings.Builder
	b.WriteString(head)
	if !strings.HasSuffix(head, "\n") {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(body)
	if blob.Valid && blob.String != "" {
		fmt.Fprintf(&b, "\n…[truncated] @blob sha256:%s (len=%d)", blob.String, total)
	}
	return b.String()
}

// HostCount is one distinct recorded host plus its exchange count.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// Hosts returns distinct recorded hosts with exchange counts, most recent
// activity first — powers the page's target picker.
func (t *Traffic) Hosts() ([]HostCount, error) {
	rows, err := t.db.Query(`SELECT host, COUNT(*) AS n, MAX(ts) AS last FROM exchanges GROUP BY host ORDER BY last DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCount
	for rows.Next() {
		var h HostCount
		var last int64
		if err := rows.Scan(&h.Host, &h.Count, &last); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Count returns total recorded exchanges.
func (t *Traffic) Count() (int, error) {
	var n int
	err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
	return n, err
}

// likeContains builds a LIKE pattern matching s literally anywhere in the
// value. `_` and `%` are LIKE wildcards and a hostname may contain either, so
// both — and the escape character itself — are escaped: without this, deleting
// "a_b" also deleted "axb".
func likeContains(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s) + "%"
}

// DeleteHost removes every recorded exchange whose host contains the given
// substring — mirroring the UI's host filter, so what you filtered is what gets
// deleted. Everything lives in SQLite, so the deletion is one transaction across
// the index, bodies, full-text index and blob references. Content-addressed
// blobs are shared across hosts and so are garbage-collected afterwards rather
// than deleted by host. Returns rows deleted.
func (t *Traffic) DeleteHost(host string) (int64, error) {
	like := likeContains(host)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	// Resolved before the rows go away: with a substring match, the index is the
	// only record of which host directories the filter actually hit.
	legacy, err := t.hostTrees(`host LIKE ? ESCAPE '\'`, like)
	if err != nil {
		return 0, err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	n, err := t.deleteWhere(tx, `host LIKE ? ESCAPE '\'`, like)
	if err != nil {
		return 0, err
	}
	// Staged before the commit so a filesystem failure can still abort the whole
	// deletion, and before gcBlobs so reference collection sees the correct live
	// set — a staged tree is invisible to it.
	stageDir, moves, err := t.stageTrees(legacy, nil)
	if err != nil {
		return 0, errors.Join(err, restoreTrees(stageDir, moves))
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.Join(fmt.Errorf("submit traffic index deletion: %w", err), restoreTrees(stageDir, moves))
	}
	t.reapStage(stageDir)
	if n > 0 {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// DeleteAll removes every recorded exchange — the page's clear-everything
// action. It differs from the host-scoped deletions in two ways. It sweeps host
// directories without consulting the index, because "clear everything" should
// leave nothing behind and a directory whose rows are already gone would
// otherwise survive. And it ends with a full compaction: VACUUM costs what it
// keeps, so an emptied index is the one moment it is free, and it is also the
// only way to switch on auto_vacuum for a database created without it.
//
// Evidence already bound to a finding is untouched. Those bodies were copied
// into the evidence store when they were bound, precisely so that disposable
// traffic could be cleared without taking proof with it.
//
// Returns the number of exchanges deleted and how many bytes of index the
// compaction handed back.
func (t *Traffic) DeleteAll() (deleted int64, reclaimed int64, err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	before := t.indexBytes()
	trees, err := t.allHostTrees()
	if err != nil {
		return 0, 0, err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	if deleted, err = t.deleteWhere(tx, `1=1`); err != nil {
		return 0, 0, err
	}
	// Staged before the commit so a filesystem failure can still abort the whole
	// deletion, exactly as in DeleteHost.
	stageDir, moves, err := t.stageTrees(trees, nil)
	if err != nil {
		return 0, 0, errors.Join(err, restoreTrees(stageDir, moves))
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, errors.Join(fmt.Errorf("submit traffic index deletion: %w", err), restoreTrees(stageDir, moves))
	}
	t.reapStage(stageDir)
	if err := t.gcBlobs(); err != nil {
		return deleted, 0, err
	}
	if err := t.compactIndex(); err != nil {
		// The deletion is already durable; compaction is disk space, not
		// correctness, so it must not turn a completed purge into a failed one.
		log.Printf("[traffic] index compaction failed: %v", err)
		return deleted, 0, nil
	}
	return deleted, before - t.indexBytes(), nil
}

// allHostTrees lists every host directory left by the pre-SQLite layout. Unlike
// hostTrees it does not go through the index, so it also finds directories whose
// rows are already gone. Underscore-prefixed entries are the store's own
// (_index, _blobs, _ca, _delete_staging) and are never hosts.
func (t *Traffic) allHostTrees() ([]string, error) {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			dirs = append(dirs, filepath.Join(t.dir, e.Name()))
		}
	}
	return dirs, nil
}

// compactIndex rewrites the index into a fresh file, which is what actually
// returns its pages to the filesystem. VACUUM's runtime and temporary space
// scale with the content it keeps, so this is only reached right after DeleteAll
// has emptied the index — never as a routine step. It doubles as the conversion
// path for a database created before auto_vacuum=incremental: that pragma only
// takes effect through the VACUUM that follows it, and both must run on the same
// connection. Callers must hold wmu.
func (t *Traffic) compactIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if t.fts {
		// A full merge, not the bounded one reclaim uses: with the index emptied
		// there is nothing left to merge, so this only discards the tombstones.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts) VALUES('optimize')`); err != nil {
			return fmt.Errorf("merge full-text index: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA auto_vacuum=incremental`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("compact index: %w", err)
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	// A legacy database has just been converted, so later deletions can reclaim
	// space on their own instead of waiting for another purge.
	t.incrementalVacuum = mode == autoVacuumIncremental
	if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("truncate WAL: %w", err)
	}
	return nil
}

// deleteWhere removes every trace of the exchanges matching the condition:
// full-text index rows, bodies, blob references, and finally the index rows.
// Order matters — each sub-select reads exchanges, so that table is emptied last.
func (t *Traffic) deleteWhere(tx *sql.Tx, where string, args ...any) (int64, error) {
	if t.fts {
		// ex_fts is contentless and addressed by rowid, hence the rowid sub-select.
		if _, err := tx.Exec(`DELETE FROM ex_fts WHERE rowid IN (SELECT rowid FROM exchanges WHERE `+where+`)`, args...); err != nil {
			return 0, fmt.Errorf("delete full-text index: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("delete bodies: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE exchange_id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("delete blob references: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM exchanges WHERE `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("delete index rows: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// hostTrees returns the on-disk directory of every host matching the condition.
// Exchanges recorded since bodies moved into SQLite have no directory at all, so
// most of these paths simply will not exist — staging skips those. The lookup is
// deliberately not restricted to rows with a path: a host whose index rows are
// already gone can still have an orphaned directory, and deleting the host should
// take that with it.
func (t *Traffic) hostTrees(where string, args ...any) ([]string, error) {
	rows, err := t.db.Query(`SELECT DISTINCT host FROM exchanges WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dirs []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		dirs = append(dirs, filepath.Join(t.dir, sanitize(h)))
	}
	return dirs, rows.Err()
}

type stagedTrafficPath struct {
	source string
	staged string
}

// A staging journal has one of two scopes, and recovery must never convert one
// into the other: a version-2 journal was written by an operation that selected
// exact exchange IDs, so replaying it may only remove those IDs.
const (
	// hostDeleteStageVersionHosts is a host-scoped stage (the page's exact-host
	// delete, and every archive compaction written before ID scoping). Recovery
	// finishes it by deleting the journal's hosts, which is what its writer did.
	hostDeleteStageVersionHosts = 1
	// hostDeleteStageVersionExchanges is a task- or archive-scoped stage. It
	// carries the exact IDs and no host, because a task operation never selects
	// by host.
	hostDeleteStageVersionExchanges = 2
)

type hostDeleteStageJournal struct {
	Version     int                   `json:"version"`
	ArchiveID   int64                 `json:"archive_id,omitempty"`
	TaskID      int64                 `json:"task_id,omitempty"`
	Hosts       []string              `json:"hosts,omitempty"`
	ExchangeIDs []string              `json:"exchange_ids,omitempty"`
	Moves       []hostDeleteStageMove `json:"moves,omitempty"`
}

type hostDeleteStageMove struct {
	Source string `json:"source"`
	Staged string `json:"staged"`
}

const hostDeleteStageJournalName = "journal.json"

// stageTrees moves host directories aside onto the same filesystem. The rename is
// atomic and instant, which buys two things the unlink cannot: the deletion stays
// reversible until the transaction commits, and the tree stops being visible to
// blob reference collection right away (legacyBlobRefs skips underscore-prefixed
// directories, so anything under _delete_staging is already out of the live set).
// hosts is the journal's host list, which is what tells recovery whether the
// rows of a host-scoped stage are already gone. An empty stageDir is returned
// when there was nothing to stage.
func (t *Traffic) stageTrees(dirs, hosts []string) (stageDir string, moves []stagedTrafficPath, err error) {
	seen := make(map[string]struct{}, len(dirs))
	planned := make([]stagedTrafficPath, 0, len(dirs))
	for _, source := range dirs {
		if _, dup := seen[source]; dup {
			continue
		}
		seen[source] = struct{}{}
		// Only a direct child of the store, and never one of the store's own
		// underscore-prefixed directories, may be moved: a host named "_index"
		// must not take the index, the blobs or the CA with it.
		if base := filepath.Base(source); strings.HasPrefix(base, "_") || filepath.Dir(filepath.Clean(source)) != filepath.Clean(t.dir) {
			log.Printf("[traffic] refusing to stage %s: not a host directory", source)
			continue
		}
		if _, err := os.Lstat(source); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return stageDir, moves, fmt.Errorf("check historical traffic directory %s: %w", source, err)
		}
		planned = append(planned, stagedTrafficPath{source: source})
	}
	// A host-scoped delete must still leave a journal when there is not a single
	// historical host directory to move (traffic on a fresh install lands only in
	// SQLite + _blobs): if the crash point falls between the SQLite commit and
	// the background unlink, the journal's hosts are what tell recovery the rows
	// are already gone instead of restoring trees whose rows no longer exist.
	uniqueHosts := uniqueArchiveHosts(hosts)
	if len(planned) == 0 && len(uniqueHosts) == 0 {
		return "", nil, nil
	}
	parent := filepath.Join(t.dir, "_delete_staging")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, fmt.Errorf("create traffic staging directory: %w", err)
	}
	if stageDir, err = os.MkdirTemp(parent, "hosts-"); err != nil {
		return "", nil, fmt.Errorf("create traffic staging directory: %w", err)
	}
	journal := hostDeleteStageJournal{Version: hostDeleteStageVersionHosts, Hosts: uniqueHosts}
	for i := range planned {
		planned[i].staged = filepath.Join(stageDir, fmt.Sprintf("%d-%s", i, filepath.Base(planned[i].source)))
		journal.Moves = append(journal.Moves, hostDeleteStageMove{Source: planned[i].source, Staged: planned[i].staged})
	}
	if err := writeHostDeleteStageJournal(filepath.Join(stageDir, hostDeleteStageJournalName), journal); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", nil, err
	}
	for _, move := range planned {
		source, staged := move.source, move.staged
		if err := os.Rename(source, staged); err != nil {
			return stageDir, moves, fmt.Errorf("move out historical traffic directory %s: %w", source, err)
		}
		moves = append(moves, stagedTrafficPath{source: source, staged: staged})
	}
	return stageDir, moves, nil
}

func writeHostDeleteStageJournal(path string, journal hostDeleteStageJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// restoreTrees puts staged directories back where they came from, newest move
// first, and drops the staging directory once everything is home.
func restoreTrees(stageDir string, moves []stagedTrafficPath) error {
	var errs []error
	for i := len(moves) - 1; i >= 0; i-- {
		move := moves[i]
		if _, err := os.Lstat(move.source); err == nil {
			errs = append(errs, fmt.Errorf("restore destination already exists: %s", move.source))
			continue
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("inspect restore destination %s: %w", move.source, err))
			continue
		}
		if err := os.Rename(move.staged, move.source); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", move.source, err))
		}
	}
	if len(errs) == 0 && stageDir != "" {
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, fmt.Errorf("remove traffic stage: %w", err))
		}
	}
	return errors.Join(errs...)
}

// reapStage unlinks a committed staging directory in the background. This is the
// step that used to stall the recorder: a legacy tree mirrors the URL path per
// request and can hold hundreds of thousands of small files, and the whole unlink
// ran while the write lock was held. The rows are already gone by now, so losing
// this to a shutdown leaves garbage under _delete_staging, never inconsistent
// state.
func (t *Traffic) reapStage(stageDir string) {
	if stageDir == "" {
		return
	}
	t.reaping.Go(func() {
		if err := os.RemoveAll(stageDir); err != nil {
			log.Printf("[traffic] failed to clean up historical traffic directory %s: %v", stageDir, err)
		}
	})
}

// DeleteHostsExact removes recorded exchanges for a set of EXACT hosts (the
// batch path for the page's multi-select delete): index rows + each host's file
// tree, then one blob-GC pass. Exact match — unlike DeleteHost's substring —
// so picking "api.example.com" never sweeps "api.example.com.cn". Returns rows
// deleted. Duplicate hosts are harmless (idempotent deletes, single tree pass).
func (t *Traffic) DeleteHostsExact(hosts []string) (int64, error) {
	stage, err := t.StageDeleteHostsExact(hosts)
	if err != nil {
		return 0, err
	}
	deleted := stage.Deleted()
	if err := stage.Commit(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// HostDeleteStage keeps the SQLite delete transaction open so a task deletion or
// archive compaction can be coordinated with PostgreSQL: the traffic side is
// staged here and only committed once the caller's own transaction has
// succeeded. The Traffic write lock is held until Commit or Rollback, so no
// recorder can add rows or a blob reference for the exchanges that are
// mid-deletion. Rollback restores any staged host tree and drops the journal.
type HostDeleteStage struct {
	traffic  *Traffic
	tx       *sql.Tx
	stageDir string
	moves    []stagedTrafficPath
	deleted  int64
	done     bool
}

// Deleted reports the number of exchange rows selected by this stage.
func (s *HostDeleteStage) Deleted() int64 {
	if s == nil {
		return 0
	}
	return s.deleted
}

// StageDeleteHostsExact prepares a reversible exact-host deletion. Callers must
// finish every successful stage with Commit or Rollback. The journal names the
// hosts, so recovery can tell a committed stage (rows already gone) from one
// whose transaction rolled back (trees must come home).
func (t *Traffic) StageDeleteHostsExact(hosts []string) (*HostDeleteStage, error) {
	t.wmu.Lock()
	stage := &HostDeleteStage{traffic: t}
	fail := func(cause error) (*HostDeleteStage, error) {
		if rollbackErr := stage.rollbackLocked(); rollbackErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("rollback traffic deletion: %w", rollbackErr))
		}
		return nil, cause
	}
	abort := func(cause error) (*HostDeleteStage, error) {
		t.wmu.Unlock()
		stage.done = true
		return nil, cause
	}

	unique := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		unique = append(unique, host)
	}

	// Exact hosts are known up front, so their directories are derived directly
	// rather than looked up: a host whose index rows are already gone can still
	// own an orphaned directory that this deletion should take with it.
	legacy := make([]string, 0, len(unique))
	for _, h := range unique {
		legacy = append(legacy, filepath.Join(t.dir, sanitize(h)))
	}

	tx, err := t.db.Begin()
	if err != nil {
		return abort(err)
	}
	stage.tx = tx
	for _, h := range unique {
		n, err := t.deleteWhere(tx, `host=?`, h)
		if err != nil {
			return fail(err)
		}
		stage.deleted += n
	}

	stage.stageDir, stage.moves, err = t.stageTrees(legacy, unique)
	if err != nil {
		return fail(err)
	}
	return stage, nil
}

// dbResidentPath restricts a task operation to rows whose bodies live in SQLite.
// A row with a legacy path still has its bodies in a pre-SQLite host tree, which
// a task operation never moves, so such a row is left in place rather than
// guessed at.
const dbResidentPath = `COALESCE(path,'')=''`

// exchangeIDBatch bounds one IN (...) statement. SQLite's default parameter
// ceiling is 32766, and one task can own more exchanges than that.
const exchangeIDBatch = 512

// StageDeleteTask stages deletion of every exchange with task_id = taskID.
// Ownership is the whole selection: hosts are never consulted, so a capture at a
// host with no registered asset is still deleted, while another run's exchanges
// and unattributed history at the same host are untouched.
func (t *Traffic) StageDeleteTask(taskID int64) (*HostDeleteStage, error) {
	if taskID <= 0 {
		return nil, errors.New("task id must be positive")
	}
	return t.stageExchanges(func(tx *sql.Tx) ([]string, int, error) {
		return t.selectExchangeIDs(tx, `task_id=? AND `+dbResidentPath, taskID)
	}, 0, taskID)
}

// StageDeleteExchangesForArchive stages deletion of exactly ids, each re-checked
// as task_id = taskID. The archive worker passes the IDs it exported, so rows
// captured after the snapshot stay hot and a re-selection by task can never
// delete evidence the package does not contain.
func (t *Traffic) StageDeleteExchangesForArchive(ids []string, archiveID, taskID int64) (*HostDeleteStage, error) {
	if archiveID <= 0 || taskID <= 0 {
		return nil, errors.New("archive and task ids must be positive")
	}
	return t.stageExchanges(func(tx *sql.Tx) ([]string, int, error) {
		var selected []string
		var legacy int
		for start := 0; start < len(ids); start += exchangeIDBatch {
			batch := ids[start:min(start+exchangeIDBatch, len(ids))]
			clause, args := inClause(batch)
			found, skipped, err := t.selectExchangeIDs(tx, `id IN (`+clause+`) AND task_id=? AND `+dbResidentPath, append(args, taskID)...)
			if err != nil {
				return nil, 0, err
			}
			selected = append(selected, found...)
			legacy += skipped
		}
		return selected, legacy, nil
	}, archiveID, taskID)
}

// stageExchanges deletes the rows chosen by selectIDs and journals their exact
// IDs. The traffic write lock is held until Commit or Rollback, so no recorder
// can add a row or a blob reference to a task that is mid-deletion.
func (t *Traffic) stageExchanges(selectIDs func(*sql.Tx) ([]string, int, error), archiveID, taskID int64) (*HostDeleteStage, error) {
	t.wmu.Lock()
	stage := &HostDeleteStage{traffic: t}
	fail := func(cause error) (*HostDeleteStage, error) {
		if rollbackErr := stage.rollbackLocked(); rollbackErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("rollback traffic deletion: %w", rollbackErr))
		}
		return nil, cause
	}
	tx, err := t.db.Begin()
	if err != nil {
		t.wmu.Unlock()
		stage.done = true
		return nil, err
	}
	stage.tx = tx
	ids, legacy, err := selectIDs(tx)
	if err != nil {
		return fail(err)
	}
	if legacy > 0 {
		log.Printf("[traffic] task %d: %d exchange(s) still point at a pre-SQLite host tree and were left in place", taskID, legacy)
	}
	if len(ids) == 0 {
		return stage, nil
	}
	for start := 0; start < len(ids); start += exchangeIDBatch {
		batch := ids[start:min(start+exchangeIDBatch, len(ids))]
		clause, args := inClause(batch)
		n, err := t.deleteWhere(tx, `id IN (`+clause+`)`, args...)
		if err != nil {
			return fail(err)
		}
		stage.deleted += n
	}
	stage.stageDir, err = t.writeExchangeStageJournal(ids, archiveID, taskID)
	if err != nil {
		return fail(err)
	}
	return stage, nil
}

// selectExchangeIDs returns the IDs matched by where, split into rows whose
// bodies live in SQLite and rows that still point at a pre-SQLite host tree.
func (t *Traffic) selectExchangeIDs(tx *sql.Tx, where string, args ...any) (ids []string, legacy int, err error) {
	rows, err := tx.Query(`SELECT id,COALESCE(path,'') FROM exchanges WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, path string
		if err := rows.Scan(&id, &path); err != nil {
			return nil, 0, err
		}
		if path != "" {
			legacy++
			continue
		}
		ids = append(ids, id)
	}
	return ids, legacy, rows.Err()
}

func inClause(values []string) (string, []any) {
	placeholders := make([]string, len(values))
	args := make([]any, len(values))
	for i, value := range values {
		placeholders[i] = "?"
		args[i] = value
	}
	return strings.Join(placeholders, ","), args
}

// writeExchangeStageJournal records the exact IDs a task or archive stage
// deleted. Nothing is moved on disk, so this journal exists only to let restart
// recovery finish a deletion whose SQLite commit was lost — and it names no
// host, so recovery cannot widen it.
func (t *Traffic) writeExchangeStageJournal(ids []string, archiveID, taskID int64) (string, error) {
	parent := filepath.Join(t.dir, "_delete_staging")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create traffic staging directory: %w", err)
	}
	stageDir, err := os.MkdirTemp(parent, "exchanges-")
	if err != nil {
		return "", fmt.Errorf("create traffic staging directory: %w", err)
	}
	journal := hostDeleteStageJournal{
		Version:     hostDeleteStageVersionExchanges,
		ArchiveID:   archiveID,
		TaskID:      taskID,
		ExchangeIDs: ids,
	}
	if err := writeHostDeleteStageJournal(filepath.Join(stageDir, hostDeleteStageJournalName), journal); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", err
	}
	return stageDir, nil
}

// RecoverHostDeleteStages resolves stages left by a process exit. SQLite rolls
// open transactions back on restart, while the supplied callback identifies task
// archives (and task deletions) whose PostgreSQL commit already happened.
//
// A version-1 journal is host-scoped and is finished the way its writer would
// have finished it. A version-2 journal carries the exact exchange IDs of a task
// or archive operation and no host, so replaying it can only remove those IDs —
// it can never widen back to a host.
func (t *Traffic) RecoverHostDeleteStages(archiveCommitted func(int64, int64) (bool, error)) error {
	if t == nil {
		return nil
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	parent := filepath.Join(t.dir, "_delete_staging")
	entries, err := os.ReadDir(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	needsGC := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		stageDir := filepath.Join(parent, entry.Name())
		raw, err := os.ReadFile(filepath.Join(stageDir, hostDeleteStageJournalName))
		if os.IsNotExist(err) {
			// Older versions did not persist enough information for lossless
			// recovery. Keep the directory for manual inspection.
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var journal hostDeleteStageJournal
		if err := json.Unmarshal(raw, &journal); err != nil {
			errs = append(errs, fmt.Errorf("read traffic staging journal %s: %w", stageDir, err))
			continue
		}
		if journal.Version != hostDeleteStageVersionHosts && journal.Version != hostDeleteStageVersionExchanges {
			errs = append(errs, fmt.Errorf("traffic staging journal %s has unsupported version %d", stageDir, journal.Version))
			continue
		}
		moves := make([]stagedTrafficPath, 0, len(journal.Moves))
		for _, move := range journal.Moves {
			if !pathWithin(t.dir, move.Source) || !pathWithin(stageDir, move.Staged) {
				errs = append(errs, fmt.Errorf("traffic staging journal contains an out-of-bounds path: %s", stageDir))
				moves = nil
				break
			}
			if _, err := os.Lstat(move.Staged); err == nil {
				moves = append(moves, stagedTrafficPath{source: move.Source, staged: move.Staged})
			} else if !os.IsNotExist(err) {
				errs = append(errs, err)
				moves = nil
				break
			}
		}
		if moves == nil {
			continue
		}
		committed := false
		if journal.ArchiveID > 0 {
			if archiveCommitted == nil {
				errs = append(errs, fmt.Errorf("traffic archive %d has no stateful parser", journal.ArchiveID))
				continue
			}
			committed, err = archiveCommitted(journal.ArchiveID, journal.TaskID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		} else if journal.TaskID > 0 {
			// A task-delete stage: ask PostgreSQL whether the task still exists.
			// hostsHaveNoExchanges cannot decide this, because SQLite has already
			// rolled the rows back by the time recovery runs.
			if archiveCommitted == nil {
				errs = append(errs, fmt.Errorf("traffic staging journal %s needs a task lookup", stageDir))
				continue
			}
			committed, err = archiveCommitted(0, journal.TaskID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		} else if len(journal.Hosts) > 0 {
			committed, err = t.hostsHaveNoExchanges(journal.Hosts)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if !committed {
			// Nothing was committed, so an ID-scoped stage has nothing to put
			// back: its transaction rolled back with every row intact. Restoring
			// also drops the now-stale journal.
			if err := restoreTrees(stageDir, moves); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if journal.Version == hostDeleteStageVersionExchanges {
			if err := t.deleteArchivedExchanges(journal.ExchangeIDs); err != nil {
				errs = append(errs, err)
				continue
			}
		} else if err := t.deleteArchivedHosts(journal.Hosts); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, err)
			continue
		}
		needsGC = true
	}
	if needsGC {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *Traffic) hostsHaveNoExchanges(hosts []string) (bool, error) {
	for _, host := range hosts {
		var count int
		if err := t.db.QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

func (t *Traffic) deleteArchivedHosts(hosts []string) error {
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, host := range hosts {
		if _, err := t.deleteWhere(tx, `host=?`, host); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// deleteArchivedExchanges finishes a committed ID-scoped stage. The IDs are the
// ones the journal recorded, so a row captured after that point is never
// selected, whatever task it belongs to.
func (t *Traffic) deleteArchivedExchanges(ids []string) error {
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for start := 0; start < len(ids); start += exchangeIDBatch {
		batch := ids[start:min(start+exchangeIDBatch, len(ids))]
		clause, args := inClause(batch)
		if _, err := t.deleteWhere(tx, `id IN (`+clause+`)`, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func pathWithin(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, candidateAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// Rollback discards the staged deletion, leaving the traffic store untouched.
func (s *HostDeleteStage) Rollback() error {
	if s == nil || s.done {
		return nil
	}
	return s.rollbackLocked()
}

func (s *HostDeleteStage) rollbackLocked() error {
	if s == nil || s.done {
		return nil
	}
	var errs []error
	if s.tx != nil {
		if err := s.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			errs = append(errs, fmt.Errorf("rollback traffic index: %w", err))
		}
	}
	if err := restoreTrees(s.stageDir, s.moves); err != nil {
		errs = append(errs, err)
	}
	s.done = true
	s.traffic.wmu.Unlock()
	return errors.Join(errs...)
}

// Commit makes the staged deletion permanent. SQLite is committed only after
// the caller has committed its PostgreSQL task deletion.
func (s *HostDeleteStage) Commit() error {
	if s == nil || s.done {
		return nil
	}
	if err := s.tx.Commit(); err != nil {
		// A failed SQLite commit normally rolls the transaction back. Restore the
		// trees so the traffic store remains internally consistent and recoverable.
		restoreErr := restoreTrees(s.stageDir, s.moves)
		s.done = true
		s.traffic.wmu.Unlock()
		return errors.Join(fmt.Errorf("submit traffic index deletion: %w", err), restoreErr)
	}
	// Unlinking the staged trees is what used to hold the write lock for hours;
	// it now runs in the background, while collection below only needs them to be
	// out of the live tree — which the staging rename already guaranteed.
	s.traffic.reapStage(s.stageDir)
	s.traffic.reclaim()
	var errs []error
	if err := s.traffic.gcBlobs(); err != nil {
		errs = append(errs, fmt.Errorf("reclaim traffic blobs: %w", err))
	}
	s.done = true
	s.traffic.wmu.Unlock()
	return errors.Join(errs...)
}

// indexBytes is the index's real footprint on disk: the database plus its
// write-ahead log and shared-memory file, since those are what an operator sees
// the data directory holding.
func (t *Traffic) indexBytes() int64 {
	base := filepath.Join(t.dir, "_index", "index.sqlite")
	var total int64
	for _, p := range []string{base, base + "-wal", base + "-shm"} {
		if st, err := os.Stat(p); err == nil {
			total += st.Size()
		}
	}
	return total
}

// reclaim hands space freed by a deletion back to the filesystem. Deleting rows
// only makes them invisible: SQLite chains their pages onto a freelist, and
// deleting from the contentless_delete full-text index writes tombstones rather
// than removing the postings they hide. Neither shrinks a single byte on disk,
// and since bodies below maxInlineBody live in that same file, an install that
// captures heavily ends up holding far more than the traffic it still has.
//
// The work is done in the background, in bounded steps that drop the write lock
// between them, because it is proportional to what was deleted — freeing several
// gigabytes under one lock would stall record(), which go-mitmproxy calls before
// it replies to the client, and so would stall the requests being recorded.
// Safe to call with wmu held: the background pass simply waits for it.
//
// Best-effort throughout. Failing to reclaim costs disk space, never
// correctness, so errors are logged and the next deletion resumes the work.
func (t *Traffic) reclaim() {
	if !t.reclaiming.CompareAndSwap(false, true) {
		return // one pass at a time; a second would only contend for the lock
	}
	t.reaping.Go(func() {
		defer t.reclaiming.Store(false)
		// One pinned connection for the whole pass: a long reclamation issues
		// hundreds of statements, and letting the pool hand each one a different
		// connection would both churn connections and split the freelist readings
		// that decide when to stop away from the vacuum they measure.
		ctx := context.Background()
		conn, err := t.db.Conn(ctx)
		if err != nil {
			log.Printf("[traffic] index space reclamation failed (acquire connection): %v", err)
			return
		}
		defer conn.Close()
		deadline := time.Now().Add(reclaimBudget)
		merges := reclaimMergeSteps
		for step := 0; ; step++ {
			t.wmu.Lock()
			progressed, err := t.reclaimChunk(ctx, conn, &merges)
			t.wmu.Unlock()
			if err != nil {
				log.Printf("[traffic] index space reclamation failed: %v", err)
				return
			}
			if !progressed {
				break
			}
			if t.stopping() {
				return // shutdown must not wait out the remaining budget
			}
			if step+1 >= reclaimMaxSteps {
				log.Printf("[traffic] index space reclamation incomplete (reached the %d-step cap); will continue on the next delete", reclaimMaxSteps)
				return
			}
			if time.Now().After(deadline) {
				log.Printf("[traffic] index space reclamation incomplete (used up the %s budget); will continue on the next delete", reclaimBudget)
				return
			}
		}
		// Truncating the log is what makes the reclamation visible on disk: in WAL
		// mode the freed pages are recorded there first, and a PASSIVE checkpoint
		// would leave the log itself sitting at its high-water mark.
		t.wmu.Lock()
		defer t.wmu.Unlock()
		if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			log.Printf("[traffic] WAL truncation failed: %v", err)
		}
	})
}

// reclaimChunk does one bounded step and reports whether it made progress, which
// is what the caller loops on. merges carries the remaining full-text merge
// budget and is spent down here. Callers must hold wmu.
func (t *Traffic) reclaimChunk(ctx context.Context, conn *sql.Conn, merges *int) (bool, error) {
	progressed := false
	if t.fts && *merges > 0 {
		// A negative rank is fts5's page budget for one incremental merge.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts, rank) VALUES('merge', ?)`, -reclaimMergePages); err != nil {
			return false, fmt.Errorf("merge full-text index: %w", err)
		}
		*merges--
		progressed = true
	}
	if !t.incrementalVacuum {
		// incremental_vacuum is a silent no-op on a database created with
		// auto_vacuum=0; only a full compaction can convert one. Merging the
		// full-text index above still pays off, so stop here rather than earlier.
		return progressed, nil
	}
	var before, after int
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&before); err != nil {
		return false, err
	}
	if before == 0 {
		return progressed, nil
	}
	// The budget is a constant and PRAGMA arguments cannot be bound as parameters.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, reclaimChunkPages)); err != nil {
		return false, fmt.Errorf("reclaim index free pages: %w", err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&after); err != nil {
		return false, err
	}
	// Progress, not an empty freelist, is the right stopping condition:
	// incremental_vacuum can only release pages it manages to move to the end of
	// the file, so a residual freelist it cannot shrink is a normal outcome.
	return progressed || after < before, nil
}

// gcBlobs removes blobs that no remaining exchange references. Live references
// come from blob_refs, so collection is one query plus a sweep of the blob
// directory — no exchange body is ever read. Emptied bucket directories are
// removed as well; the previous file-scanning collector deleted only files and
// left the buckets behind permanently. Best-effort: walk errors only skip the
// affected entries. Callers must hold wmu so this never races a concurrent
// record() writing a fresh blob + reference.
func (t *Traffic) gcBlobs() error {
	refs := make(map[string]struct{})
	rows, err := t.db.Query(`SELECT DISTINCT hash FROM blob_refs`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		refs[h] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := t.legacyBlobRefs(refs); err != nil {
		return err
	}

	root := filepath.Join(t.dir, "_blobs", "sha256")
	var buckets []string
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			if p != root {
				buckets = append(buckets, p)
			}
			return nil
		}
		h := strings.TrimSuffix(d.Name(), ".bin")
		if _, ok := refs[h]; !ok {
			os.Remove(p)
		}
		return nil
	}); err != nil {
		return err
	}
	// Deepest first, so a two-level bucket left by the old layout collapses fully.
	// Remove fails harmlessly on a non-empty directory — exactly the guard needed
	// to avoid deleting a bucket that still holds live blobs.
	sort.Slice(buckets, func(i, j int) bool { return len(buckets[i]) > len(buckets[j]) })
	for _, b := range buckets {
		os.Remove(b)
	}
	return nil
}

// legacyBlobRefs adds hashes referenced by pre-SQLite exchanges, whose bodies are
// still .http files on disk holding "@blob sha256:<hex>" pointers. Without this
// the first collection after the upgrade would delete blobs that history still
// points at. Skipped entirely once no legacy rows remain — the steady state — so
// the tree walk is transitional rather than a permanent cost.
func (t *Traffic) legacyBlobRefs(refs map[string]struct{}) error {
	var n int
	if err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges WHERE path<>''`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	blobRe := regexp.MustCompile(`@blob sha256:([0-9a-f]{64})`)
	return filepath.WalkDir(t.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// _blobs/_index/_ca never contain references; skip their subtrees.
			if p != t.dir && strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if nm := d.Name(); nm != "request.http" && nm != "response.http" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range blobRe.FindAllSubmatch(b, -1) {
			refs[string(m[1])] = struct{}{}
		}
		return nil
	})
}

// query returns one page of exchange metadata filtered by host and/or a url
// substring. Default page size is intentionally small (3) to keep tool results
// lightweight and capped at 10; page is 0-based (page*limit offset).
func (t *Traffic) query(host, contains, bodyContains string, page, limit int) ([]ExchangeMeta, error) {
	if limit <= 0 {
		limit = 3
	}
	if limit > 10 {
		limit = 10
	}
	if page < 0 {
		page = 0
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges WHERE 1=1`
	args := []any{}
	if host != "" {
		hostName, port, err := normalizeSearchHost(host)
		if err != nil {
			return nil, err
		}
		q += ` AND host=?`
		args = append(args, hostName)
		if port != "" {
			// Recorded rows historically store URL.Hostname() (without the port),
			// so constrain the original URL authority as a compatibility fallback.
			// New and old captures therefore share the same search contract.
			authority := net.JoinHostPort(hostName, port)
			q += ` AND (url LIKE ? OR url LIKE ? OR url LIKE ?)`
			args = append(args,
				"%://"+authority+"/%",
				"%://"+authority+"?%",
				"%://"+authority,
			)
		}
	}
	if contains != "" {
		q += ` AND (url LIKE ? OR url_template LIKE ?)`
		args = append(args, "%"+contains+"%", "%"+contains+"%")
	}
	if b := strings.TrimSpace(bodyContains); b != "" {
		cond, arg, ok := t.ftsFilter(b)
		if !ok {
			if !t.fts {
				return nil, fmt.Errorf("the full-text index is not enabled on this instance; cannot search by body")
			}
			return nil, fmt.Errorf("body search keyword requires at least %d characters (currently %d)", minTrigram, utf8.RuneCountInString(b))
		}
		q += ` AND ` + cond
		args = append(args, arg)
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, page*limit)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// normalizeSearchHost accepts the forms agents commonly have at hand while
// keeping the stored host (URL.Hostname()) as the canonical host key. A port,
// when supplied, is applied to the URL authority so captures from different
// services on the same IP cannot be mixed.
func normalizeSearchHost(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("host is a required parameter")
	}
	if strings.Contains(raw, "://") {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Host == "" {
			return "", "", fmt.Errorf("cannot parse host: %q", raw)
		}
		host, port = u.Hostname(), u.Port()
	} else if h, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		host, port = h, p
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	} else {
		host = raw
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("cannot parse host: %q", raw)
	}
	if port != "" {
		p, parseErr := strconv.Atoi(port)
		if parseErr != nil || p < 1 || p > 65535 {
			return "", "", fmt.Errorf("invalid port: %q", port)
		}
		port = strconv.Itoa(p)
	}
	return strings.ToLower(host), port, nil
}

// Tools exposes traffic lookup to work agents so they query already-captured
// traffic instead of re-curling the same resource (token + dedup win).
func (t *Traffic) Tools() []actool.CoreTool {
	allow := func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}
	ro := func(json.RawMessage) bool { return true }

	search := actool.Build(actool.Spec{
		Name:        "traffic_search",
		Description: TrafficSearchDescription,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":          map[string]any{"type": "string", "description": "Host filter (required; e.g. '107.172.96.177', '107.172.96.177:8082', or 'http://107.172.96.177:8082/path')"},
				"contains":      map[string]any{"type": "string", "description": "URL substring filter (optional, e.g. 'api' / 'login')"},
				"body_contains": map[string]any{"type": "string", "description": "Body full-text search (optional, at least 3 characters); matches request/response headers and bodies, e.g. 'password' / 'root:x:0' / 'intranet test'"},
				"limit":         map[string]any{"type": "integer", "description": "Results per page; default 3, max 10"},
				"page":          map[string]any{"type": "integer", "description": "Page number, starting at 0; default 0 (paginated by ts descending)"},
			},
			"required": []any{"host"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Host, Contains string
				BodyContains   string `json:"body_contains"`
				Limit          int
				Page           int
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Host) == "" {
				return actool.Errorf("host is required: specify a bare host, host:port, or full URL to avoid scanning the entire database."), nil
			}
			rows, err := t.query(a.Host, a.Contains, a.BodyContains, a.Page, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(rows) == 0 {
				return actool.Text("No matching traffic."), nil
			}
			// Slimmed down to a minimal index: keep only the fields needed for locating, plus the response code/length, without any response content.
			type liteRow struct {
				ID      string `json:"id"`
				Method  string `json:"method"`
				URL     string `json:"url"`
				Status  int    `json:"status"`
				RespLen int    `json:"resp_len"`
			}
			lite := make([]liteRow, 0, len(rows))
			for _, r := range rows {
				lite = append(lite, liteRow{ID: r.ID, Method: r.Method, URL: r.URL, Status: r.Status, RespLen: r.RespLen})
			}
			b, _ := json.Marshal(lite)
			return actool.Text(string(b)), nil
		},
	})

	get := actool.Build(actool.Spec{
		Name:        "traffic_get",
		Description: "Fetch the raw request/response of one captured traffic entry by id (truncated if too large). Use with traffic_search to avoid repeated curl calls.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"id": map[string]any{"type": "string", "description": "id returned by traffic_search"}},
			"required":   []any{"id"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ ID string }
			_ = json.Unmarshal(in, &a)
			req, resp, err := t.Get(a.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("=== REQUEST ===\n" + clip(req, 2500) + "\n\n=== RESPONSE ===\n" + clip(resp, 4000)), nil
		},
	})

	blob := actool.Build(actool.Spec{
		Name:        "traffic_blob",
		Description: "Read the raw content of very large request/response bodies in segments. The part shown in traffic_get as '…[truncated] @blob sha256:<hash>' is stored here; pass that hash in to get the complete content. Returns at most 8KB per call; use offset to read further (the result reports the total length). Suited to browsing backup files, leaked source, large JSON exports, and other responses over the inline threshold.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hash":   map[string]any{"type": "string", "description": "the 64-character hex value after sha256: in traffic_get's @blob marker"},
				"offset": map[string]any{"type": "integer", "description": "starting byte offset, default 0"},
				"length": map[string]any{"type": "integer", "description": "bytes to read this time; default and max 8192"},
			},
			"required": []any{"hash"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Hash   string
				Offset int64
				Length int64
			}
			_ = json.Unmarshal(in, &a)
			if a.Length <= 0 || a.Length > maxBlobRead {
				a.Length = maxBlobRead
			}
			data, total, err := t.BlobRange(a.Hash, a.Offset, a.Length)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(data) == 0 {
				return actool.Text(fmt.Sprintf("offset %d exceeds the content length (total %d bytes).", a.Offset, total)), nil
			}
			head := fmt.Sprintf("[offset=%d this read=%d total=%d]\n", a.Offset, len(data), total)
			if isBinaryBody("", data) {
				return actool.Text(head + "binary content; first 512 bytes in hex:\n" + hex.EncodeToString(clipBytes(data, 512))), nil
			}
			return actool.Text(head + truncateUTF8(data, len(data))), nil
		},
	})

	return []actool.CoreTool{search, get, blob}
}

// SeedToolMetas returns the traffic tools built on a ZERO receiver, for seeding the
// tools catalog (metadata only — Name/Description/InputSchema). The handlers close
// over the nil receiver but are never invoked on this instance, so it is safe.
func SeedToolMetas() []actool.CoreTool { return (&Traffic{}).Tools() }

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... [truncated, %d bytes total; full content in the traffic file tree] ...", len(s))
}

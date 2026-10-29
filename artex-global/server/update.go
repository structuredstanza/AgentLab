package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

// HTTP surface for the page's one-click update. The actual download, verification, and binary-swap logic all lives in the selfupdate package,
// This layer only handles the authentication boundary, concurrency mutual exclusion, and progress broadcasting, and tells main when it's time to exit.
//
// The restart is not performed by this process: once the new version is staged, the process exits with selfupdate.ExitRestart,
// and the daemon script (start.sh / start.bat, or ENTRYPOINT under Docker) brings it back up.

// User-facing update messages (SSE progress messages, check reasons, and error responses).
// The frontend (update-card in system/settings) renders the progress.message, reason, and writeErr
// bodies verbatim, so these are kept in Korean. Logs and Chinese comments are at Z2 (lowest log level) and out of scope.
const (
	updateMsgPreparing          = "Preparing…"
	updateMsgFailed             = "Update failed"
	updateMsgStaged             = "The new version is ready. Restarting…"
	updateErrNotReleaseFmt      = "The current version %q is not an official release, so one-click update is unavailable"
	updateErrAlreadyLatestFmt   = "Already on the latest version (%s)"
	updateErrInProgress         = "An update is already in progress"
	updateErrRollbackInProgress = "Cannot roll back while an update is in progress"
)

// restartCh is closed once the upgrade is ready or the rollback completes, and main exits with ExitRestart upon receiving it.
var (
	restartOnce sync.Once
	restartCh   = make(chan struct{})
)

// RestartRequested returns a channel that is closed when the process is asked to exit so that the daemon supervisor restarts it.
func RestartRequested() <-chan struct{} { return restartCh }

func requestRestart() { restartOnce.Do(func() { close(restartCh) }) }

// bootState is the conclusion of selfupdate.Bootstrap at this startup (update succeeded / just rolled back /
// staged file was discarded), injected by main so that /api/update/check can tell the frontend faithfully how the previous update turned out.
var (
	bootStateMu sync.Mutex
	bootState   selfupdate.State
)

// SetBootUpdateState is called once by main at startup.
func SetBootUpdateState(st selfupdate.State) {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	bootState = st
}

func bootUpdateState() selfupdate.State {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	return bootState
}

// releaseCache caches the results of GitHub's latest-release queries.
//
// The "new version available" hint in the top bar queries once on every full page load, and the unauthenticated GitHub API allows
// only 60 requests per IP per hour. Without caching, opening several tabs or refreshing a few times would exhaust the quota,
// and the check would then fail exactly when an update is actually wanted. When the user explicitly clicks "Check for updates", force can be used to bypass the cache.
type releaseCache struct {
	mu  sync.Mutex
	rel *selfupdate.Release
	err error
	at  time.Time
	// fetch is the data-fetching function, an injection point kept only for tests; when it is nil, the real GitHub query is used.
	fetch func(context.Context, *http.Client) (*selfupdate.Release, error)
}

const (
	releaseTTL = 30 * time.Minute
	// Failed results are also cached for a short while; otherwise, when GitHub is unreachable, every page load would have to wait for a full timeout;
	// but the TTL must be short, so things recover on their own soon after the network comes back.
	releaseErrTTL = 2 * time.Minute
	// Timeout for the query. The 30-minute timeout in NewClient is meant for downloading the full package; checking the version must not wait that long.
	releaseTimeout = 20 * time.Second
)

var relCache = &releaseCache{}

// get returns the latest Release, and does not touch the network if the result is cached.
//
// The lock is held for the entire duration of the fetch: concurrent requests queue up and wait for the result of the same query, instead of each hitting GitHub on its own
// (when a page has just loaded and several tabs query at the same time is exactly when rate limiting is most likely to be triggered).
func (c *releaseCache) get(ctx context.Context, client *http.Client, force bool) (*selfupdate.Release, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force {
		ttl := releaseTTL
		if c.err != nil {
			ttl = releaseErrTTL
		}
		if !c.at.IsZero() && time.Since(c.at) < ttl {
			return c.rel, c.err
		}
	}

	fetch := c.fetch
	if fetch == nil {
		fetch = selfupdate.FetchLatest
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	rel, err := fetch(ctx, client)
	// A cancelled request (the user closed the tab) does not mean GitHub has a problem, so do not write it into the cache,
	// Otherwise the next visitor would get an inexplicable "cancelled" error.
	if err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return c.rel, err
	}
	c.rel, c.err, c.at = rel, err, time.Now()
	return rel, err
}

// updateProgress is a progress update pushed to the frontend.
type updateProgress struct {
	Phase   selfupdate.Phase `json:"phase"`
	Percent int              `json:"percent"` // Only meaningful during the download stage; otherwise -1
	Message string           `json:"message"`
	Version string           `json:"version,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// updateHub holds the progress of a single upgrade and broadcasts it to SSE subscribers.
//
// running doubles as a mutex: during an upgrade, another POST to /api/update/apply returns 409 immediately,
// Avoid two goroutines writing to the same artex.new at the same time.
type updateHub struct {
	mu      sync.Mutex
	running bool
	cur     updateProgress
	subs    map[chan updateProgress]struct{}
}

var updHub = &updateHub{
	cur:  updateProgress{Phase: selfupdate.PhaseIdle, Percent: -1},
	subs: map[chan updateProgress]struct{}{},
}

// begin acquires the upgrade permission and returns false if an upgrade is already in progress.
func (h *updateHub) begin(version string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return false
	}
	h.running = true
	h.cur = updateProgress{Phase: selfupdate.PhaseDownload, Percent: 0, Message: updateMsgPreparing, Version: version}
	h.fanout(h.cur)
	return true
}

// finish ends an upgrade. A nil err means the staging succeeded and the program is waiting to restart.
func (h *updateHub) finish(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	if err != nil {
		h.cur = updateProgress{Phase: selfupdate.PhaseFailed, Percent: -1, Message: updateMsgFailed, Error: err.Error(), Version: h.cur.Version}
	} else {
		h.cur = updateProgress{Phase: selfupdate.PhaseStaged, Percent: 100, Message: updateMsgStaged, Version: h.cur.Version}
	}
	h.fanout(h.cur)
}

func (h *updateHub) publish(ph selfupdate.Phase, pct int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = updateProgress{Phase: ph, Percent: pct, Message: msg, Version: h.cur.Version}
	h.fanout(h.cur)
}

// fanout must be called while holding h.mu. The subscriber channels are buffered; when one is full, the message is dropped——
// Progress is transient, disposable information, and must never let a stuck SSE connection block the upgrade itself.
func (h *updateHub) fanout(p updateProgress) {
	for ch := range h.subs {
		select {
		case ch <- p:
		default:
		}
	}
}

func (h *updateHub) snapshot() (updateProgress, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.running
}

func (h *updateHub) subscribe() (<-chan updateProgress, func()) {
	ch := make(chan updateProgress, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// updateCheck queries GitHub for the latest stable release and compares it with the current version.
//
// The frontend also connects to api.github.com directly (GitHub's CORS is *), but **this endpoint is authoritative**:
// The download is performed by the backend, and only the backend's ability to reach GitHub makes an update possible. The browser can connect while the server cannot
// for the browser to reach GitHub while the server cannot (the server is on an internal network, or the proxy is configured only in the browser). In that case, clicking update will inevitably fail,
// so it is better to report the error honestly at the check step.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion
	mode := "binary"
	if selfupdate.InDocker() {
		mode = "docker"
	}
	boot := bootUpdateState()
	out := map[string]any{
		"current":     current,
		"mode":        mode,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"has_backup":  selfupdate.HasBackup(),
		"repo":        selfupdate.Repo,
		"boot_notice": boot.Detail,
		"rolled_back": boot.RolledBack,
	}

	// The top-bar notice uses the cache (by default); when the user clicks "Check for updates", force=1 is passed to force a fresh fetch from upstream.
	force := r.URL.Query().Get("force") != ""
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, force)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}

	latest := rel.TagName
	out["latest"] = latest
	out["notes"] = rel.Body
	out["html_url"] = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		out["published_at"] = rel.PublishedAt.Format(time.RFC3339)
	}

	asset := selfupdate.AssetName(latest, runtime.GOOS, runtime.GOARCH)
	out["asset"] = asset
	if a, ok := rel.FindAsset(asset); ok {
		out["asset_available"] = true
		out["size"] = a.Size
	} else {
		out["asset_available"] = false
	}

	cmp, comparable := selfupdate.CompareVersions(current, latest)
	out["comparable"] = comparable
	out["has_update"] = comparable && cmp < 0
	if !comparable {
		// Development builds (dev / git describe with a suffix) have no comparable version number. Letting them through would only
		// overwrite the local binary being debugged with the official release, so updates are simply not offered.
		out["reason"] = fmt.Sprintf(updateErrNotReleaseFmt, current)
	}
	writeJSON(w, 200, out)
}

// updateApply downloads and stages the new version, then makes the process exit so the supervisor script can restart it.
//
// Returns 202 immediately and runs the actual work in a background goroutine: a full package download may take several minutes,
// Attaching this to the request will get it cut off by the reverse proxy timeout. Progress goes through /api/update/stream.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion

	// Uses the cache: ensures that the version installed is the one the user saw and confirmed in the UI.
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, false)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	cmp, comparable := selfupdate.CompareVersions(current, rel.TagName)
	if !comparable {
		writeErr(w, 400, fmt.Sprintf(updateErrNotReleaseFmt, current))
		return
	}
	if cmp >= 0 {
		writeErr(w, 400, fmt.Sprintf(updateErrAlreadyLatestFmt, current))
		return
	}
	if !updHub.begin(rel.TagName) {
		writeErr(w, 409, updateErrInProgress)
		return
	}

	go func() {
		// Deliberately uses s.ctx instead of the request's ctx: the request ends as soon as the HTTP response returns,
		// so downloading under it would be canceled immediately.
		err := selfupdate.Stage(s.ctx, client, rel, current, func(ph selfupdate.Phase, pct int, msg string) {
			updHub.publish(ph, pct, msg)
		})
		updHub.finish(err)
		if err != nil {
			log.Printf("[update] update failed: %v", err)
			return
		}
		log.Printf("[update] %s → %s staged; exiting to complete the swap", current, rel.TagName)
		// Leave a moment to push the last progress update to the frontend before triggering the exit.
		time.Sleep(1500 * time.Millisecond)
		requestRestart()
	}()

	writeJSON(w, 202, map[string]any{"ok": true, "target": rel.TagName})
}

// updateRollback actively rolls back to the previous version (the artex.old backup made before the swap).
func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	if _, running := updHub.snapshot(); running {
		writeErr(w, 409, updateErrRollbackInProgress)
		return
	}
	if err := selfupdate.Rollback(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[update] manually rolled back to the previous version; exiting to complete the switch")
	writeJSON(w, 202, map[string]any{"ok": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		requestRestart()
	}()
}

// updateStream pushes update progress via SSE.
func (s *Server) updateStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := updHub.subscribe()
	defer unsub()

	send := func(p updateProgress) {
		b, _ := json.Marshal(p)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	// First send a current-state message so that after a page refresh, the in-progress upgrade is visible immediately.
	cur, _ := updHub.snapshot()
	send(cur)

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			send(p)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

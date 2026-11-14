package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
)

// browserSession is one task's Chromium: the driver plus when it was last used.
type browserSession struct {
	drv      *browser.Driver
	lastUsed time.Time
}

// browserSessions keeps one driver per task. A task's browser is a real process
// with a profile on disk: creating one per tool call would lose cookies between
// steps, and never closing them would leak a Chromium per task.
type browserSessions struct {
	mu   sync.Mutex
	byID map[string]*browserSession
}

// browserIdleTimeout closes a browser no tool has touched for this long, unless
// its task still has work running. The idle reaper and the session cap are the
// only things that end a session, so a task that stops without saying so still
// releases its process.
const browserIdleTimeout = 10 * time.Minute

// browserMaxSessions bounds concurrent Chromium processes on the guest. A
// launch at the cap evicts the least-recently-used session with no running
// work; when every session is busy the launch is refused.
const browserMaxSessions = 4

func (s *Server) browserFor(ctx context.Context, taskID string) (*browser.Driver, error) {
	s.browsers.mu.Lock()
	defer s.browsers.mu.Unlock()
	if s.browsers.byID == nil {
		s.browsers.byID = map[string]*browserSession{}
	}
	if sess := s.browsers.byID[taskID]; sess != nil {
		sess.lastUsed = time.Now()
		return sess.drv, nil
	}
	drv, err := s.launchBrowser(ctx, taskID)
	if err != nil {
		return nil, err
	}
	s.browsers.byID[taskID] = &browserSession{drv: drv, lastUsed: time.Now()}
	return drv, nil
}

// launchBrowser starts the task's Chromium on a profile of its own, pointed at
// the recording proxy when capture is on, so every request the browser makes is
// evidence without extra work. The caller holds browsers.mu.
func (s *Server) launchBrowser(ctx context.Context, taskID string) (*browser.Driver, error) {
	if err := s.evictForCap(); err != nil {
		return nil, err
	}
	opts := browserLaunchOptions(s, taskID)
	if err := os.MkdirAll(opts.UserDataDir, 0o700); err != nil {
		return nil, fmt.Errorf("browser profile: %w", err)
	}
	if err := os.MkdirAll(opts.DownloadDir, 0o755); err != nil {
		return nil, fmt.Errorf("browser downloads: %w", err)
	}
	drv, err := browser.Launch(ctx, opts)
	if err != nil {
		return nil, err
	}
	log.Printf("[browser] launched for task %s", taskID)
	return drv, nil
}

// browserLaunchOptions is what one task's browser launches with: its own
// profile, the recording proxy, the per-request boundary and a downloads
// folder under the task directory.
func browserLaunchOptions(s *Server, taskID string) browser.Options {
	dir := filepath.Join(s.m.dir, "tasks", taskID)
	opts := browser.Options{
		Executable:   browserExecutable(s),
		UserDataDir:  filepath.Join(dir, "browser-profile"),
		DownloadDir:  filepath.Join(dir, "downloads"),
		AllowRequest: s.browserRequestScope(taskID),
	}
	if proxy := s.m.ProxyAddr(); proxy != "" {
		opts.ProxyServer = proxyURL(proxy)
	}
	return opts
}

// evictForCap frees one slot at the session cap by closing the least-recently
// used session whose task has no running work. Called with browsers.mu held,
// before a new launch; a session with running work is never evicted.
func (s *Server) evictForCap() error {
	if len(s.browsers.byID) < browserMaxSessions {
		return nil
	}
	var victimID string
	var victim *browserSession
	for id, sess := range s.browsers.byID {
		if s.engine.HasRunningWork(id) {
			continue
		}
		if victim == nil || sess.lastUsed.Before(victim.lastUsed) {
			victimID, victim = id, sess
		}
	}
	if victim == nil {
		return fmt.Errorf("all %d browser sessions are busy; close one or wait", browserMaxSessions)
	}
	delete(s.browsers.byID, victimID)
	log.Printf("[browser] evicting session for task %s: %d-session cap, idle %s", victimID, browserMaxSessions, time.Since(victim.lastUsed).Round(time.Second))
	_ = victim.drv.Close()
	return nil
}

// proxyURL normalizes a proxy address for Chromium's --proxy-server. The
// recorder already returns a full URL, and prefixing it again produced
// "http://http://127.0.0.1:8788", which Chromium rejects with
// ERR_NO_SUPPORTED_PROXIES.
func proxyURL(raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	return "http://" + raw
}

// browserExecutable resolves Chromium: M1NERVAC0NSOLE_CHROMIUM first (CI and
// the guest image set it), then the image's stable link, then the guest's own
// binary.
func browserExecutable(s *Server) string {
	if p := strings.TrimSpace(os.Getenv("M1NERVAC0NSOLE_CHROMIUM")); p != "" {
		return p
	}
	for _, p := range []string{"/opt/ms-playwright/current/chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// closeBrowser ends one task's session, if any.
func (s *Server) closeBrowser(taskID string) {
	s.browsers.mu.Lock()
	sess := s.browsers.byID[taskID]
	delete(s.browsers.byID, taskID)
	s.browsers.mu.Unlock()
	if sess != nil {
		_ = sess.drv.Close()
	}
}

// reapBrowsers closes sessions idle past browserIdleTimeout. A task with work
// still running keeps its browser: the page is the agent's tab, and closing it
// mid-intent would silently reset the next tool call. Called once a minute from
// the server's lifecycle goroutine.
func (s *Server) reapBrowsers() {
	cutoff := time.Now().Add(-browserIdleTimeout)
	var stale []string
	s.browsers.mu.Lock()
	for id, sess := range s.browsers.byID {
		if !sess.lastUsed.Before(cutoff) {
			continue
		}
		if s.engine.HasRunningWork(id) {
			log.Printf("[browser] keeping idle session for task %s: work is still running", id)
			continue
		}
		stale = append(stale, id)
	}
	s.browsers.mu.Unlock()
	for _, id := range stale {
		log.Printf("[browser] closing idle session for task %s", id)
		s.closeBrowser(id)
	}
}

// browserTaskID is the task a browser tool acts for. A chat session has none,
// and a browser without a task has no scope to enforce.
func browserTaskID(ctx context.Context) (string, error) {
	id := agent.RunInfoFrom(ctx).TaskID
	if id <= 0 {
		return "", fmt.Errorf("the browser tools only run inside a task; this session has no task to scope them to")
	}
	return strconv.FormatInt(id, 10), nil
}

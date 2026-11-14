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

// browserIdleTimeout closes a browser no tool has touched for this long. The
// idle reaper is the only thing that ends a session, so a task that stops
// without saying so still releases its process.
const browserIdleTimeout = 10 * time.Minute

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
// evidence without extra work.
func (s *Server) launchBrowser(ctx context.Context, taskID string) (*browser.Driver, error) {
	profile := filepath.Join(s.m.dir, "tasks", taskID, "browser-profile")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return nil, fmt.Errorf("browser profile: %w", err)
	}
	opts := browser.Options{
		Executable:  browserExecutable(s),
		UserDataDir: profile,
	}
	if proxy := s.m.ProxyAddr(); proxy != "" {
		opts.ProxyServer = proxyURL(proxy)
	}
	drv, err := browser.Launch(ctx, opts)
	if err != nil {
		return nil, err
	}
	log.Printf("[browser] launched for task %s", taskID)
	return drv, nil
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

// browserExecutable resolves Chromium: the image's stable link first, then the
// guest's own binary, then the PATH.
func browserExecutable(s *Server) string {
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

// reapBrowsers closes sessions idle past browserIdleTimeout. Called once a
// minute from the server's lifecycle goroutine.
func (s *Server) reapBrowsers() {
	cutoff := time.Now().Add(-browserIdleTimeout)
	var stale []string
	s.browsers.mu.Lock()
	for id, sess := range s.browsers.byID {
		if sess.lastUsed.Before(cutoff) {
			stale = append(stale, id)
		}
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

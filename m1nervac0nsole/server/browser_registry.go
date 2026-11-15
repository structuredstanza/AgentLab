package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// browserSession is one task's Chromium: the driver, the gateway credential its
// launch ran under, and when it was last used.
type browserSession struct {
	drv      *browser.Driver
	cred     string
	lastUsed time.Time
}

// browserSessions keeps one driver per task. A task's browser is a real process
// with a profile on disk: creating one per tool call would lose cookies between
// steps, and never closing them would leak a Chromium per task.
type browserSessions struct {
	mu   sync.Mutex
	byID map[string]*browserSession
	// launching counts launches in flight. The cap counts them so it holds
	// while a launch runs, without holding mu across the launch.
	launching int
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
	if s.browsers.byID == nil {
		s.browsers.byID = map[string]*browserSession{}
	}
	if sess := s.browsers.byID[taskID]; sess != nil {
		sess.lastUsed = time.Now()
		s.browsers.mu.Unlock()
		return sess.drv, nil
	}
	if err := s.evictForCap(); err != nil {
		s.browsers.mu.Unlock()
		return nil, err
	}
	s.browsers.launching++
	s.browsers.mu.Unlock()

	// The launch spawns a process and attaches to its page, so it runs without
	// the registry lock: one slow browser must not block every other task.
	drv, cred, err := s.launchBrowser(ctx, taskID)

	s.browsers.mu.Lock()
	s.browsers.launching--
	if err != nil {
		s.browsers.mu.Unlock()
		return nil, err
	}
	if sess := s.browsers.byID[taskID]; sess != nil {
		// A concurrent call registered this task's browser first; keep that one.
		sess.lastUsed = time.Now()
		s.browsers.mu.Unlock()
		s.closeSession(&browserSession{drv: drv, cred: cred})
		return sess.drv, nil
	}
	s.browsers.byID[taskID] = &browserSession{drv: drv, cred: cred, lastUsed: time.Now()}
	s.browsers.mu.Unlock()
	return drv, nil
}

// launchBrowser starts the task's Chromium on a profile of its own, pointed at
// the recording proxy when capture is on, so every request the browser makes is
// evidence without extra work. It returns the credential the launch ran under.
//
// The browser gets a session of its own: it outlives the run that started it, so
// it cannot borrow that run's credential, and the registry revokes this one when
// the browser closes.
func (s *Server) launchBrowser(ctx context.Context, taskID string) (*browser.Driver, string, error) {
	tid, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("browser: task %q: %w", taskID, err)
	}
	sess, err := s.session(ctx, netpolicy.CallerAgent, tid, 0, netpolicy.PurposeTesting)
	if err != nil {
		return nil, "", fmt.Errorf("browser: launch needs a session: %w", err)
	}
	// A launch that fails must not leave its credential behind: nothing else
	// holds it.
	launched := false
	defer func() {
		if !launched {
			s.m.RevokeSession(sess.Credential)
		}
	}()

	ctx = execbox.WithSession(ctx, sess)
	opts := browserLaunchOptions(s, ctx, taskID)
	if err := os.MkdirAll(opts.UserDataDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("browser profile: %w", err)
	}
	if err := os.MkdirAll(opts.DownloadDir, 0o755); err != nil {
		return nil, "", fmt.Errorf("browser downloads: %w", err)
	}
	drv, err := browser.Launch(ctx, opts)
	if err != nil {
		return nil, "", err
	}
	launched = true
	log.Printf("[browser] launched for task %s", taskID)
	return drv, sess.Credential, nil
}

// browserLaunchOptions is what one task's browser launches with: its own
// profile, the recording proxy, the per-request boundary and a downloads
// folder under the task directory.
//
// Chromium ignores credentials embedded in --proxy-server, so the address goes
// out bare and the launch session's credential is answered over CDP instead. A
// launch with no session gets no proxy rather than a bare address the gateway
// would refuse.
func browserLaunchOptions(s *Server, ctx context.Context, taskID string) browser.Options {
	dir := filepath.Join(s.m.dir, "tasks", taskID)
	opts := browser.Options{
		Executable:   browserExecutable(s),
		UserDataDir:  filepath.Join(dir, "browser-profile"),
		DownloadDir:  filepath.Join(dir, "downloads"),
		AllowRequest: s.browserRequestScope(taskID),
	}
	proxyURL := execbox.ProxyURL(ctx, s.m.ProxyAddr())
	if u, err := url.Parse(proxyURL); err == nil && u.User != nil {
		opts.ProxyUser = u.User.Username()
		opts.ProxyPass, _ = u.User.Password()
		u.User = nil
		proxyURL = u.String()
	}
	opts.ProxyServer = proxyURL
	return opts
}

// evictForCap frees one slot at the session cap by closing the least-recently
// used session whose task has no running work. Called with browsers.mu held,
// before a new launch; a session with running work is never evicted.
func (s *Server) evictForCap() error {
	if len(s.browsers.byID)+s.browsers.launching < browserMaxSessions {
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
	s.closeSession(victim)
	return nil
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
	s.closeSession(sess)
}

// closeSession ends one browser and revokes the credential its launch ran
// under: the browser is the only holder, so nothing else can use it once the
// process is gone. Called without browsers.mu held.
func (s *Server) closeSession(sess *browserSession) {
	if sess == nil {
		return
	}
	if sess.drv != nil {
		_ = sess.drv.Close()
	}
	if s.m != nil {
		s.m.RevokeSession(sess.cred)
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

// browserTaskID is the task a browser tool acts for. The task comes from the
// run's own context or from the conversation row the chat is bound to, never from
// a tool argument: a model cannot point the browser at another engagement.
//
// A chat with no task has no testing browser at all - there is nothing to scope
// it to - so the refusal names the research browser, which is the surface that
// chat does have.
func (s *Server) browserTaskID(ctx context.Context) (string, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID > 0 {
		return strconv.FormatInt(ri.TaskID, 10), nil
	}
	if id := conversationIDFromSession(ri.SessionID); id > 0 {
		c, err := s.m.PG().GetConversation(id)
		if err != nil {
			return "", fmt.Errorf("this chat's task binding could not be read (%v), so the browser cannot be scoped", err)
		}
		if c != nil && c.TaskID > 0 {
			return strconv.FormatInt(c.TaskID, 10), nil
		}
	}
	return "", fmt.Errorf("the browser tools test a target and need a task; this chat is not bound to one. For public documentation, repositories and advisories use the research browser (mcp__obscura__*), which needs no task")
}

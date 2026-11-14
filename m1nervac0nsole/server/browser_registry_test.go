package server

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
)

// testBrowserServer is a Server with only the fields the registry touches: no
// manager, no DB, and a zero-value driver whose Close is observable.
func testBrowserServer() *Server {
	return &Server{engine: NewEngine(nil), browsers: browserSessions{byID: map[string]*browserSession{}}}
}

func addBrowserSession(s *Server, taskID string, lastUsed time.Time) *browser.Driver {
	drv := &browser.Driver{}
	s.browsers.byID[taskID] = &browserSession{drv: drv, lastUsed: lastUsed}
	return drv
}

// A long scan between two browser steps must not lose the page: the reaper
// skips a session whose task still has work running.
func TestReapBrowsersKeepsSessionUnderRunningWork(t *testing.T) {
	s := testBrowserServer()
	drv := addBrowserSession(s, "7", time.Now().Add(-11*time.Minute))
	if !s.engine.beginTaskOperation("7") {
		t.Fatal("could not register a running operation")
	}
	defer s.engine.decInflight("7")

	s.reapBrowsers()

	if drv.Closed() {
		t.Fatal("the reaper closed a browser under running work")
	}
	if s.browsers.byID["7"] == nil {
		t.Fatal("the reaper dropped the session")
	}
}

// Without running work the same idle session is genuinely idle and is closed.
func TestReapBrowsersClosesIdleSession(t *testing.T) {
	s := testBrowserServer()
	drv := addBrowserSession(s, "7", time.Now().Add(-11*time.Minute))

	s.reapBrowsers()

	if !drv.Closed() {
		t.Fatal("an idle session with no running work must be closed")
	}
	if s.browsers.byID["7"] != nil {
		t.Fatal("the closed session is still registered")
	}
}

// Every tool call goes through browserFor, which is what keeps the session
// alive between steps.
func TestBrowserForBumpsLastUsed(t *testing.T) {
	s := testBrowserServer()
	drv := addBrowserSession(s, "7", time.Now().Add(-11*time.Minute))

	got, err := s.browserFor(context.Background(), "7")
	if err != nil || got != drv {
		t.Fatalf("browserFor = %v, %v; want the existing driver", got, err)
	}
	if age := time.Since(s.browsers.byID["7"].lastUsed); age > time.Minute {
		t.Fatalf("lastUsed was not bumped by the tool call (age %s)", age)
	}
}

// At the cap the oldest idle session makes room; an older busy session is kept.
func TestBrowserEvictForCapPicksOldestIdle(t *testing.T) {
	s := testBrowserServer()
	now := time.Now()
	busy := addBrowserSession(s, "1", now.Add(-3*time.Hour))
	oldestIdle := addBrowserSession(s, "2", now.Add(-2*time.Hour))
	addBrowserSession(s, "3", now.Add(-time.Hour))
	addBrowserSession(s, "4", now.Add(-time.Minute))
	if !s.engine.beginTaskOperation("1") {
		t.Fatal("could not register a running operation")
	}
	defer s.engine.decInflight("1")

	if err := s.evictForCap(); err != nil {
		t.Fatal(err)
	}

	if s.browsers.byID["2"] != nil || !oldestIdle.Closed() {
		t.Fatal("the oldest idle session was not evicted")
	}
	if busy.Closed() || s.browsers.byID["1"] == nil {
		t.Fatal("a session with running work was evicted")
	}
	if len(s.browsers.byID) != browserMaxSessions-1 {
		t.Fatalf("sessions after eviction = %d, want %d", len(s.browsers.byID), browserMaxSessions-1)
	}
}

// Below the cap nothing is evicted.
func TestBrowserEvictForCapLeavesRoomBelowCap(t *testing.T) {
	s := testBrowserServer()
	for i := 1; i < browserMaxSessions; i++ {
		addBrowserSession(s, strconv.Itoa(i), time.Now().Add(-time.Duration(i)*time.Hour))
	}
	if err := s.evictForCap(); err != nil {
		t.Fatal(err)
	}
	if len(s.browsers.byID) != browserMaxSessions-1 {
		t.Fatalf("sessions = %d, want %d", len(s.browsers.byID), browserMaxSessions-1)
	}
}

// When every session is busy the launch is refused rather than killing work.
func TestLaunchBrowserRefusesWhenAllBusy(t *testing.T) {
	s := testBrowserServer()
	for i := 1; i <= browserMaxSessions; i++ {
		id := strconv.Itoa(i)
		addBrowserSession(s, id, time.Now().Add(-time.Duration(i)*time.Minute))
		if !s.engine.beginTaskOperation(id) {
			t.Fatal("could not register a running operation")
		}
		defer s.engine.decInflight(id)
	}

	_, err := s.launchBrowser(context.Background(), "5")
	if err == nil || !strings.Contains(err.Error(), "all 4 browser sessions are busy; close one or wait") {
		t.Fatalf("launchBrowser error = %v", err)
	}
	if len(s.browsers.byID) != browserMaxSessions {
		t.Fatalf("a refusal evicted a session: %d left", len(s.browsers.byID))
	}
}

// CI and the guest image point the driver at their own Chromium.
func TestBrowserExecutableEnvOverride(t *testing.T) {
	t.Setenv("M1NERVAC0NSOLE_CHROMIUM", "/opt/ci/chrome")
	if got := browserExecutable(&Server{}); got != "/opt/ci/chrome" {
		t.Fatalf("browserExecutable = %q, want the env override", got)
	}
}

// A launch carries the per-request boundary and a downloads folder under the
// task directory.
func TestBrowserLaunchOptions(t *testing.T) {
	s := testBrowserServer()
	s.m = &Manager{dir: t.TempDir()}
	opts := browserLaunchOptions(s, "7")
	if opts.AllowRequest == nil {
		t.Fatal("a launch with a task id must carry the request boundary")
	}
	if want := filepath.Join(s.m.dir, "tasks", "7", "downloads"); opts.DownloadDir != want {
		t.Fatalf("DownloadDir = %q, want %q", opts.DownloadDir, want)
	}
	if want := filepath.Join(s.m.dir, "tasks", "7", "browser-profile"); opts.UserDataDir != want {
		t.Fatalf("UserDataDir = %q, want %q", opts.UserDataDir, want)
	}
}

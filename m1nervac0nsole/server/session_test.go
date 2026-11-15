package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/browser"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

// execboxRefusal is the message every spawn site produces when the run carries no
// session: the supervisor refuses instead of starting an unisolated process.
const execboxRefusal = "execbox: isolated execution unavailable: execbox: no netpolicy session in context"

// fakeExecClient stands in for the supervisor's socket client, so a test can tell
// "refused before the boundary" from "reached the boundary". It records what it
// was asked to start and answers with a process that runs a canned script.
type fakeExecClient struct {
	mu       sync.Mutex
	runOnce  int
	run      int
	runFiles int
	specs    []execbox.Spec
	sessions []netpolicy.Session
	stdout   string
	stderr   string
	exit     int
	// artifact is the capture identity the last spawn carried, and artifactRef
	// what a one-shot run returns as its pointer. They let a test prove the
	// spawn site attached an identity without a real supervisor.
	artifact    execbox.ArtifactCall
	hasArtifact bool
	artifactRef string
}

func (f *fakeExecClient) record(ctx context.Context, s netpolicy.Session, spec execbox.Spec) (string, string, int) {
	f.specs = append(f.specs, spec)
	f.sessions = append(f.sessions, s)
	if call, ok := execbox.ArtifactsFrom(ctx); ok {
		f.artifact, f.hasArtifact = call, true
	}
	return f.stdout, f.stderr, f.exit
}

func (f *fakeExecClient) RunOnce(ctx context.Context, s netpolicy.Session, spec execbox.Spec) (execbox.Result, error) {
	f.mu.Lock()
	f.runOnce++
	f.record(ctx, s, spec)
	ref := f.artifactRef
	f.mu.Unlock()
	return execbox.Result{ExitCode: 0, Output: []byte("ok"), Artifact: ref}, nil
}

func (f *fakeExecClient) Run(ctx context.Context, s netpolicy.Session, spec execbox.Spec) (io.ReadWriteCloser, error) {
	f.mu.Lock()
	f.run++
	out, errOut, code := f.record(ctx, s, spec)
	ref := f.artifactRef
	f.mu.Unlock()
	return newFakeProcess(out, errOut, code, ref), nil
}

func (f *fakeExecClient) RunWithFiles(ctx context.Context, s netpolicy.Session, spec execbox.Spec, _ []*os.File) (io.ReadWriteCloser, error) {
	f.mu.Lock()
	f.runFiles++
	out, errOut, code := f.record(ctx, s, spec)
	ref := f.artifactRef
	f.mu.Unlock()
	return newFakeProcess(out, errOut, code, ref), nil
}

func (f *fakeExecClient) Capabilities(context.Context) (execbox.Report, error) {
	return execbox.Report{Isolation: true}, nil
}

func (f *fakeExecClient) counts() (runOnce, run, runFiles int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runOnce, f.run, f.runFiles
}

// last returns the spec and session of the most recent Run/RunWithFiles/RunOnce
// call.
func (f *fakeExecClient) last() (execbox.Spec, netpolicy.Session, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return execbox.Spec{}, netpolicy.Session{}, false
	}
	return f.specs[len(f.specs)-1], f.sessions[len(f.sessions)-1], true
}

// fakeProcess is a session whose program wrote the canned stdout and stderr and
// exited with the canned code.
type fakeProcess struct {
	out  *io.PipeReader
	in   *io.PipeWriter
	errR *io.PipeReader
	code int
	// ref is the capture pointer the fake reports, so a caller's pointer plumbing
	// is exercised without a real supervisor.
	ref string
}

func newFakeProcess(stdout, stderr string, code int, ref string) *fakeProcess {
	out, outW := io.Pipe()
	go func() {
		_, _ = io.WriteString(outW, stdout)
		_ = outW.Close()
	}()
	inR, in := io.Pipe()
	_ = inR.Close()
	errR, errW := io.Pipe()
	go func() {
		_, _ = io.WriteString(errW, stderr)
		_ = errW.Close()
	}()
	return &fakeProcess{out: out, in: in, errR: errR, code: code, ref: ref}
}

func (p *fakeProcess) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *fakeProcess) Write(b []byte) (int, error) { return len(b), nil }
func (p *fakeProcess) Close() error                { return nil }
func (p *fakeProcess) CloseStdin() error           { return nil }
func (p *fakeProcess) Stderr() io.Reader           { return p.errR }
func (p *fakeProcess) Resize(int, int) error       { return nil }
func (p *fakeProcess) Wait() (int, error)          { return p.code, nil }
func (p *fakeProcess) Kill() error                 { return nil }

// ArtifactPointer reports the canned capture pointer.
func (p *fakeProcess) ArtifactPointer() string { return p.ref }

// installFakeClient installs the fake for one test and restores the standalone
// SDK behaviour afterwards, so no other test inherits an executor.
func installFakeClient(t *testing.T) *fakeExecClient {
	t.Helper()
	f := &fakeExecClient{}
	execbox.Install(f)
	t.Cleanup(func() { execbox.Install(nil) })
	return f
}

func testSession() netpolicy.Session {
	return netpolicy.Session{ID: "session-test", TaskID: 7, ConversationID: 3, Purpose: netpolicy.PurposeTesting, Revision: 1}
}

// TestSpawnPathsRefuseWithoutASession is the startup assertion: with the client
// installed, a context that carries no session makes every path that can start a
// process refuse with the documented capability error, instead of spawning an
// unisolated child.
func TestSpawnPathsRefuseWithoutASession(t *testing.T) {
	f := installFakeClient(t)
	ctx := context.Background()
	// Background tasks and PTY shells spawn from the session's root context, which
	// the agent package sets to the run context; here that is a context with no
	// session, exactly like a run whose session could not be issued.
	mgr, err := actool.NewManagerWithContext(ctx, "execbox-gate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Cleanup)

	t.Run("bash", func(t *testing.T) {
		res, err := actool.NewBash().Call(ctx, json.RawMessage(`{"command":"echo hi"}`), &actool.ToolContext{WorkingDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(res.Flatten(), execboxRefusal) {
			t.Fatalf("Bash without a session = %q (isError=%v), want the capability error", res.Flatten(), res.IsError)
		}
	})

	t.Run("background task", func(t *testing.T) {
		_, err := mgr.Spawn(actool.SpawnSpec{Command: "echo hi"})
		if err == nil || !strings.Contains(err.Error(), execboxRefusal) {
			t.Fatalf("background Spawn without a session = %v, want the capability error", err)
		}
	})

	t.Run("pty", func(t *testing.T) {
		res, err := actool.NewShellOpen().Call(ctx, json.RawMessage(`{"command":"bash"}`), &actool.ToolContext{Tasks: mgr})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(res.Flatten(), execboxRefusal) {
			t.Fatalf("shell_open without a session = %q (isError=%v), want the capability error", res.Flatten(), res.IsError)
		}
	})

	t.Run("mcp stdio", func(t *testing.T) {
		_, err := connectMCP(ctx, &db.MCPServer{Name: "fixture", Transport: "stdio", Command: "true"})
		if !errors.Is(err, execbox.ErrUnavailable) || !strings.Contains(err.Error(), execboxRefusal) {
			t.Fatalf("connectMCP without a session = %v, want the capability error", err)
		}
	})

	t.Run("chromium", func(t *testing.T) {
		_, err := browser.Launch(ctx, browser.Options{UserDataDir: t.TempDir()})
		if !errors.Is(err, execbox.ErrUnavailable) || !strings.Contains(err.Error(), execboxRefusal) {
			t.Fatalf("browser.Launch without a session = %v, want the capability error", err)
		}
	})

	if runOnce, run, runFiles := f.counts(); runOnce+run+runFiles != 0 {
		t.Fatalf("a refused path still reached the supervisor: runOnce=%d run=%d runFiles=%d", runOnce, run, runFiles)
	}
}

// TestSpawnPathsProceedWithASession is the other half of the assertion: the same
// calls with a session reach the boundary, so the refusal above is the session
// gate and not a broken tool.
func TestSpawnPathsProceedWithASession(t *testing.T) {
	f := installFakeClient(t)
	ctx := execbox.WithSession(context.Background(), testSession())
	mgr, err := actool.NewManagerWithContext(ctx, "execbox-gate-open")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Cleanup)

	t.Run("bash", func(t *testing.T) {
		res, err := actool.NewBash().Call(ctx, json.RawMessage(`{"command":"echo hi"}`), &actool.ToolContext{WorkingDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError || !strings.Contains(res.Flatten(), "ok") {
			t.Fatalf("Bash with a session = %q (isError=%v), want the supervisor's output", res.Flatten(), res.IsError)
		}
	})

	t.Run("background task", func(t *testing.T) {
		task, err := mgr.Spawn(actool.SpawnSpec{Command: "echo hi"})
		if err != nil {
			t.Fatalf("background Spawn with a session: %v", err)
		}
		if task == nil || task.ID == "" {
			t.Fatal("background Spawn returned no task")
		}
	})

	t.Run("pty", func(t *testing.T) {
		res, err := actool.NewShellOpen().Call(ctx, json.RawMessage(`{"command":"bash"}`), &actool.ToolContext{Tasks: mgr})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError || !strings.Contains(res.Flatten(), "session_id") {
			t.Fatalf("shell_open with a session = %q (isError=%v), want a session id", res.Flatten(), res.IsError)
		}
	})

	t.Run("mcp stdio", func(t *testing.T) {
		// The bridge is our own binary, which in a test is the test binary and not
		// an MCP server, so the handshake fails. What matters is that the session
		// gate is passed: the failure is no longer the capability error.
		mcpCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		_, err := connectMCP(mcpCtx, &db.MCPServer{Name: "fixture", Transport: "stdio", Command: "true"})
		if err == nil {
			t.Fatal("a test binary answered the MCP handshake")
		}
		if errors.Is(err, execbox.ErrUnavailable) {
			t.Fatalf("connectMCP with a session still refused: %v", err)
		}
	})

	t.Run("chromium", func(t *testing.T) {
		// The fake process never speaks CDP, so the attach fails; the launch itself
		// got past the session gate and asked the boundary for a process.
		_, err := browser.Launch(ctx, browser.Options{UserDataDir: t.TempDir()})
		if err == nil {
			t.Fatal("a fake process answered CDP")
		}
		if errors.Is(err, execbox.ErrUnavailable) {
			t.Fatalf("browser.Launch with a session still refused: %v", err)
		}
	})

	runOnce, run, runFiles := f.counts()
	if runOnce != 1 || run < 2 || runFiles != 1 {
		t.Fatalf("supervisor calls: runOnce=%d run=%d runFiles=%d, want 1, >=2, 1", runOnce, run, runFiles)
	}
}

// TestInstallIsAtomicWithSpawnWiring proves the entry point's install cannot
// succeed while one registered spawn path has no session: a single unwired path
// would turn every spawn on it into a refusal.
func TestInstallIsAtomicWithSpawnWiring(t *testing.T) {
	execbox.Install(nil)
	t.Cleanup(func() { execbox.Install(nil) })
	client := &fakeExecClient{}

	// A path whose caller may not request its purpose: the curator cannot run as
	// testing, so this path could never be given a session.
	broken := []spawnPath{
		{"task engine", netpolicy.CallerAgent, netpolicy.PurposeTesting, true},
		{"tool curator", netpolicy.CallerCurator, netpolicy.PurposeTesting, true},
	}
	if err := installBoundary(broken, probeSource{}, client); err == nil {
		t.Fatal("install succeeded with a spawn path that has no session")
	}
	if _, ok := execbox.Installed(); ok {
		t.Fatal("the client was installed despite a spawn path without a session")
	}

	// A path that needs a task but is registered as unbound: testing without a
	// task is refused by the issuer.
	unbound := []spawnPath{{"task engine", netpolicy.CallerAgent, netpolicy.PurposeTesting, false}}
	if err := installBoundary(unbound, probeSource{}, client); err == nil {
		t.Fatal("install succeeded with a task-bound purpose registered as unbound")
	}
	if _, ok := execbox.Installed(); ok {
		t.Fatal("the client was installed despite a spawn path without a session")
	}

	// No policy source at all: no session could ever be issued.
	if err := installBoundary(spawnPaths, nil, client); err == nil {
		t.Fatal("install succeeded without a policy source")
	}
	if _, ok := execbox.Installed(); ok {
		t.Fatal("the client was installed without a policy source")
	}

	// The real registry, with a source: every path is wired, so the install runs.
	if err := installBoundary(spawnPaths, probeSource{}, client); err != nil {
		t.Fatalf("install with the full spawn registry: %v", err)
	}
	installed, ok := execbox.Installed()
	if !ok || installed != client {
		t.Fatal("the client was not installed with a complete spawn registry")
	}
}

// TestTaskSessionContextUsesTheTaskRow proves the engine's session comes from the
// task row and the fixed testing purpose, and that a task the store cannot answer
// for leaves the run without one instead of guessing.
func TestTaskSessionContextUsesTheTaskRow(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("session wiring", "prove the task session", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(mustTaskID(t, task.ID)) })

	ctx := taskSessionContext(context.Background(), m, task.ID)
	sess, ok := execbox.SessionFrom(ctx)
	if !ok {
		t.Fatal("a live task run has no session")
	}
	if sess.TaskID != mustTaskID(t, task.ID) || sess.Purpose != netpolicy.PurposeTesting || sess.ID == "" {
		t.Fatalf("task session = %+v, want this task with the testing purpose", sess)
	}
	// The session is registered with the gateway, so its credential resolves.
	if sess.Credential == "" {
		t.Fatal("the task session carries no credential, so the gateway would refuse every request")
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+sess.Credential)
	if got, ok := m.gatewaySession(req); !ok || got.ID != sess.ID {
		t.Fatalf("the task session credential resolved %+v (ok=%v), want the issued session", got, ok)
	}

	// A task id the store has no live row for: no session, and no invented one.
	missing := taskSessionContext(context.Background(), m, "999999999")
	if _, ok := execbox.SessionFrom(missing); ok {
		t.Fatal("a run for a task the store cannot answer for got a session")
	}
}

// TestConversationSessionPurposes proves the purpose comes from the conversation
// row: a task-bound thread tests under that task, an unbound thread is research,
// and the tool curator installs - with or without a task, because an install is
// operator/curator-initiated rather than task-scoped.
func TestConversationSessionPurposes(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m}
	task, err := m.CreateTask("conversation session", "prove the purpose matrix", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	bound := &db.Conversation{ID: 11, AgentKey: "worker", TaskID: taskID}
	sess, ok := execbox.SessionFrom(s.conversationSessionContext(context.Background(), bound))
	if !ok || sess.Purpose != netpolicy.PurposeTesting || sess.TaskID != taskID || sess.ConversationID != 11 {
		t.Fatalf("task-bound conversation session = %+v (ok=%v), want testing under task %d", sess, ok, taskID)
	}

	unbound := &db.Conversation{ID: 12, AgentKey: "auto"}
	sess, ok = execbox.SessionFrom(s.conversationSessionContext(context.Background(), unbound))
	if !ok || sess.Purpose != netpolicy.PurposeResearch || sess.TaskID != 0 || sess.ConversationID != 12 {
		t.Fatalf("unbound conversation session = %+v (ok=%v), want unbound research", sess, ok)
	}

	curator := &db.Conversation{ID: 13, AgentKey: toolCuratorAgent, TaskID: taskID}
	sess, ok = execbox.SessionFrom(s.conversationSessionContext(context.Background(), curator))
	if !ok || sess.Purpose != netpolicy.PurposeInstall || sess.TaskID != taskID {
		t.Fatalf("tool curator session = %+v (ok=%v), want install under task %d", sess, ok, taskID)
	}

	// An install is operator/curator-initiated, so an unbound curator thread is
	// issued one: it carries no task and is judged by the public-destination
	// rule, so no engagement grant is inherited.
	unboundCurator := &db.Conversation{ID: 14, AgentKey: toolCuratorAgent}
	sess, ok = execbox.SessionFrom(s.conversationSessionContext(context.Background(), unboundCurator))
	if !ok || sess.Purpose != netpolicy.PurposeInstall || sess.TaskID != 0 || sess.ConversationID != 14 {
		t.Fatalf("unbound tool curator session = %+v (ok=%v), want unbound install", sess, ok)
	}

	// Discovery is a backend lookup with no task: unbound research.
	sess, ok = execbox.SessionFrom(s.discoverySessionContext(context.Background()))
	if !ok || sess.Purpose != netpolicy.PurposeResearch || sess.TaskID != 0 {
		t.Fatalf("discovery session = %+v (ok=%v), want unbound research", sess, ok)
	}
}

// TestEngineExecContextCarriesTheTaskSession proves the wiring, not just the
// helper: the context every planner round and worker execution derives from
// carries the task's session, so a Bash call inside a task runs in its boundary.
func TestEngineExecContextCarriesTheTaskSession(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("engine session", "prove the engine attaches the task session", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	ctx := NewEngine(m).execContextFor(context.Background(), task.ID)
	sess, ok := execbox.SessionFrom(ctx)
	if !ok {
		t.Fatal("the engine handed out an execution context with no session: every tool process in the task would refuse")
	}
	if sess.TaskID != taskID || sess.Purpose != netpolicy.PurposeTesting {
		t.Fatalf("engine session = %+v, want testing under task %d", sess, taskID)
	}
}

// TestConversationRunContextCarriesTheSession proves a chat turn's context carries
// the session its tool processes run under, and that the turn is cancellable.
func TestConversationRunContextCarriesTheSession(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{ctx: context.Background(), m: m, chatCancel: map[string]context.CancelCauseFunc{}}

	conv := &db.Conversation{ID: 21, AgentKey: "auto"}
	ctx, cancel := s.conversationRunContext(conv, "conv-21")
	sess, ok := execbox.SessionFrom(ctx)
	if !ok {
		t.Fatal("a chat turn's context has no session: every tool process in the turn would refuse")
	}
	if sess.ConversationID != 21 || sess.Purpose != netpolicy.PurposeResearch {
		t.Fatalf("chat session = %+v, want unbound research for conversation 21", sess)
	}
	if _, registered := s.chatCancel["conv-21"]; !registered {
		t.Fatal("the turn was not registered for cancellation")
	}
	cancel(agent.AbortChatTurnFinished)
	if ctx.Err() == nil {
		t.Fatal("stopping the turn did not cancel its context")
	}
}

// drained reports whether every gateway credential has been released, waiting up
// to wait for the revoke goroutines the session helpers start.
func drained(m *Manager, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		m.sessMu.RLock()
		live := len(m.sessions)
		m.sessMu.RUnlock()
		if live == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSessionCredentialsDieWithTheirContext proves each session helper releases
// its gateway credential when the run's context ends: the credential stops
// resolving, so a finished run leaves nothing behind for the gateway's cap to
// count.
func TestSessionCredentialsDieWithTheirContext(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m}
	task, err := m.CreateTask("session revoke", "prove the credential dies with its context", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	cases := []struct {
		name  string
		issue func(context.Context) context.Context
	}{
		{"task run", func(ctx context.Context) context.Context { return taskSessionContext(ctx, m, task.ID) }},
		{"chat turn", func(ctx context.Context) context.Context {
			return s.conversationSessionContext(ctx, &db.Conversation{ID: 31, AgentKey: "auto"})
		}},
		{"mcp discovery", s.discoverySessionContext},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			sess, ok := execbox.SessionFrom(c.issue(ctx))
			if !ok {
				t.Fatal("the run got no session")
			}
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
			req.Header.Set("Proxy-Authorization", "Bearer "+sess.Credential)
			if _, ok := m.gatewaySession(req); !ok {
				t.Fatal("the issued credential does not resolve")
			}
			cancel()
			if !drained(m, 5*time.Second) {
				t.Fatal("the credential outlived its context: the gateway still holds it")
			}
			if _, ok := m.gatewaySession(req); ok {
				t.Fatal("the revoked credential still resolves")
			}
		})
	}
}

// TestSessionsNeverExhaustTheGatewayCap is the regression for the leak: the
// gateway refuses to issue past maxGatewaySessions, so a credential that is
// never released eventually makes every tool spawn fail. Every helper's
// credential is released when its context ends, so more issue/cancel cycles than
// the cap never refuse.
func TestSessionsNeverExhaustTheGatewayCap(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m}
	task, err := m.CreateTask("session cap", "prove the gateway cap is never reached", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	for i := 0; i <= maxGatewaySessions; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		var got context.Context
		switch i % 3 {
		case 0:
			got = taskSessionContext(ctx, m, task.ID)
		case 1:
			got = s.conversationSessionContext(ctx, &db.Conversation{ID: 41, AgentKey: "auto"})
		default:
			got = s.discoverySessionContext(ctx)
		}
		_, ok := execbox.SessionFrom(got)
		cancel()
		if !ok {
			t.Fatalf("cycle %d: the run got no session, so every tool spawn in it would refuse", i)
		}
		// Let the revokes catch up, so the map cannot approach the cap on a
		// loaded machine. A miss here is not the assertion; the final drain is.
		if i%256 == 0 {
			drained(m, 100*time.Millisecond)
		}
	}
	if !drained(m, 10*time.Second) {
		m.sessMu.RLock()
		live := len(m.sessions)
		m.sessMu.RUnlock()
		t.Fatalf("%d credentials are still live after every run ended", live)
	}
}

package execbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	sdktool "github.com/structuredstanza/norma/tool"
)

// fakeSupervisor answers the supervisor protocol on a real Unix socket, so the
// client's framing, its refusal paths and the SDK adapter are exercised without
// any kernel capability.
type fakeSupervisor struct {
	path    string
	ln      *net.UnixListener
	report  Report
	start   *frame
	publish *frame
	frames  []frame
	// onStdinEOF is what the fake answers after the client signals stdin EOF:
	// the frames a real session's program produces on its way out.
	onStdinEOF []frame
	// hold, when set, keeps the connection open after the configured frames
	// instead of answering, so a test can cancel or time out a live session.
	hold      chan struct{}
	gotFDs    chan int
	gotReqs   chan request
	gotFrames chan frame
}

func newFakeSupervisor(t *testing.T, rep Report) *fakeSupervisor {
	t.Helper()
	dir, err := os.MkdirTemp("", "execbox-fake")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "supervisor.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSupervisor{
		path: path, ln: ln, report: rep,
		gotFDs:    make(chan int, 4),
		gotReqs:   make(chan request, 4),
		gotFrames: make(chan frame, 16),
	}
	t.Cleanup(func() {
		ln.Close()
		os.RemoveAll(dir)
	})
	go f.serve()
	return f
}

func (f *fakeSupervisor) serve() {
	for {
		conn, err := f.ln.AcceptUnix()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSupervisor) handle(conn *net.UnixConn) {
	defer conn.Close()
	w := newWireConn(conn)
	var req request
	fds, err := w.readFirst(&req)
	if err != nil {
		return
	}
	defer closeFDs(fds)
	select {
	case f.gotFDs <- len(fds):
	default:
	}
	select {
	case f.gotReqs <- req:
	default:
	}
	switch req.Op {
	case opCapabilities:
		rep := f.report
		_ = w.write(frame{Type: frameReport, Report: &rep})
	case opPublish:
		if f.publish != nil {
			_ = w.write(*f.publish)
			return
		}
		_ = w.write(frame{Type: frameError, Message: "no publish configured"})
	case opStart:
		if f.start != nil {
			_ = w.write(*f.start)
			return
		}
		_ = w.write(frame{Type: frameReady, Handle: "fake"})
		for _, fr := range f.frames {
			if err := w.write(fr); err != nil {
				return
			}
		}
		if f.hold != nil {
			<-f.hold
			return
		}
		for {
			var fr frame
			if err := w.read(&fr); err != nil {
				return
			}
			select {
			case f.gotFrames <- fr:
			default:
			}
			switch fr.Type {
			case frameStdinEOF:
				// A real supervisor closes the program's stdin and the program
				// then exits on its own; the fake replays that exit.
				for _, out := range f.onStdinEOF {
					if err := w.write(out); err != nil {
						return
					}
				}
				return
			case frameClose:
				return
			}
		}
	}
}

func testSession() netpolicy.Session {
	return netpolicy.Session{ID: "sess-1", TaskID: 7, ConversationID: 3, Purpose: netpolicy.PurposeTesting, Revision: 2}
}

func TestRunOnceCollectsOutputAndExitCode(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{
		{Type: frameStdout, Data: []byte("hello ")},
		{Type: frameStderr, Data: []byte("world")},
		{Type: frameExit, Code: 4},
	}
	client := NewClient(f.path)
	res, err := client.RunOnce(context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.ExitCode != 4 {
		t.Errorf("exit code = %d, want 4", res.ExitCode)
	}
	if got := string(res.Output); got != "hello world" {
		t.Errorf("output = %q, want %q", got, "hello world")
	}
	req := <-f.gotReqs
	if req.Session == nil || req.Session.ID != "sess-1" || req.Session.Purpose != string(netpolicy.PurposeTesting) {
		t.Errorf("session on the wire = %+v", req.Session)
	}
}

func TestRunOnceCapabilityRefusal(t *testing.T) {
	f := newFakeSupervisor(t, Report{})
	f.start = &frame{Type: frameError, Message: "execbox: isolated execution unavailable: missing netns", Missing: []string{"netns"}, Detail: "ip netns add: operation not permitted"}
	client := NewClient(f.path)
	_, err := client.RunOnce(context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error %v does not match ErrUnavailable", err)
	}
	var capErr *CapabilityError
	if !errors.As(err, &capErr) {
		t.Fatalf("error %v is not a *CapabilityError", err)
	}
	if len(capErr.Missing) != 1 || capErr.Missing[0] != "netns" {
		t.Errorf("missing = %v, want [netns]", capErr.Missing)
	}
}

func TestRunStreamsStderrAndExitCode(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{
		{Type: frameStdout, Data: []byte("out")},
		{Type: frameStderr, Data: []byte("err")},
		{Type: frameExit, Code: 3},
	}
	client := NewClient(f.path)
	rwc, err := client.Run(context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, ok := ProcessOf(rwc)
	if !ok {
		t.Fatal("Run did not return a Process")
	}
	defer proc.Close()

	// Both streams must be consumed concurrently: the client's pump writes each
	// frame to its stream, so a consumer that ignores one would stall the other.
	errCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(proc.Stderr())
		errCh <- b
	}()
	out, err := io.ReadAll(proc)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if string(out) != "out" {
		t.Errorf("stdout = %q, want %q", out, "out")
	}
	errOut := <-errCh
	if string(errOut) != "err" {
		t.Errorf("stderr = %q, want %q", errOut, "err")
	}
	code, err := proc.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
}

func TestCapabilitiesReport(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true, Checked: []string{"netns", "veth"}})
	rep, err := NewClient(f.path).Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if !rep.OK() {
		t.Errorf("report not OK: %s", rep.String())
	}
	if len(rep.Checked) != 2 {
		t.Errorf("checked = %v", rep.Checked)
	}
}

func TestDialFailureIsCapabilityError(t *testing.T) {
	_, err := NewClient(filepath.Join(t.TempDir(), "absent.sock")).RunOnce(
		context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error %v does not match ErrUnavailable", err)
	}
}

func TestRunWithFilesSendsDescriptors(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameExit, Code: 0}}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	client := NewClient(f.path)
	rwc, err := RunFiles(client, context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp", ExtraFiles: 1}, []*os.File{r})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	defer rwc.Close()
	if n := <-f.gotFDs; n != 1 {
		t.Errorf("received %d descriptors, want 1", n)
	}
}

func TestRunWithFilesCountMismatch(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	_, err := RunFiles(NewClient(f.path), context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp", ExtraFiles: 2}, nil)
	if err == nil {
		t.Fatal("expected an error for a descriptor count mismatch")
	}
}

// --- SDK adapter refusal paths ---

func TestToolExecutorRefusesWithoutSession(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	ex := &toolExecutor{c: NewClient(f.path)}
	_, err := ex.RunOnce(context.Background(), sdktool.SpawnSpec{Command: "true"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error %v does not match ErrUnavailable", err)
	}
	if !errors.Is(err, ErrNoSession) {
		t.Errorf("error %v does not name the missing session", err)
	}
	select {
	case req := <-f.gotReqs:
		t.Fatalf("a request reached the supervisor: %+v", req)
	default:
	}
}

func TestToolExecutorRefusesIncompleteSession(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	ex := &toolExecutor{c: NewClient(f.path)}
	ctx := WithSession(context.Background(), netpolicy.Session{ID: "", Purpose: netpolicy.PurposeTesting})
	_, err := ex.RunOnce(ctx, sdktool.SpawnSpec{Command: "true"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error %v does not match ErrUnavailable", err)
	}
}

func TestToolExecutorBuildsSpec(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameStdout, Data: []byte("ok")}, {Type: frameExit, Code: 0}}
	ex := &toolExecutor{c: NewClient(f.path)}
	ctx := WithSession(context.Background(), testSession())
	res, err := ex.RunOnce(ctx, sdktool.SpawnSpec{
		Command:    "echo ok",
		WorkingDir: "/tmp",
		Env:        []string{"http_proxy=http://127.0.0.1:8788"},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Output != "ok" || res.ExitCode != 0 {
		t.Errorf("result = %+v", res)
	}
	req := <-f.gotReqs
	if len(req.Spec.Argv) != 3 || req.Spec.Argv[0] != "bash" || req.Spec.Argv[1] != "-c" || req.Spec.Argv[2] != "echo ok" {
		t.Errorf("argv = %v, want bash -c <command>", req.Spec.Argv)
	}
	if !req.Spec.MergeStderr {
		t.Error("one-shot output must merge stderr")
	}
	if !hasEnv(req.Spec.Env, "http_proxy=http://127.0.0.1:8788") {
		t.Errorf("host env entry missing from %v", req.Spec.Env)
	}
	if !hasEnv(req.Spec.Env, "PAGER=cat") {
		t.Errorf("non-interactive default missing from %v", req.Spec.Env)
	}
	if hasEnvPrefix(req.Spec.Env, "M1NERVAC0NSOLE_") {
		t.Errorf("the backend environment leaked into the session: %v", req.Spec.Env)
	}
}

func hasEnv(env []string, want string) bool {
	for _, kv := range env {
		if kv == want {
			return true
		}
	}
	return false
}

func hasEnvPrefix(env []string, prefix string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

func TestToolEnvHostValueWins(t *testing.T) {
	env := toolEnv([]string{"PATH=/custom/bin", "TERM=xterm"})
	if !hasEnv(env, "PATH=/custom/bin") {
		t.Errorf("host PATH did not win: %v", env)
	}
	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("PATH appears %d times in %v", count, env)
	}
}

// --- request validation ---

func TestSessionDirRejectsOutsideWorkspace(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "task1")
	outside := t.TempDir()
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	s := &Supervisor{cfg: Config{WritableRoots: []string{root}}}
	if _, err := s.sessionDir(inside); err != nil {
		t.Errorf("inside root refused: %v", err)
	}
	for _, dir := range []string{outside, escape, "relative/path", ""} {
		if _, err := s.sessionDir(dir); err == nil {
			t.Errorf("dir %q was accepted", dir)
		}
	}
}

func TestNewSessionRejectsBadRequests(t *testing.T) {
	s := &Supervisor{
		cfg:    Config{WritableRoots: []string{t.TempDir()}, Gateway: "127.0.0.1:8788", Resolver: "127.0.0.1:53"},
		report: Report{Isolation: true},
	}
	dir := s.cfg.WritableRoots[0]
	good := &sessionWire{ID: "s", Purpose: string(netpolicy.PurposeTesting)}
	cases := []struct {
		name string
		req  request
	}{
		{"no session", request{Spec: &Spec{Argv: []string{"true"}, Dir: dir}}},
		{"bad purpose", request{Session: &sessionWire{ID: "s", Purpose: "escalate"}, Spec: &Spec{Argv: []string{"true"}, Dir: dir}}},
		{"no program", request{Session: good, Spec: &Spec{Dir: dir}}},
		{"outside workspace", request{Session: good, Spec: &Spec{Argv: []string{"true"}, Dir: "/etc"}}},
		{"bad env", request{Session: good, Spec: &Spec{Argv: []string{"true"}, Dir: dir, Env: []string{"NOEQUALS"}}}},
		{"too many extras", request{Session: good, Spec: &Spec{Argv: []string{"true"}, Dir: dir, ExtraFiles: 99}}},
	}
	for _, tc := range cases {
		if _, err := s.newSession(tc.req); err == nil {
			t.Errorf("%s: expected a refusal", tc.name)
		}
	}
	if _, err := s.newSession(request{Session: good, Spec: &Spec{Argv: []string{"true"}, Dir: dir}}); err != nil {
		t.Errorf("valid request refused: %v", err)
	}
}

func TestStartSessionRefusesWithoutCapabilities(t *testing.T) {
	s := &Supervisor{
		cfg:      Config{WritableRoots: []string{t.TempDir()}, Gateway: "127.0.0.1:8788", Resolver: "127.0.0.1:53"},
		report:   Report{Missing: []string{"netns"}, Detail: "ip netns add: operation not permitted"},
		sessions: map[string]*session{},
	}
	clientConn, serverConn := unixSocketPair(t)
	srv := newWireConn(serverConn)
	go s.startSession(srv, request{
		Session: &sessionWire{ID: "s", Purpose: string(netpolicy.PurposeTesting)},
		Spec:    &Spec{Argv: []string{"true"}, Dir: s.cfg.WritableRoots[0]},
	}, nil)
	var f frame
	if err := newWireConn(clientConn).read(&f); err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Type != frameError {
		t.Fatalf("frame type = %q, want error", f.Type)
	}
	if len(f.Missing) != 1 || f.Missing[0] != "netns" {
		t.Errorf("missing = %v, want [netns]", f.Missing)
	}
}

// unixSocketPair returns the two ends of a connected Unix stream socket.
func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socketpair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := wrap(fds[0]), wrap(fds[1])
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestReportString(t *testing.T) {
	ok := Report{Isolation: true, Checked: []string{"netns"}}
	if !strings.Contains(ok.String(), "verified") {
		t.Errorf("ok report = %q", ok.String())
	}
	bad := Report{Missing: []string{"netns"}, Detail: "operation not permitted"}
	if !strings.Contains(bad.String(), "NOT available") || !strings.Contains(bad.String(), "netns") {
		t.Errorf("bad report = %q", bad.String())
	}
}

func TestBridgeRoundTrip(t *testing.T) {
	t.Setenv(bridgeSessionEnv, "")
	t.Setenv(bridgeProgramEnv, "")
	sess := testSession()
	cmd, args, env, err := BridgeCommand(sess, []string{"/usr/bin/mcp-server", "--flag"}, []string{"TOKEN=abc"})
	if err != nil {
		t.Fatalf("BridgeCommand: %v", err)
	}
	if !strings.HasSuffix(cmd, "execbox.test") && !strings.HasSuffix(cmd, "m1nervac0nsole") {
		t.Errorf("command = %q, want this binary", cmd)
	}
	if len(args) != 5 || args[0] != "execbox" || args[1] != "bridge" || args[2] != "--" || args[3] != "/usr/bin/mcp-server" {
		t.Fatalf("args = %v", args)
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	gotSess, err := BridgeSession()
	if err != nil {
		t.Fatalf("BridgeSession: %v", err)
	}
	if gotSess != sess {
		t.Errorf("session = %+v, want %+v", gotSess, sess)
	}
	gotEnv, err := BridgeProgramEnv()
	if err != nil {
		t.Fatalf("BridgeProgramEnv: %v", err)
	}
	if len(gotEnv) != 1 || gotEnv[0] != "TOKEN=abc" {
		t.Errorf("env = %v", gotEnv)
	}
}

func TestClientKillClosesStream(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	client := NewClient(f.path)
	rwc, err := client.Run(context.Background(), testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	if err := proc.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = proc.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Kill")
	}
}

// frameTypes drains the frames the fake supervisor received.
func frameTypes(ch chan frame) []string {
	var out []string
	for {
		select {
		case fr := <-ch:
			out = append(out, fr.Type)
		default:
			return out
		}
	}
}

// TestCloseStdinEndsInputWithoutEndingTheSession proves the EOF frame: the
// client asks the supervisor to close the program's stdin, the program finishes
// on its own, and Wait returns the code it exited with. Closing the session
// instead would return the code a killed process produces and lose the last
// frames it wrote.
func TestCloseStdinEndsInputWithoutEndingTheSession(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.onStdinEOF = []frame{
		{Type: frameStdout, Data: []byte("out")},
		{Type: frameStderr, Data: []byte("err")},
		{Type: frameExit, Code: 23},
	}
	client := NewClient(f.path)
	rwc, err := client.Run(context.Background(), testSession(), Spec{Argv: []string{"cat"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, ok := ProcessOf(rwc)
	if !ok {
		t.Fatal("Run did not return a Process")
	}
	defer proc.Close()

	if _, err := proc.Write([]byte("input\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := proc.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}
	// Both streams must be read to EOF: the client writes each frame to its
	// stream, so leaving stderr unread would stall stdout.
	errCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(proc.Stderr())
		errCh <- b
	}()
	out, err := io.ReadAll(proc)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if string(out) != "out" {
		t.Errorf("stdout = %q, want %q", out, "out")
	}
	if got := string(<-errCh); got != "err" {
		t.Errorf("stderr = %q, want %q", got, "err")
	}
	code, err := proc.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if code != 23 {
		t.Errorf("exit code = %d, want the program's 23", code)
	}
	if got := frameTypes(f.gotFrames); strings.Join(got, ",") != "stdin,stdin_eof" {
		t.Errorf("frames = %v, want the input then the EOF and never the kill frame", got)
	}
}

// TestCloseStdinRefusesAPTY proves a terminal session reports the missing
// capability instead of ending the session: a PTY has no separate stdin, and
// closing the master would take the program's output with it. Kill keeps its
// meaning, so the tree can still be torn down.
func TestCloseStdinRefusesAPTY(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	client := NewClient(f.path)
	rwc, err := client.Run(context.Background(), testSession(), Spec{Argv: []string{"bash"}, Dir: "/tmp", TTY: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	defer proc.Close()

	if err := proc.CloseStdin(); !errors.Is(err, ErrNoStdinEOF) {
		t.Fatalf("CloseStdin on a PTY = %v, want ErrNoStdinEOF", err)
	}
	if got := frameTypes(f.gotFrames); len(got) != 0 {
		t.Fatalf("a refused CloseStdin still sent %v", got)
	}
	if err := proc.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	select {
	case fr := <-f.gotFrames:
		if fr.Type != frameClose {
			t.Fatalf("Kill sent %q, want %q", fr.Type, frameClose)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Kill sent nothing")
	}
}

// --- per-call process evidence ---

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readArtifact returns the single capture under dir: its manifest, its files and
// the manifest's raw bytes.
func readArtifact(t *testing.T, dir string) (artifactMeta, map[string][]byte, []byte) {
	t.Helper()
	base := filepath.Join(dir, "exec-artifacts")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read capture root: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d capture directories, want 1", len(entries))
	}
	root := filepath.Join(base, entries[0].Name())
	raw, err := os.ReadFile(filepath.Join(root, "meta.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var meta artifactMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	files := map[string][]byte{}
	for _, name := range []string{"stdin", "stdout", "stderr"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		files[name] = b
	}
	return meta, files, raw
}

// TestRunOnceSendsEOFAndFinishesAfterIt proves the one-shot contract: a program
// that reads its input to EOF is told the input ended, instead of waiting for
// bytes nobody will send, and the exit status is the program's own.
func TestRunOnceSendsEOFAndFinishesAfterIt(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.onStdinEOF = []frame{
		{Type: frameStdout, Data: []byte("after ")},
		{Type: frameStderr, Data: []byte("eof")},
		{Type: frameExit, Code: 23, StdinAccepted: new(int64(0))},
	}
	res, err := NewClient(f.path).RunOnce(context.Background(), testSession(), Spec{Argv: []string{"cat"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Exited || res.ExitCode != 23 {
		t.Fatalf("result = %+v, want the program's exit 23", res)
	}
	if !res.StdinEOF {
		t.Error("the one-shot run did not signal stdin EOF")
	}
	if got := string(res.Output); got != "after eof" {
		t.Errorf("output = %q, want both streams in arrival order", got)
	}
	if got := frameTypes(f.gotFrames); strings.Join(got, ",") != "stdin_eof" {
		t.Errorf("frames = %v, want only stdin_eof and never the kill frame", got)
	}
}

// TestRunOnceKeepsOutputWhenTheSupervisorDrops proves a failed run still returns
// what arrived, with an unknown exit rather than a successful zero, and that the
// capture says the same.
func TestRunOnceKeepsOutputWhenTheSupervisorDrops(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameStdout, Data: []byte("before")}}
	dir := t.TempDir()
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "call-drop"})
	res, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if res.Exited || res.ExitCode != -1 {
		t.Fatalf("result = %+v, want an unknown exit", res)
	}
	if got := string(res.Output); got != "before" {
		t.Errorf("output = %q, want the bytes that arrived", got)
	}
	meta, files, _ := readArtifact(t, dir)
	if meta.ExitCode != nil {
		t.Errorf("exit code = %v, want null", *meta.ExitCode)
	}
	if meta.Outcome != OutcomeTransportError {
		t.Errorf("outcome = %q, want %q", meta.Outcome, OutcomeTransportError)
	}
	if meta.Streams.Stdout.Complete || meta.Streams.Stderr.Complete {
		t.Error("a dropped run claimed complete streams")
	}
	if !bytes.Equal(files["stdout"], []byte("before")) {
		t.Errorf("captured stdout = %q, want the bytes that arrived", files["stdout"])
	}
}

// TestRunOnceCaptureSeparatesStreams proves a run with a capture identity keeps
// the two streams apart byte for byte, including invalid UTF-8, and records the
// hashes the tool result anchors on. Output still carries both.
func TestRunOnceCaptureSeparatesStreams(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	out := []byte{0xff, 0x00, 'o', 'u', 't'}
	errOut := []byte{0xfe, '\n', 'e'}
	f.frames = []frame{
		{Type: frameStdout, Data: out},
		{Type: frameStderr, Data: errOut},
		{Type: frameExit, Code: 7, StdinAccepted: new(int64(0))},
	}
	dir := t.TempDir()
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "call-7"})
	// MergeStderr is asked for and overridden: a capture records the streams apart.
	res, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{
		Argv:        []string{"true"},
		Dir:         "/tmp",
		MergeStderr: true,
		Env:         []string{"http_proxy=http://credential@127.0.0.1:8788"},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Exited || res.ExitCode != 7 {
		t.Fatalf("result = %+v, want exit 7", res)
	}
	if !bytes.Equal(res.Stdout, out) || !bytes.Equal(res.Stderr, errOut) {
		t.Errorf("streams = %q / %q, want %q / %q", res.Stdout, res.Stderr, out, errOut)
	}
	if want := append(append([]byte{}, out...), errOut...); !bytes.Equal(res.Output, want) {
		t.Errorf("output = %q, want %q", res.Output, want)
	}
	meta, files, raw := readArtifact(t, dir)
	if meta.Merged {
		t.Error("a split capture must not claim merged streams")
	}
	if !bytes.Equal(files["stdout"], out) || !bytes.Equal(files["stderr"], errOut) {
		t.Errorf("captured streams = %q / %q", files["stdout"], files["stderr"])
	}
	if len(files["stdin"]) != 0 {
		t.Errorf("stdin capture = %q, want no submitted bytes", files["stdin"])
	}
	if meta.Streams.Stdout.Bytes != int64(len(out)) || meta.Streams.Stdout.SHA256 != sha256Hex(out) {
		t.Errorf("stdout record = %+v", meta.Streams.Stdout)
	}
	if meta.Streams.Stderr.SHA256 != sha256Hex(errOut) {
		t.Errorf("stderr record = %+v", meta.Streams.Stderr)
	}
	if !meta.Streams.Stdout.Complete || !meta.Streams.Stderr.Complete {
		t.Errorf("streams = %+v, want complete", meta.Streams)
	}
	if meta.ToolUseID != "call-7" || meta.Origin != OriginTool {
		t.Errorf("identity = %q/%q", meta.ToolUseID, meta.Origin)
	}
	if meta.ExitCode == nil || *meta.ExitCode != 7 || meta.Outcome != OutcomeExited {
		t.Errorf("exit = %v/%q", meta.ExitCode, meta.Outcome)
	}
	if meta.Streams.Stdin.AcceptedBytes == nil || *meta.Streams.Stdin.AcceptedBytes != 0 {
		t.Errorf("accepted stdin = %v, want the reported 0", meta.Streams.Stdin.AcceptedBytes)
	}
	if !meta.Streams.Stdin.EOFSent {
		t.Error("the manifest does not record the EOF that was sent")
	}
	if len(meta.Argv) != 1 || meta.Argv[0] != "true" || meta.Dir != "/tmp" {
		t.Errorf("process record = %v in %q", meta.Argv, meta.Dir)
	}
	if strings.Contains(string(raw), "credential") {
		t.Errorf("the manifest recorded the environment: %s", raw)
	}
	if res.Artifact == "" || !strings.Contains(res.Artifact, sha256Hex(out)) || !strings.Contains(res.Artifact, sha256Hex(errOut)) {
		t.Errorf("pointer = %q, want the relative path and both hashes", res.Artifact)
	}
}

// TestCaptureRecordsSubmittedAndAcceptedStdin proves the two counts stay
// distinct: the file holds what the client submitted, the manifest also says how
// much the supervisor's pipe took, and a program that stops reading is visible.
func TestCaptureRecordsSubmittedAndAcceptedStdin(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	accepted := int64(4096)
	f.onStdinEOF = []frame{
		{Type: frameStdout, Data: []byte("done")},
		{Type: frameExit, Code: 0, StdinAccepted: &accepted},
	}
	dir := t.TempDir()
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "call-9"})
	rwc, err := NewClient(f.path).Run(ctx, testSession(), Spec{Argv: []string{"cat"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	defer proc.Close()
	body := bytes.Repeat([]byte("x"), 1<<20)
	if _, err := proc.Write(body); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := proc.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}
	out, err := io.ReadAll(proc)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if string(out) != "done" {
		t.Errorf("stdout = %q", out)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	meta, files, _ := readArtifact(t, dir)
	if meta.Streams.Stdin.SubmittedBytes != int64(len(body)) {
		t.Errorf("submitted = %d, want %d", meta.Streams.Stdin.SubmittedBytes, len(body))
	}
	if !bytes.Equal(files["stdin"], body) {
		t.Errorf("stdin capture is %d bytes, want the submitted %d", len(files["stdin"]), len(body))
	}
	if meta.Streams.Stdin.AcceptedBytes == nil || *meta.Streams.Stdin.AcceptedBytes != accepted {
		t.Errorf("accepted = %v, want the supervisor's %d", meta.Streams.Stdin.AcceptedBytes, accepted)
	}
	if !meta.Streams.Stdin.EOFSent {
		t.Error("the manifest does not record the EOF that was sent")
	}
	if meta.ExitCode == nil || *meta.ExitCode != 0 || meta.Outcome != OutcomeExited {
		t.Errorf("exit = %v/%q", meta.ExitCode, meta.Outcome)
	}
}

// TestCaptureDistinguishesCancelFromTimeout proves a run that never exited is
// recorded as unknown, with the reason the caller can act on.
func TestCaptureDistinguishesCancelFromTimeout(t *testing.T) {
	cases := []struct {
		name    string
		outcome string
		timeout bool
	}{
		{"deadline", OutcomeTimeout, true},
		{"cancel", OutcomeCancelled, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSupervisor(t, Report{Isolation: true})
			f.hold = make(chan struct{})
			defer close(f.hold)
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.timeout {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			} else {
				go func() {
					time.Sleep(100 * time.Millisecond)
					cancel()
				}()
			}
			ctx = WithArtifacts(ctx, ArtifactCall{Dir: dir, ToolUseID: "call-1"})
			res, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
			if err == nil {
				t.Fatal("expected the context error")
			}
			if res.Exited || res.ExitCode != -1 {
				t.Fatalf("result = %+v, want an unknown exit and never 0", res)
			}
			meta, _, _ := readArtifact(t, dir)
			if meta.Outcome != tc.outcome {
				t.Errorf("outcome = %q, want %q", meta.Outcome, tc.outcome)
			}
			if meta.ExitCode != nil {
				t.Errorf("exit code = %v, want null", *meta.ExitCode)
			}
			if meta.Streams.Stdout.Complete || meta.Streams.Stderr.Complete {
				t.Error("an interrupted capture claimed complete streams")
			}
			if res.Artifact == "" {
				t.Error("no pointer to the capture that was written")
			}
		})
	}
}

// TestCaptureRefusesASymlinkedArtifactDirectory proves a link out of the run
// workspace cannot be used to write elsewhere: the process still runs, and
// nothing is written through the link.
func TestCaptureRefusesASymlinkedArtifactDirectory(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameExit, Code: 0}}
	dir := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(dir, "exec-artifacts")); err != nil {
		t.Fatal(err)
	}
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "call-1"})
	res, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("the run must still complete: %v", err)
	}
	if res.Artifact != "" {
		t.Errorf("a refused capture reported a pointer: %q", res.Artifact)
	}
	entries, err := os.ReadDir(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the capture wrote through the link: %v", entries)
	}
}

// TestSDKIdentityReachesTheCapture proves the SDK's tool-call identity is enough
// to get a capture: a Bash spawn attaches it from its ToolContext, and the client
// reads it without the host passing anything else.
func TestSDKIdentityReachesTheCapture(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameExit, Code: 0}}
	dir := t.TempDir()
	ctx := sdktool.WithExecIdentity(context.Background(), sdktool.ExecIdentity{ToolUseID: "sdk-call", RunDir: dir})
	res, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	meta, _, _ := readArtifact(t, dir)
	if meta.ToolUseID != "sdk-call" || meta.Origin != OriginTool {
		t.Errorf("identity = %q/%q, want the SDK's tool call", meta.ToolUseID, meta.Origin)
	}
	if res.Artifact == "" {
		t.Error("the SDK identity produced no capture")
	}
}

// TestOperatorCaptureHasNoToolUseID proves an action with no tool call is
// recorded as such instead of borrowing an id it does not have.
func TestOperatorCaptureHasNoToolUseID(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameExit, Code: 0}}
	dir := t.TempDir()
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, Origin: OriginOperator})
	if _, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	meta, _, _ := readArtifact(t, dir)
	if meta.ToolUseID != "" || meta.Origin != OriginOperator {
		t.Errorf("identity = %q/%q, want an operator capture with no tool id", meta.ToolUseID, meta.Origin)
	}
}

// TestArtifactIdentityNeedsARunDirectoryOrAnOperatorOrigin proves an unusable
// call records nothing instead of guessing where evidence should go.
func TestArtifactIdentityNeedsARunDirectoryOrAnOperatorOrigin(t *testing.T) {
	ctx := context.Background()
	for _, call := range []ArtifactCall{
		{ToolUseID: "call-1"},
		{Dir: "/tmp"},
	} {
		if _, ok := ArtifactsFrom(WithArtifacts(ctx, call)); ok {
			t.Errorf("%+v was accepted", call)
		}
	}
	if _, ok := ArtifactsFrom(WithArtifacts(ctx, ArtifactCall{Dir: "relative/path", ToolUseID: "call-1"})); ok {
		t.Error("a relative run directory was accepted")
	}
	if _, ok := ArtifactsFrom(WithArtifacts(ctx, ArtifactCall{Dir: "/tmp", Origin: OriginOperator})); !ok {
		t.Error("an operator capture with a run directory was refused")
	}
}

// TestCaptureDirectoriesDoNotCollide proves repeated tool_use ids and several
// spawns in one call each get their own directory, with the permissions the
// capture promises.
func TestCaptureDirectoriesDoNotCollide(t *testing.T) {
	f := newFakeSupervisor(t, Report{Isolation: true})
	f.frames = []frame{{Type: frameExit, Code: 0}}
	dir := t.TempDir()
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "same-call"})
	const n = 50
	var wg sync.WaitGroup
	failures := make(chan string, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := NewClient(f.path).RunOnce(ctx, testSession(), Spec{Argv: []string{"true"}, Dir: "/tmp"})
			switch {
			case err != nil:
				failures <- err.Error()
			case res.Artifact == "":
				failures <- "no capture pointer"
			}
		}()
	}
	wg.Wait()
	close(failures)
	for msg := range failures {
		t.Error(msg)
	}
	base := filepath.Join(dir, "exec-artifacts")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("%d capture directories, want %d", len(entries), n)
	}
	for _, e := range entries {
		root := filepath.Join(base, e.Name())
		fi, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %o, want 0700", e.Name(), fi.Mode().Perm())
		}
		for _, name := range []string{"stdin", "stdout", "meta.json"} {
			fi, err := os.Stat(filepath.Join(root, name))
			if err != nil {
				t.Errorf("%s/%s: %v", e.Name(), name, err)
				continue
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s/%s mode = %o, want 0600", e.Name(), name, fi.Mode().Perm())
			}
		}
	}
}

package execbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Kernel tests exercise the real boundary. They never pass silently: a missing
// capability is reported as BLOCKED with the reason, because a green skip is not
// proof of enforcement.

func requireKernel(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BLOCKED: kernel test needs root (CAP_SYS_ADMIN for namespaces, cgroup v2 writes and iptables)")
	}
	for _, bin := range []string{"ip", "iptables", "setpriv", "bash"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("BLOCKED: %s is not installed", bin)
		}
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("BLOCKED: cgroup v2 is not mounted at /sys/fs/cgroup")
	}
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		t.Skip("BLOCKED: network namespaces are not available")
	}
}

// kernelEnv is one supervisor plus the paths a test needs.
type kernelEnv struct {
	sup    *Supervisor
	client Client
	cfg    Config
	ws     string
	stop   context.CancelFunc
}

func newKernelEnv(t *testing.T, gateway string) *kernelEnv {
	t.Helper()
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	handle, err := newHandle()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Socket = filepath.Join(base, "supervisor.sock")
	cfg.StateDir = filepath.Join(base, "state")
	cfg.CgroupRoot = filepath.Join("/sys/fs/cgroup", "execbox-test-"+handle)
	cfg.WritableRoots = []string{ws}
	cfg.ToolboxRoot = filepath.Join(base, "toolbox")
	cfg.Gateway = gateway
	cfg.Resolver = "127.0.0.1:5353"
	if self, err := os.Executable(); err == nil {
		cfg.Self = self
	}
	cfg.Logf = t.Logf
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	if !sup.Report().OK() {
		t.Fatalf("BLOCKED: capability self-test failed: %s", sup.Report().String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := sup.Serve(ctx); err != nil {
			t.Logf("serve: %v", err)
		}
	}()
	waitForSocket(t, cfg.Socket)
	t.Cleanup(func() {
		cancel()
		_ = sup.Close()
		removeCgroupTree(cfg.CgroupRoot)
	})
	return &kernelEnv{sup: sup, client: NewClient(cfg.Socket), cfg: cfg, ws: ws, stop: cancel}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("supervisor socket %s never appeared", path)
}

func testSess(id string) netpolicy.Session {
	return netpolicy.Session{ID: id, TaskID: 1, ConversationID: 1, Purpose: netpolicy.PurposeTesting, Revision: 1}
}

// TestKernelSessionBoundary proves the whole boundary in one session: uid,
// capabilities, filesystem visibility, and what the network admits.
func TestKernelSessionBoundary(t *testing.T) {
	requireKernel(t)
	// The gateway fixture: the only address a session may reach.
	gw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	go func() {
		for {
			c, err := gw.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, gwPort, err := net.SplitHostPort(gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// A second host service on a port the session must not reach. It listens on
	// every address so the check is policy, not "nothing was listening".
	other, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, otherPort, err := net.SplitHostPort(other.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	env := newKernelEnv(t, "127.0.0.1:"+gwPort)
	mine := filepath.Join(env.ws, "taskA")
	sibling := filepath.Join(env.ws, "taskB")
	if err := os.MkdirAll(mine, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret.txt"), []byte("sibling"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf(`set +e
echo uid=$(id -u)
echo caps=$(sed -n 's/^CapEff:\s*//p' /proc/self/status)
echo nnp=$(sed -n 's/^NoNewPrivs:\s*//p' /proc/self/status)
echo write=$( (printf x > ./own.txt && echo ok) 2>/dev/null || echo fail)
echo sibling=$( (ls %s >/dev/null 2>&1 && echo visible) || echo hidden)
echo outside=$( (cat %s >/dev/null 2>&1 && echo visible) || echo hidden)
echo gateway=$( (timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%s' >/dev/null 2>&1 && echo ok) || echo fail)
GW=$(ip route | sed -n 's/^default via \([0-9.]*\).*/\1/p')
echo otherport=$( (timeout 3 bash -c "exec 3<>/dev/tcp/$GW/%s" >/dev/null 2>&1 && echo ok) || echo fail)
echo external=$( (timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1 && echo ok) || echo fail)
`, sibling, outside, gwPort, otherPort)
	scriptPath := filepath.Join(mine, "probe.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := env.client.RunOnce(context.Background(), testSess("boundary"), Spec{
		Argv: []string{"bash", scriptPath},
		Dir:  mine,
		Env:  []string{"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	out := string(res.Output)
	t.Logf("session output:\n%s", out)
	if res.ExitCode != 0 {
		t.Fatalf("probe exited %d", res.ExitCode)
	}
	want := map[string]string{
		"uid":       "1000",
		"caps":      "0000000000000000",
		"nnp":       "1",
		"write":     "ok",
		"sibling":   "hidden",
		"outside":   "hidden",
		"gateway":   "ok",
		"otherport": "fail",
		"external":  "fail",
	}
	for key, value := range want {
		got := field(out, key)
		if got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
	// The write landed in the task workspace, which the backend can read.
	if _, err := os.Stat(filepath.Join(mine, "own.txt")); err != nil {
		t.Errorf("workspace write did not reach the host: %v", err)
	}
}

func field(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// TestKernelPrivateTmp proves a caller that asks for /tmp is served the
// session's own tmpfs: the program can write there, and a file the host left in
// /tmp is not visible inside the session. run_tool, toolbox_install and the
// stdio bridge all ask for /tmp, and the deployed supervisor's writable roots
// are only the task and session workspaces.
func TestKernelPrivateTmp(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	handle, err := newHandle()
	if err != nil {
		t.Fatal(err)
	}
	marker := "execbox-host-marker-" + handle
	if err := os.WriteFile(filepath.Join("/tmp", marker), []byte("host"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filepath.Join("/tmp", marker))

	res, err := env.client.RunOnce(context.Background(), testSess("private-tmp"), Spec{
		Argv: []string{"bash", "-c",
			"printf x > /tmp/probe && echo write=$(cat /tmp/probe); " +
				"echo host=$( (cat /tmp/" + marker + " >/dev/null 2>&1 && echo visible) || echo hidden)"},
		Dir: "/tmp",
		Env: []string{"PATH=/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatalf("a /tmp working directory was refused with the deployed roots: %v", err)
	}
	out := string(res.Output)
	t.Logf("session output:\n%s", out)
	if res.ExitCode != 0 {
		t.Fatalf("probe exited %d", res.ExitCode)
	}
	if got := field(out, "write"); got != "x" {
		t.Errorf("write = %q, want the session's own /tmp to be writable", got)
	}
	if got := field(out, "host"); got != "hidden" {
		t.Errorf("host = %q, want the host's /tmp to be invisible", got)
	}
}

// TestKernelPublishedToolSurvivesItsSession is the persistence proof: an install
// session stages a fixture under $PREFIX, the supervisor publishes it, and a
// later session of another purpose finds it on PATH and cannot write it.
func TestKernelPublishedToolSurvivesItsSession(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	install := netpolicy.Session{ID: "kernel-install", Purpose: netpolicy.PurposeInstall, Revision: 1}
	script := `set -eu
mkdir -p "$PREFIX/bin"
printf '#!/bin/sh\necho fixture-tool 1.0\n' > "$PREFIX/bin/fixture-tool"
chmod 0755 "$PREFIX/bin/fixture-tool"
echo staged-in=$PREFIX
`
	res, err := env.client.RunOnce(context.Background(), install, Spec{
		Argv: []string{"bash", "-c", script}, Dir: dir, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("install RunOnce: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("install exited %d: %s", res.ExitCode, res.Output)
	}
	if !strings.Contains(string(res.Output), "staged-in="+env.cfg.StagingRoot()) {
		t.Errorf("the install session did not get a staging prefix: %s", res.Output)
	}

	pub, err := PublishArtifact(env.client, context.Background(), install, "fixture-tool")
	if err != nil {
		t.Fatalf("PublishArtifact: %v", err)
	}
	if pub.Path != filepath.Join(env.cfg.BinDir(), "fixture-tool") || pub.Size == 0 || pub.SHA256 == "" {
		t.Fatalf("published = %+v", pub)
	}

	// A later session of a different purpose: the tool is on PATH, and the
	// published directory is read-only there.
	later := netpolicy.Session{ID: "kernel-later", Purpose: netpolicy.PurposeTesting, Revision: 1}
	res, err = env.client.RunOnce(context.Background(), later, Spec{
		Argv: []string{"bash", "-c", `set +e
echo which=$(command -v fixture-tool)
echo run=$(fixture-tool)
echo write=$( (printf x > ` + pub.Path + ` && echo ok) 2>/dev/null || echo denied)
echo prefix=${PREFIX:-none}
`},
		Dir: dir, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("later RunOnce: %v", err)
	}
	out := string(res.Output)
	t.Logf("later session output:\n%s", out)
	if got := field(out, "which"); got != pub.Path {
		t.Errorf("which = %q, want %q", got, pub.Path)
	}
	if got := field(out, "run"); got != "fixture-tool 1.0" {
		t.Errorf("run = %q, want the published tool's output", got)
	}
	if got := field(out, "write"); got != "denied" {
		t.Errorf("write = %q, want the published directory to be read-only", got)
	}
	if got := field(out, "prefix"); got != "none" {
		t.Errorf("a testing session exported PREFIX=%q", got)
	}
	// The staged copy is gone; the published one is what later sessions use.
	if entries, err := os.ReadDir(env.cfg.StagingRoot()); err == nil {
		for _, e := range entries {
			if e.Name() == install.ID {
				t.Errorf("the install staging prefix survived its publication")
			}
		}
	}
}

// TestKernelProbeLeavesALiveSupervisorAlone proves `execbox probe` can run on a
// guest that is already serving: the probe works in its own state and cgroup
// directories, so it neither sweeps the live session's state nor kills its
// process.
func TestKernelProbeLeavesALiveSupervisorAlone(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rwc, err := env.client.Run(context.Background(), testSess("live"), Spec{
		Argv: []string{"bash", "-c", "sleep 300"}, Dir: dir, Env: []string{"PATH=/usr/bin:/bin"}, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, ok := ProcessOf(rwc)
	if !ok {
		t.Fatal("no process control")
	}
	defer proc.Kill()
	// The session's state directory is what the probe's sweep would remove.
	deadline := time.Now().Add(10 * time.Second)
	state := ""
	for time.Now().Before(deadline) && state == "" {
		entries, _ := os.ReadDir(env.cfg.StateDir)
		if len(entries) > 0 {
			state = filepath.Join(env.cfg.StateDir, entries[0].Name())
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if state == "" {
		t.Fatal("the live session never created its state directory")
	}

	rep := Probe(env.cfg)
	t.Logf("probe report: %s", rep.String())

	if _, err := os.Stat(state); err != nil {
		t.Errorf("the probe removed the live session's state directory: %v", err)
	}
	if !anyProcessMatches("sleep 300") {
		t.Error("the probe killed the live session's process")
	}
}

// TestKernelTeardown proves a finished session leaves nothing behind.
func TestKernelTeardown(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := env.client.RunOnce(context.Background(), testSess("teardown"), Spec{
		Argv: []string{"/bin/true"}, Dir: dir, Env: []string{"PATH=/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Output)
	}
	assertNoSessionLeftovers(t, env.cfg)
}

// TestKernelKillRemovesProcessTree proves cancellation reaches grandchildren.
func TestKernelKillRemovesProcessTree(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rwc, err := env.client.Run(context.Background(), testSess("kill"), Spec{
		Argv: []string{"bash", "-c", "sleep 300 & echo started; wait"},
		Dir:  dir, Env: []string{"PATH=/usr/bin:/bin"}, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	buf := make([]byte, 64)
	if _, err := proc.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
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
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end after Kill")
	}
	assertNoSessionLeftovers(t, env.cfg)
}

// TestKernelStdinEOFKeepsTheSessionAlive proves the EOF frame reaches the real
// program: a program that reads stdin to EOF finishes reading and keeps running,
// so the session is still there to be torn down by Kill.
func TestKernelStdinEOFKeepsTheSessionAlive(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rwc, err := env.client.Run(context.Background(), testSess("stdin-eof"), Spec{
		Argv: []string{"bash", "-c", "cat >/dev/null; echo eof; sleep 300"},
		Dir:  dir, Env: []string{"PATH=/usr/bin:/bin"}, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	if _, err := proc.Write([]byte("input\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := proc.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}
	// The echo after cat proves the program saw EOF and is still running: a
	// session that ended on EOF would produce no further output.
	var out []byte
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(string(out), "eof") {
		if time.Now().After(deadline) {
			t.Fatalf("no output after stdin EOF: %q", out)
		}
		buf := make([]byte, 64)
		n, err := proc.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			t.Fatalf("read after stdin EOF: %v (output %q)", err, out)
		}
	}
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
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end after Kill")
	}
	assertNoSessionLeftovers(t, env.cfg)
}

// TestKernelPTY proves an interactive session works through the terminal path.
func TestKernelPTY(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rwc, err := env.client.Run(context.Background(), testSess("pty"), Spec{
		Argv: []string{"bash"}, Dir: dir, Env: []string{"PATH=/usr/bin:/bin", "TERM=dumb"},
		TTY: true, Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	defer proc.Close()
	if _, err := proc.Write([]byte("echo pty-ok; exit\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A session's output must be drained until EOF: the client writes each
	// frame to the stream, so a caller that stops reading also stops the exit
	// status from arriving.
	var got strings.Builder
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, err := proc.Read(buf)
			if n > 0 {
				got.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-drained:
	case <-time.After(20 * time.Second):
		t.Fatalf("no pty output: %q", got.String())
	}
	if !strings.Contains(got.String(), "pty-ok") {
		t.Fatalf("pty output = %q", got.String())
	}
	code, _ := proc.Wait()
	if code != 0 {
		t.Errorf("pty exit = %d, want 0", code)
	}
}

// TestKernelExtraFiles proves descriptors reach the program at fd 3 and 4, the
// mapping the Chromium CDP pipe depends on.
func TestKernelExtraFiles(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	toChildR, toChildW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer toChildW.Close()
	fromChildR, fromChildW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer fromChildR.Close()
	rwc, err := RunFiles(env.client, context.Background(), testSess("fds"), Spec{
		Argv: []string{"bash", "-c", "echo hello >&4; read -r line <&3; echo got:$line >&4"},
		Dir:  dir, Env: []string{"PATH=/usr/bin:/bin"}, ExtraFiles: 2,
	}, []*os.File{toChildR, fromChildW})
	if err != nil {
		toChildR.Close()
		fromChildW.Close()
		t.Fatalf("RunFiles: %v", err)
	}
	toChildR.Close()
	fromChildW.Close()
	proc, ok := ProcessOf(rwc)
	if !ok {
		t.Fatal("no process control")
	}
	defer proc.Close()
	buf := make([]byte, 64)
	n, err := fromChildR.Read(buf)
	if err != nil {
		t.Fatalf("read fd 4: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "hello") {
		t.Fatalf("fd 4 said %q", buf[:n])
	}
	if _, err := toChildW.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write fd 3: %v", err)
	}
	n, err = fromChildR.Read(buf)
	if err != nil {
		t.Fatalf("read fd 4 again: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "got:ping") {
		t.Fatalf("fd 4 said %q", buf[:n])
	}
	if code, _ := proc.Wait(); code != 0 {
		t.Errorf("exit = %d", code)
	}
}

// TestKernelSupervisorCrash proves a SIGKILLed supervisor leaves no running
// session, and that the next supervisor sweeps the namespaces, veth pairs,
// firewall rules and cgroups the crash left behind.
func TestKernelSupervisorCrash(t *testing.T) {
	requireKernel(t)
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	handle, err := newHandle()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Socket = filepath.Join(base, "supervisor.sock")
	cfg.StateDir = filepath.Join(base, "state")
	cfg.CgroupRoot = filepath.Join("/sys/fs/cgroup", "execbox-test-"+handle)
	cfg.WritableRoots = []string{ws}
	cfg.ToolboxRoot = filepath.Join(base, "toolbox")
	cfg.Gateway = "127.0.0.1:1"
	cfg.Resolver = "127.0.0.1:5353"
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Self = self

	cmd := exec.Command(self, "execbox", "serve-test")
	cmd.Env = append(os.Environ(),
		"EXECBOX_TEST_SOCKET="+cfg.Socket,
		"EXECBOX_TEST_STATE="+cfg.StateDir,
		"EXECBOX_TEST_CGROUP="+cfg.CgroupRoot,
		"EXECBOX_TEST_GATEWAY="+cfg.Gateway,
		"EXECBOX_TEST_RESOLVER="+cfg.Resolver,
		"EXECBOX_TEST_WORKSPACE="+ws,
		"EXECBOX_TEST_TOOLBOX="+cfg.ToolboxRoot,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start supervisor: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		removeCgroupTree(cfg.CgroupRoot)
	}()
	waitForSocket(t, cfg.Socket)

	dir := filepath.Join(ws, "task")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	client := NewClient(cfg.Socket)
	rwc, err := client.Run(context.Background(), testSess("crash"), Spec{
		Argv: []string{"bash", "-c", "echo up; sleep 300"},
		Dir:  dir, Env: []string{"PATH=/usr/bin:/bin"}, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, _ := ProcessOf(rwc)
	buf := make([]byte, 32)
	if _, err := proc.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill supervisor: %v", err)
	}
	_, _ = cmd.Process.Wait()

	// The session's processes must be gone: the child dies with the supervisor
	// (Pdeathsig) and PID 1 leaving takes the pid namespace with it.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !anyProcessMatches("sleep 300") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if anyProcessMatches("sleep 300") {
		t.Error("a session process survived the supervisor crash")
	}

	// The crash leaves the namespace, veth and rules behind; the next supervisor
	// sweeps them before it serves anything.
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	_ = sup.Close()
	assertNoSessionLeftovers(t, cfg)
}

// anyProcessMatches reports whether any process's command line contains want.
func anyProcessMatches(want string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := parsePID(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if strings.Contains(strings.ReplaceAll(string(b), "\x00", " "), want) {
			return true
		}
	}
	return false
}

func parsePID(s string) (int, error) {
	var pid int
	_, err := fmt.Sscanf(s, "%d", &pid)
	return pid, err
}

// removeCgroupTree removes a test cgroup root: cgroupfs directories cannot be
// removed with RemoveAll, and a child that still holds a process must be killed
// first.
func removeCgroupTree(root string) {
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(root, e.Name())
			_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o644)
			_ = os.Remove(dir)
		}
	}
	_ = os.Remove(root)
}

// countDirs counts the subdirectories of path: a cgroup directory also holds
// its own control files, so counting entries would be wrong.
func countDirs(path string) int {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n
}

// assertNoSessionLeftovers checks every artefact a session can create.
func assertNoSessionLeftovers(t *testing.T, cfg Config) {
	t.Helper()
	if n := countDirs(cfg.StateDir); n > 0 {
		t.Errorf("state dir still holds %d session(s)", n)
	}
	if n := countDirs(cfg.CgroupRoot); n > 0 {
		t.Errorf("cgroup root still holds %d session(s)", n)
	}
	if entries, err := os.ReadDir("/run/netns"); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "eb-") {
				t.Errorf("network namespace %s still exists", e.Name())
			}
		}
	}
	out, err := exec.Command("ip", "-br", "link").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], "eb") && strings.HasSuffix(fields[0], "o") {
				t.Errorf("veth %s still exists", fields[0])
			}
		}
	}
	rules, err := exec.Command("iptables", "-S").Output()
	if err == nil {
		for _, line := range strings.Split(string(rules), "\n") {
			if strings.Contains(line, "EB-") {
				t.Errorf("firewall rule still exists: %s", line)
			}
		}
	}
}

// TestKernelRunOnceEOFAndSplitCapture proves the one-shot contract against the
// real supervisor: a program that reads its input to EOF finishes on the EOF the
// client sends, its own exit status survives, and the capture holds both streams
// byte for byte, including bytes that are not valid UTF-8.
func TestKernelRunOnceEOFAndSplitCapture(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "capture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "kernel-call"})
	// cat blocks until its stdin ends: without the client's EOF this run would
	// hang until the test deadline instead of exiting 23.
	res, err := env.client.RunOnce(ctx, testSess("capture"), Spec{
		Argv: []string{"bash", "-c", "cat; printf '\\377err' 1>&2; exit 23"},
		Dir:  dir,
		Env:  []string{"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
	})
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Exited || res.ExitCode != 23 {
		t.Fatalf("result = %+v, want the program's own exit 23", res)
	}
	if len(res.Stdout) != 0 {
		t.Errorf("stdout = %q, want the empty stream cat produced", res.Stdout)
	}
	if !bytes.Equal(res.Stderr, []byte("\xfferr")) {
		t.Errorf("stderr = %q, want the program's bytes", res.Stderr)
	}
	meta, files, _ := readArtifact(t, dir)
	if meta.ExitCode == nil || *meta.ExitCode != 23 || meta.Outcome != OutcomeExited {
		t.Errorf("exit = %v/%q, want 23/exited", meta.ExitCode, meta.Outcome)
	}
	if !meta.Streams.Stdin.EOFSent {
		t.Error("the manifest does not record the EOF that ended cat's input")
	}
	if meta.Streams.Stdin.AcceptedBytes == nil || *meta.Streams.Stdin.AcceptedBytes != 0 {
		t.Errorf("accepted stdin = %v, want the 0 the pipe took", meta.Streams.Stdin.AcceptedBytes)
	}
	if !bytes.Equal(files["stderr"], []byte("\xfferr")) {
		t.Errorf("captured stderr = %q", files["stderr"])
	}
	if meta.Streams.Stderr.SHA256 != sha256Hex([]byte("\xfferr")) || !meta.Streams.Stderr.Complete {
		t.Errorf("stderr record = %+v", meta.Streams.Stderr)
	}
	if meta.ToolUseID != "kernel-call" {
		t.Errorf("tool_use_id = %q", meta.ToolUseID)
	}
}

// TestKernelLargeStdinDoesNotDeadlock proves the bidirectional backpressure path
// over the real socket: more stdin than the socket buffer holds is written while
// the program's output is drained, every byte comes back, and the supervisor's
// accepted count equals what the client submitted.
func TestKernelLargeStdinDoesNotDeadlock(t *testing.T) {
	requireKernel(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "large")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := WithArtifacts(context.Background(), ArtifactCall{Dir: dir, ToolUseID: "kernel-large"})
	rwc, err := env.client.Run(ctx, testSess("large"), Spec{
		Argv: []string{"cat"},
		Dir:  dir,
		Env:  []string{"PATH=/usr/local/bin:/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	proc, ok := ProcessOf(rwc)
	if !ok {
		t.Fatal("Run did not return a Process")
	}
	defer proc.Close()
	body := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	writeDone := make(chan error, 1)
	go func() {
		_, werr := proc.Write(body)
		if werr == nil {
			werr = proc.CloseStdin()
		}
		writeDone <- werr
	}()
	got, readErr := io.ReadAll(proc)
	if readErr != nil {
		t.Fatalf("read stdout: %v", readErr)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	code, err := proc.Wait()
	if err != nil || code != 0 {
		t.Fatalf("wait = %d, %v", code, err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("echoed %d bytes, want the %d that were sent", len(got), len(body))
	}
	meta, files, _ := readArtifact(t, dir)
	if meta.Streams.Stdin.SubmittedBytes != int64(len(body)) {
		t.Errorf("submitted = %d, want %d", meta.Streams.Stdin.SubmittedBytes, len(body))
	}
	if meta.Streams.Stdin.AcceptedBytes == nil || *meta.Streams.Stdin.AcceptedBytes != int64(len(body)) {
		t.Errorf("accepted = %v, want the %d the pipe took", meta.Streams.Stdin.AcceptedBytes, len(body))
	}
	if !bytes.Equal(files["stdin"], body) || !bytes.Equal(files["stdout"], body) {
		t.Errorf("captured %d stdin and %d stdout bytes", len(files["stdin"]), len(files["stdout"]))
	}
}

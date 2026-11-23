package execbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

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

func newKernelEnv(t *testing.T, gateway string, opts ...func(*Config)) *kernelEnv {
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
	for _, o := range opts {
		o(&cfg)
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
echo foreigngw=$( (timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/%s' >/dev/null 2>&1 && echo ok) || echo fail)
`, sibling, outside, gwPort, otherPort, gwPort)
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
		// Another address on the gateway's port must not reach the recorder.
		"foreigngw": "fail",
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

// TestKernelSweepReclaimsNamespaceWithoutStateDir is the orphan case the live
// guest accumulated: teardown removes a session's state directory even when
// unlinking its namespace failed (its processes were still alive), so a sweep
// driven by the directory alone can never reclaim that namespace, and it then
// fails every later test that asserts no eb-* namespace exists.
func TestKernelSweepReclaimsNamespaceWithoutStateDir(t *testing.T) {
	requireKernel(t)
	handle, err := newHandle()
	if err != nil {
		t.Fatal(err)
	}
	name := netnsName(handle)
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("stage orphan namespace: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })

	base := t.TempDir()
	cfg := DefaultConfig()
	cfg.StateDir = filepath.Join(base, "state") // deliberately empty: no record of the handle
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	(&Supervisor{cfg: cfg.withDefaults()}).sweep() // withDefaults is what NewSupervisor applies

	if _, err := os.Stat(netnsDir + "/" + name); !os.IsNotExist(err) {
		t.Fatalf("namespace %s survived the sweep with no state directory (stat err %v)", name, err)
	}
}

// TestKernelSweepPreservesAnotherSupervisorsLiveSession guards the blast radius
// of sweeping by name: a second supervisor starting (a test's, or a restart
// racing the old process) must not delete the namespace, veth or firewall rules
// of a session that is still running under another supervisor.
func TestKernelSweepPreservesAnotherSupervisorsLiveSession(t *testing.T) {
	requireKernel(t)
	gw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	live := newKernelEnv(t, gw.Addr().String())

	stream, err := live.client.Run(context.Background(), testSess("live-during-sweep"), Spec{
		Argv: []string{"/bin/sleep", "60"}, Dir: live.ws, Env: []string{"PATH=/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// The client API does not expose the handle, so find the namespace by the
	// property the sweep itself keys on: a process is inside it.
	var name string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		entries, err := os.ReadDir(netnsDir)
		if err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), netnsPrefix) && netnsInUse(e.Name()) {
					name = e.Name()
				}
			}
		}
		if name != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if name == "" {
		t.Fatal("no live session namespace appeared")
	}

	// A second supervisor with its own StateDir owns none of the above.
	other := newKernelEnv(t, gw.Addr().String())
	other.sup.sweep()

	if _, err := os.Stat(netnsDir + "/" + name); err != nil {
		t.Fatalf("another supervisor's start deleted the live session's namespace %s: %v", name, err)
	}
	out, err := exec.Command("ip", "netns", "exec", name, "ip", "-br", "addr").CombinedOutput()
	if err != nil {
		t.Fatalf("live session's namespace %s is unusable after the sweep: %v: %s", name, err, out)
	}
	if !strings.Contains(string(out), "eb") {
		t.Fatalf("live session lost its interface after the sweep: %s", out)
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

// --- direct lane ---

// assertNoLaneLeftovers is assertNoSessionLeftovers scoped to what a lane adds
// (its FORWARD chain and masquerade), so it stays meaningful in a guest whose
// live application owns sessions of its own.
func assertNoLaneLeftovers(t *testing.T, cfg Config, handle string) {
	t.Helper()
	if n := countDirs(cfg.StateDir); n > 0 {
		t.Errorf("state dir still holds %d session(s)", n)
	}
	forward, comment := laneChain(handle), "EB-"+handle
	for _, table := range [][]string{{"-S"}, {"-t", "nat", "-S"}} {
		out, err := exec.Command("iptables", append([]string{"-w"}, table...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("list firewall rules: %v: %s", err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			i := slices.Index(fields, "--comment")
			if slices.Contains(fields, forward) ||
				(i >= 0 && i+1 < len(fields) && strings.Trim(fields[i+1], `"`) == comment) {
				t.Errorf("lane rule still exists: %s", line)
			}
		}
	}
}

const (
	laneEgress   = "lanegr"
	laneTargetIP = "10.99.0.2"
	laneNetns    = "ltgt"
)

func mustIP(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// inNetns runs fn on a thread that has joined the named network namespace, so
// the sockets fn creates live there. The thread is never unlocked: it ends with
// the goroutine instead of returning to the pool in the wrong namespace.
func inNetns(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		f, err := os.Open("/run/netns/" + name)
		if err != nil {
			done <- err
			return
		}
		err = unix.Setns(int(f.Fd()), unix.CLONE_NEWNET)
		f.Close()
		if err != nil {
			done <- err
			return
		}
		fn()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatalf("netns %s: %v", name, err)
	}
}

// laneNet is the lane's far side: a veth pair whose root end plays the egress
// interface and whose peer sits in another namespace with the target services.
type laneNet struct {
	portA, portB, portUDP int
	// fixRx counts the heartbeat bytes the target received from the client.
	fixRx atomic.Int64
	// udpSrc maps each datagram's payload to the source address it arrived from.
	mu     sync.Mutex
	udpSrc map[string]string
}

func newLaneNet(t *testing.T) *laneNet {
	t.Helper()
	_ = exec.Command("ip", "link", "del", laneEgress).Run()
	_ = exec.Command("ip", "netns", "del", laneNetns).Run()
	prevFwd, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", laneEgress).Run()
		_ = exec.Command("ip", "netns", "del", laneNetns).Run()
		if v := strings.TrimSpace(string(prevFwd)); v != "" {
			_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(v), 0o644)
		}
	})
	mustIP(t, "netns", "add", laneNetns)
	mustIP(t, "link", "add", laneEgress, "type", "veth", "peer", "name", "lanepr")
	mustIP(t, "link", "set", "lanepr", "netns", laneNetns)
	mustIP(t, "addr", "add", "10.99.0.1/24", "dev", laneEgress)
	mustIP(t, "link", "set", laneEgress, "up")
	mustIP(t, "-n", laneNetns, "addr", "add", laneTargetIP+"/24", "dev", "lanepr")
	mustIP(t, "-n", laneNetns, "link", "set", "lanepr", "up")
	mustIP(t, "-n", laneNetns, "link", "set", "lo", "up")

	n := &laneNet{}
	inNetns(t, laneNetns, func() {
		plain := func() int {
			ln, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				t.Errorf("listen: %v", err)
				return 0
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					c.Close()
				}
			}()
			return ln.Addr().(*net.TCPAddr).Port
		}
		n.portA, n.portB = plain(), plain()
		pc, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			t.Errorf("listen udp: %v", err)
			return
		}
		t.Cleanup(func() { pc.Close() })
		n.portUDP = pc.LocalAddr().(*net.UDPAddr).Port
		n.udpSrc = map[string]string{}
		// The "x" datagrams are the revocation test's heartbeat: the target
		// counts them and answers each client address one-way on its own
		// schedule. UDP has no ACKs, so nothing but the firewall can stop either
		// direction (a TCP stream would stall by itself once its ACKs died).
		var last net.Addr
		go func() {
			buf := make([]byte, 512)
			for {
				k, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				n.mu.Lock()
				n.udpSrc[string(buf[:k])] = from.(*net.UDPAddr).IP.String()
				if string(buf[:k]) == "x" {
					n.fixRx.Add(int64(k))
					last = from
				}
				n.mu.Unlock()
			}
		}()
		go func() {
			chunk := bytes.Repeat([]byte("d"), 64)
			for {
				time.Sleep(100 * time.Millisecond)
				n.mu.Lock()
				to := last
				n.mu.Unlock()
				if to == nil {
					continue
				}
				if _, err := pc.WriteTo(chunk, to); err != nil {
					return
				}
			}
		}()
	})
	if t.Failed() {
		t.FailNow()
	}
	return n
}

func laneRule(id int64, effect, pattern, proto string, ports ...int) netpolicy.Rule {
	return netpolicy.Rule{ID: id, Effect: effect, Pattern: pattern, Protocol: proto, Ports: ports, Authorized: true}
}

func laneOf(rules ...netpolicy.Rule) *DirectLane {
	return &DirectLane{Egress: laneEgress, Policy: netpolicy.State{Rules: rules}}
}

// writeScript puts a program in the task workspace and returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

var laneEnvPath = []string{"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}

func requirePython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("BLOCKED: python3 is not installed")
	}
}

// TestKernelDirectLaneScope proves what a lane admits and what it never does:
// an authorized port connects, an unauthorized one does not, and a scope that
// covers the guest's own network still cannot reach a service on the host.
func TestKernelDirectLaneScope(t *testing.T) {
	requireKernel(t)
	requirePython(t)
	ln := newLaneNet(t)

	hostAny, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostAny.Close()
	hostLo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostLo.Close()
	for _, l := range []net.Listener{hostAny, hostLo} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
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

	env := newKernelEnv(t, gw.Addr().String())
	dir := filepath.Join(env.ws, "scope")
	script := writeScript(t, dir, "probe.sh", fmt.Sprintf(`set +e
try() { (timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1 && echo ok) || echo fail; }
GW=$(ip route | sed -n 's/^default via \([0-9.]*\).*/\1/p')
echo caps=$(sed -n 's/^CapEff:\s*//p' /proc/self/status)
echo authorized=$(try %[1]s %[2]d)
echo unauthorized=$(try %[1]s %[3]d)
echo hostany=$(try $GW %[4]d)
echo hostlo=$(try 127.0.0.1 %[5]d)
echo gateway=$(try 127.0.0.1 %[6]d)
`, laneTargetIP, ln.portA, ln.portB, hostAny.Addr().(*net.TCPAddr).Port, hostLo.Addr().(*net.TCPAddr).Port, gw.Addr().(*net.TCPAddr).Port))

	lane := laneOf(
		laneRule(1, "include", laneTargetIP, "tcp", ln.portA),
		// A scope over the guest's own network: the host's side of the veth lives
		// inside it, and must still be unreachable apart from gateway and DNS.
		laneRule(2, "include", "10.98.0.0/16", "any"),
	)
	out, handle := runLaneOnce(t, env, "lane-scope", dir, lane, "bash", script)
	t.Logf("session output:\n%s", out)
	for key, want := range map[string]string{
		"authorized": "ok", "unauthorized": "fail", "hostany": "fail", "hostlo": "fail", "gateway": "ok",
	} {
		if got := field(out, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	assertNoLaneLeftovers(t, env.cfg, handle)
}

// TestKernelDirectLaneForgedSource proves a source address the session does not
// own cannot leave: the lane is bound to the session's address, so an alias the
// process bound (or a raw socket could write) dies at the root FORWARD chain.
func TestKernelDirectLaneForgedSource(t *testing.T) {
	requireKernel(t)
	requirePython(t)
	ln := newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "forge")
	script := writeScript(t, dir, "forge.py", fmt.Sprintf(`import socket, time
def bind_alias(s, src):
    deadline = time.time() + 15
    while True:
        try:
            s.bind((src, 0))
            return True
        except OSError:
            if time.time() > deadline:
                return False
            time.sleep(0.1)
def attempt(src):
    s = socket.socket()
    s.settimeout(3)
    try:
        if src and not bind_alias(s, src):
            return "nobind"
        s.connect(("%[1]s", %[2]d))
        return "ok"
    except Exception:
        return "fail"
    finally:
        s.close()
def datagram(src, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if src and not bind_alias(s, src):
            return
        s.sendto(payload, ("%[1]s", %[3]d))
    except Exception:
        pass
    finally:
        s.close()
print("real=" + attempt(None), flush=True)
print("forged=" + attempt("10.99.77.7"), flush=True)
datagram(None, b"real")
datagram("10.99.77.7", b"forged")
`, laneTargetIP, ln.portA, ln.portUDP))
	lane := laneOf(laneRule(1, "include", laneTargetIP, "any"))
	rwc, err := env.client.Run(context.Background(), testSess("lane-forge"), Spec{
		Argv: []string{"python3", script}, Dir: dir, Env: laneEnvPath, Lane: lane, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer rwc.Close()
	handle := liveHandle(t, env)
	_, inner := vethNames(handle)
	mustIP(t, "-n", netnsName(handle), "addr", "add", "10.99.77.7/32", "dev", inner)
	got, _ := io.ReadAll(rwc)
	out := string(got)
	t.Logf("session output:\n%s", out)
	if f := field(out, "real"); f != "ok" {
		t.Errorf("real source = %q, want ok", f)
	}
	if f := field(out, "forged"); f != "fail" {
		t.Errorf("forged source = %q, want fail", f)
	}
	// The TCP result alone cannot tell "dropped" from "no return path"; the
	// target saw every datagram that was let through, and from whom.
	time.Sleep(300 * time.Millisecond)
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if src := ln.udpSrc["real"]; src != "10.99.0.1" {
		t.Errorf("real datagram arrived from %q, want the masqueraded 10.99.0.1", src)
	}
	if src, ok := ln.udpSrc["forged"]; ok {
		t.Errorf("forged datagram reached the target from %s", src)
	}
	assertNoLaneLeftovers(t, env.cfg, handle)
}

// liveHandle returns the handle of the one live session of env.
func liveHandle(t *testing.T, env *kernelEnv) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if entries, err := os.ReadDir(env.cfg.StateDir); err == nil && len(entries) == 1 {
			if _, err := os.Stat("/run/netns/" + netnsName(entries[0].Name())); err == nil {
				return entries[0].Name()
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no live session appeared")
	return ""
}

// runLaneOnce keeps the session alive until its handle has been recorded for
// cleanup assertions after exit.
func runLaneOnce(t *testing.T, env *kernelEnv, id, dir string, lane *DirectLane, argv ...string) (output, handle string) {
	t.Helper()
	rwc, err := env.client.Run(context.Background(), testSess(id), Spec{
		Argv: append([]string{"bash", "-c", `read -r; exec "$@"`, id}, argv...),
		Dir:  dir, Env: laneEnvPath, Lane: lane, MergeStderr: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	handle = liveHandle(t, env)
	proc, _ := ProcessOf(rwc)
	if err := proc.CloseStdin(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(rwc)
	if err != nil {
		t.Fatal(err)
	}
	if code, err := proc.Wait(); err != nil || code != 0 {
		t.Fatalf("session exit = %d, err = %v: %s", code, err, out)
	}
	return string(out), handle
}

// TestKernelDirectLaneInputSourceGuard checks the source filter takes
// precedence over all admissions, including the conntrack shortcut.
func TestKernelDirectLaneInputSourceGuard(t *testing.T) {
	requireKernel(t)
	newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	rwc, err := env.client.Run(context.Background(), testSess("lane-input"), Spec{
		Argv: []string{"sleep", "30"}, Dir: env.ws, Env: laneEnvPath, Lane: laneOf(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	handle := liveHandle(t, env)
	env.sup.mu.Lock()
	s := env.sup.sessions[handle]
	env.sup.mu.Unlock()
	if s == nil {
		t.Fatal("session exited before its INPUT chain could be checked")
	}
	rules, err := exec.Command("iptables", "-w", "-S", s.chain).CombinedOutput()
	if err != nil {
		t.Fatalf("list INPUT chain: %v: %s", err, rules)
	}
	want := fmt.Sprintf("-A %s ! -s %s/32 -j DROP", s.chain, s.sessIP)
	for _, rule := range strings.Split(string(rules), "\n") {
		if strings.HasPrefix(rule, "-A "+s.chain+" ") {
			if rule != want {
				t.Fatalf("first INPUT rule = %q, want %q", rule, want)
			}
			return
		}
	}
	t.Fatalf("no rules in INPUT chain: %s", rules)
}

func TestKernelDirectLaneCleanupIgnoresAnotherSupervisor(t *testing.T) {
	requireKernel(t)
	newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	other := newKernelEnv(t, "127.0.0.1:1")
	rwc, err := other.client.Run(context.Background(), testSess("other-lane"), Spec{
		Argv: []string{"sleep", "30"}, Dir: other.ws, Env: laneEnvPath, Lane: laneOf(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	_, handle := runLaneOnce(t, env, "owned-lane", env.ws, laneOf(), "/bin/true")
	assertNoLaneLeftovers(t, env.cfg, handle)
}

// TestKernelDirectLaneRevocationCutsBothDirections proves a replaced snapshot
// without the rule stops an established flow in both directions: the target
// keeps sending one-way, the client keeps sending, and neither side's bytes
// arrive once the rule is gone.
func TestKernelDirectLaneRevocationCutsBothDirections(t *testing.T) {
	requireKernel(t)
	requirePython(t)
	ln := newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "revoke")
	script := writeScript(t, dir, "stream.py", fmt.Sprintf(`import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.05)
dst = ("%s", %d)
nextsend = 0.0
print("up", flush=True)
while True:
    n = 0
    end = time.time() + 0.5
    while time.time() < end:
        if time.time() >= nextsend:
            try:
                s.sendto(b"x", dst)
            except OSError:
                pass
            nextsend = time.time() + 0.2
        try:
            n += len(s.recv(4096))
        except OSError:
            pass
    print("rx", n, flush=True)
`, laneTargetIP, ln.portUDP))
	sess := testSess("lane-revoke")
	lane := laneOf(laneRule(1, "include", laneTargetIP, "udp", ln.portUDP))
	rwc, err := env.client.Run(context.Background(), sess, Spec{
		Argv: []string{"python3", script}, Dir: dir, Env: laneEnvPath, Lane: lane, MergeStderr: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer rwc.Close()
	lines := make(chan string, 256)
	go func() {
		sc := bufio.NewScanner(rwc)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	// rx drains the client's per-tick receive counts for d.
	rx := func(d time.Duration) (total int, ticks int) {
		timer := time.After(d)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					return
				}
				var k int
				if _, err := fmt.Sscanf(l, "rx %d", &k); err == nil {
					total += k
					ticks++
				}
			case <-timer:
				return
			}
		}
	}
	if total, _ := rx(2 * time.Second); total == 0 || ln.fixRx.Load() == 0 {
		t.Fatalf("flow never carried data both ways: client rx=%d, target rx=%d", total, ln.fixRx.Load())
	}

	if err := SetDirectLane(context.Background(), env.client, sess, laneOf()); err != nil {
		t.Fatalf("SetDirectLane: %v", err)
	}
	rx(1500 * time.Millisecond) // frames already in flight
	settled := ln.fixRx.Load()
	total, ticks := rx(2500 * time.Millisecond)
	if ticks == 0 {
		t.Fatal("the client stopped reporting; the test proves nothing")
	}
	if total != 0 {
		t.Errorf("client still received %d bytes after the rule was revoked", total)
	}
	if after := ln.fixRx.Load(); after != settled {
		t.Errorf("target still received %d bytes after the rule was revoked", after-settled)
	}
}

// TestKernelDirectLaneRefusesDownEgress proves a lane never falls back to the
// default route: with the interface down it is refused at start and at
// replacement, and the typed error survives the socket.
func TestKernelDirectLaneRefusesDownEgress(t *testing.T) {
	requireKernel(t)
	newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "egress")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sess := testSess("lane-egress")
	lane := laneOf(laneRule(1, "include", laneTargetIP, "any"))
	rwc, err := env.client.Run(context.Background(), sess, Spec{
		Argv: []string{"sleep", "30"}, Dir: dir, Env: laneEnvPath, Lane: lane,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer rwc.Close()
	handle := liveHandle(t, env)

	mustIP(t, "link", "set", laneEgress, "down")
	err = SetDirectLane(context.Background(), env.client, sess, lane)
	var eg *EgressError
	if !errors.Is(err, ErrEgressUnavailable) || !errors.As(err, &eg) || eg.Iface != laneEgress {
		t.Fatalf("down interface: SetDirectLane = %v, want an EgressError for %s", err, laneEgress)
	}
	// Refusing a replacement must also destroy the previous authority.
	p, _ := ProcessOf(rwc)
	ended := make(chan struct{})
	go func() { _, _ = p.Wait(); close(ended) }()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("failed replacement left its process alive")
	}
	assertNoLaneLeftovers(t, env.cfg, handle)
	if _, err := env.client.RunOnce(context.Background(), sess, Spec{
		Argv: []string{"/bin/true"}, Dir: dir, Env: laneEnvPath, Lane: lane,
	}); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("start on a down interface = %v, want ErrEgressUnavailable", err)
	}
	missing := &DirectLane{Egress: "nosuch0"}
	if err := SetDirectLane(context.Background(), env.client, sess, missing); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("missing interface: SetDirectLane = %v, want ErrEgressUnavailable", err)
	}
	mustIP(t, "link", "set", laneEgress, "up")
	if err := SetDirectLane(context.Background(), env.client, sess, lane); err != nil {
		t.Fatalf("interface back up: SetDirectLane = %v", err)
	}
}

// TestKernelDirectLaneCapNetRaw proves CAP_NET_RAW exists only with a lane.
func TestKernelDirectLaneCapNetRaw(t *testing.T) {
	requireKernel(t)
	newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "caps")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	caps := func(lane *DirectLane) string {
		res, err := env.client.RunOnce(context.Background(), testSess("lane-caps"), Spec{
			Argv: []string{"sed", "-n", "s/^CapEff:\\s*//p", "/proc/self/status"}, Dir: dir, Env: laneEnvPath, Lane: lane,
		})
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("RunOnce: %v (exit %d): %s", err, res.ExitCode, res.Output)
		}
		return strings.TrimSpace(string(res.Output))
	}
	if got := caps(nil); got != "0000000000000000" {
		t.Errorf("without a lane CapEff = %s, want none", got)
	}
	// Bit 13 is CAP_NET_RAW.
	if got := caps(laneOf()); got != "0000000000002000" {
		t.Errorf("with a lane CapEff = %s, want only CAP_NET_RAW", got)
	}
}

// TestKernelDirectLaneHostnameViaDNS proves a hostname rule works through the
// session's own resolver: the answered address is admitted for the rule's port
// and nothing else, and it was not reachable before the name was resolved.
func TestKernelDirectLaneHostnameViaDNS(t *testing.T) {
	requireKernel(t)
	requirePython(t)
	ln := newLaneNet(t)
	srv := &dns.Server{Addr: "127.0.0.1:5353", Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA && r.Question[0].Name == "app.lane.test." {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.ParseIP(laneTargetIP),
			})
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ListenAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture resolver did not start")
	}
	defer srv.Shutdown()

	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "dns")
	script := writeScript(t, dir, "dns.py", fmt.Sprintf(`import socket
def attempt(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "ok"
    except Exception:
        return "fail"
print("before=" + attempt("%[1]s", %[2]d))
ip = socket.gethostbyname("app.lane.test")
print("resolved=" + ip)
print("after=" + attempt("app.lane.test", %[2]d))
import time
time.sleep(1.5)
print("expired=" + attempt(ip, %[2]d))
print("otherport=" + attempt("app.lane.test", %[3]d))
`, laneTargetIP, ln.portA, ln.portB))
	lane := laneOf(laneRule(1, "include", "app.lane.test", "tcp", ln.portA))
	out, handle := runLaneOnce(t, env, "lane-dns", dir, lane, "python3", script)
	t.Logf("session output:\n%s", out)
	for key, want := range map[string]string{"before": "fail", "resolved": laneTargetIP, "after": "ok", "expired": "fail", "otherport": "fail"} {
		if got := field(out, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	assertNoLaneLeftovers(t, env.cfg, handle)
}

// TestKernelControllerDisconnectWithBlockedStdin proves socket ownership does
// not depend on the stdin writer returning: RDHUP kills the whole cgroup even
// when a nonreading program and its background descendant hold the pipe open.
func TestKernelControllerDisconnectWithBlockedStdin(t *testing.T) {
	requireKernel(t)
	newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "disconnect")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := NewClient(env.cfg.Socket).(*socketClient).dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer w.c.Close()
	spec := Spec{Argv: []string{"bash", "-c", "sleep 60 & wait"}, Dir: dir, Env: laneEnvPath, Lane: laneOf()}
	if err := w.write(request{Op: opStart, Session: sessionToWire(testSess("disconnect")), Spec: &spec}); err != nil {
		t.Fatal(err)
	}
	var ready frame
	if err := w.read(&ready); err != nil || ready.Type != frameReady {
		t.Fatalf("ready: %v %+v", err, ready)
	}
	cgroup := filepath.Join(env.cfg.CgroupRoot, ready.Handle)
	if err := w.write(frame{Type: frameStdin, Data: bytes.Repeat([]byte("x"), 256<<10)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if b, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs")); err != nil || len(strings.Fields(string(b))) < 2 {
		t.Fatalf("process tree never existed: %q %v", b, err)
	}
	// A second unread frame makes a MSG_PEEK EOF-only workaround insufficient.
	if err := w.write(frame{Type: frameStdin, Data: []byte("queued")}); err != nil {
		t.Fatal(err)
	}
	w.c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cgroup); os.IsNotExist(err) && countDirs(env.cfg.StateDir) == 0 {
			assertNoLaneLeftovers(t, env.cfg, ready.Handle)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("controller disconnect left the process cgroup alive")
}

func TestKernelDirectLaneDNSApplyFailureKillsSession(t *testing.T) {
	requireKernel(t)
	newLaneNet(t)
	env := newKernelEnv(t, "127.0.0.1:1")
	dir := filepath.Join(env.ws, "dns-failure")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lane := laneOf(laneRule(1, "include", "app.lane.test", "tcp", 80))
	rwc, err := env.client.Run(context.Background(), testSess("dns-failure"), Spec{
		Argv: []string{"sleep", "30"}, Dir: dir, Env: laneEnvPath, Lane: lane,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	handle := liveHandle(t, env)
	env.sup.mu.Lock()
	s := env.sup.sessions[handle]
	env.sup.mu.Unlock()
	mustIP(t, "link", "set", laneEgress, "down")
	m := new(dns.Msg)
	m.SetQuestion("app.lane.test.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "app.lane.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP(laneTargetIP)}}
	reply, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	s.observeDNS(reply)
	p, _ := ProcessOf(rwc)
	ended := make(chan struct{})
	go func() { _, _ = p.Wait(); close(ended) }()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("failed DNS apply left its session alive")
	}
	assertNoLaneLeftovers(t, env.cfg, handle)
}

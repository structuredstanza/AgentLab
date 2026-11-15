package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/limits"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

// fixtureManifestTOML is a manifest whose program is a shell, so a test can
// decide what the "tool" prints without installing anything.
const fixtureManifestTOML = `
id = "fixture-run"
name = "Fixture run"
description = "proves run_tool spawns inside a session"
category = "recon"
accepts = ["domain"]
requires = ["bash"]

[command]
program = "bash"
args = ["-c", "printf 'a.example\nb.example\n'"]
timeout_seconds = 30

[emit]
parser = "lines"
fields = ["value"]

[[emit.facts]]
kind = "line"
data = { value = "{{ record.value }}" }
`

// fixtureServer returns a Server whose live manifest set is the shipped catalog
// plus one fixture manifest, so run_tool can be driven without a database.
func fixtureServer(t *testing.T, toml string) (*Server, *manifest.Manifest) {
	t.Helper()
	m, err := manifest.Check(toml)
	if err != nil {
		t.Fatalf("fixture manifest: %v", err)
	}
	s := &Server{m: &Manager{}}
	s.manifestLive.snap.Store(&manifestSnapshot{
		set:    builtinManifests.Overlay([]*manifest.Manifest{m}),
		stored: map[string]string{m.ID: toml},
	})
	return s, m
}

// callRunTool invokes run_tool and returns its text.
func callRunTool(t *testing.T, s *Server, ctx context.Context, tool, target string) actool.Result {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"tool": tool, "target": target})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.toolRunManifest().Call(ctx, raw, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("run_tool returned an error: %v", err)
	}
	return res
}

// TestRunToolSpawnsInsideTheSession proves the spawn path: the process is started
// by the installed client with the session from the run context, its working
// directory and HOME/TMPDIR are inside a session writable root, and only stdout
// reaches the parser.
func TestRunToolSpawnsInsideTheSession(t *testing.T) {
	f := installFakeClient(t)
	f.stdout = "a.example\nb.example\n"
	f.stderr = "warning: this must not be parsed\n"
	s, _ := fixtureServer(t, fixtureManifestTOML)
	sess := netpolicy.Session{ID: "manifest-run", TaskID: 42, ConversationID: 7, Purpose: netpolicy.PurposeTesting, Revision: 3}
	ctx := execbox.WithSession(agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42}), sess)

	res := callRunTool(t, s, ctx, "fixture-run", "example.com")
	text := res.Flatten()
	if res.IsError {
		t.Fatalf("run_tool reported an error: %q", text)
	}
	for _, want := range []string{"a.example", "b.example", "2 facts"} {
		if !strings.Contains(text, want) {
			t.Errorf("result %q is missing %q", text, want)
		}
	}
	if strings.Contains(text, "warning") {
		t.Errorf("stderr reached the parser: %q", text)
	}

	spec, got, ok := f.last()
	if !ok {
		t.Fatal("the tool never reached the execution boundary")
	}
	if got != sess {
		t.Errorf("session = %+v, want the run's own %+v", got, sess)
	}
	if len(spec.Argv) < 2 || spec.Argv[0] != "bash" {
		t.Errorf("argv = %v, want the manifest's program and arguments", spec.Argv)
	}
	if spec.Dir != "/tmp" {
		t.Errorf("working directory = %q, want the session's private /tmp", spec.Dir)
	}
	env := strings.Join(spec.Env, " ")
	for _, want := range []string{"HOME=/tmp", "TMPDIR=/tmp"} {
		if !strings.Contains(env, want) {
			t.Errorf("environment %v is missing %q: a tool writing $HOME/.config would fail", spec.Env, want)
		}
	}
}

// TestRunToolKeepsNonZeroOutput proves a tool that exits non-zero still returns
// the rows it printed, with the same note the direct spawn produced.
func TestRunToolKeepsNonZeroOutput(t *testing.T) {
	f := installFakeClient(t)
	f.stdout = "a.example\n"
	f.exit = 2
	s, _ := fixtureServer(t, fixtureManifestTOML)
	ctx := execbox.WithSession(context.Background(), netpolicy.Session{ID: "manifest-run", Purpose: netpolicy.PurposeTesting})

	text := callRunTool(t, s, ctx, "fixture-run", "example.com").Flatten()
	if !strings.Contains(text, "a.example") {
		t.Errorf("the rows printed before the failure were dropped: %q", text)
	}
	if !strings.Contains(text, "exited non-zero") || !strings.Contains(text, "exit status 2") {
		t.Errorf("the non-zero exit was not reported: %q", text)
	}
}

// TestRunToolCarriesItsCapture proves run_tool attaches the calling tool_use id
// and the run workspace to the spawn, and that the result names the capture: a
// manifest run's raw streams are otherwise lost to the parser.
func TestRunToolCarriesItsCapture(t *testing.T) {
	f := installFakeClient(t)
	f.stdout = "a.example\n"
	f.artifactRef = "[exec artifact: exec-artifacts/abc-1234 (stdin sha256: aa, stdout sha256: bb, stderr sha256: cc)]"
	s, _ := fixtureServer(t, fixtureManifestTOML)
	ctx := execbox.WithSession(context.Background(), netpolicy.Session{ID: "manifest-run", Purpose: netpolicy.PurposeTesting})
	raw, err := json.Marshal(map[string]any{"tool": "fixture-run", "target": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	res, err := s.toolRunManifest().Call(ctx, raw, &actool.ToolContext{ToolUseID: "call-42", WorkingDir: runDir})
	if err != nil {
		t.Fatalf("run_tool returned an error: %v", err)
	}
	if !f.hasArtifact {
		t.Fatal("the manifest run carried no capture identity")
	}
	if f.artifact.ToolUseID != "call-42" || f.artifact.Dir != runDir || f.artifact.Origin != execbox.OriginTool {
		t.Errorf("capture identity = %+v, want the call's id and the run workspace", f.artifact)
	}
	if text := res.Flatten(); !strings.Contains(text, f.artifactRef) {
		t.Errorf("the result does not name the capture: %q", text)
	}
}

// captureFixtureTOML writes rows on stdout, a diagnostic on stderr and exits 7:
// the shape a scanner produces when it finds results and still fails.
const captureFixtureTOML = `
id = "fixture-capture"
name = "Fixture capture"
description = "proves the manifest capture keeps both streams"
category = "recon"
accepts = ["domain"]
requires = ["bash"]

[command]
program = "bash"
args = ["-c", "printf 'a.example\\n'; printf 'diagnostic\\n' 1>&2; exit 7"]
timeout_seconds = 30

[emit]
parser = "lines"
fields = ["value"]

[[emit.facts]]
kind = "line"
data = { value = "{{ record.value }}" }
`

// TestKernelRunToolCaptureKeepsBothStreams is the end-to-end proof for a manifest
// run: the parser sees the rows and never the diagnostics, the capture keeps both
// streams byte for byte, and the manifest records the program's own exit status.
func TestKernelRunToolCaptureKeepsBothStreams(t *testing.T) {
	requireExecboxKernel(t)
	client, ws := startExecboxSupervisorWithWorkspace(t, "127.0.0.1:1")
	execbox.Install(client)
	t.Cleanup(func() { execbox.Install(nil) })

	s, _ := fixtureServer(t, captureFixtureTOML)
	runDir := filepath.Join(ws, "task-42")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := execbox.WithSession(context.Background(), netpolicy.Session{
		ID: "manifest-capture", TaskID: 42, Purpose: netpolicy.PurposeTesting, Revision: 1,
	})
	raw, err := json.Marshal(map[string]any{"tool": "fixture-capture", "target": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.toolRunManifest().Call(ctx, raw, &actool.ToolContext{ToolUseID: "call-capture", WorkingDir: runDir})
	if err != nil {
		t.Fatalf("run_tool returned an error: %v", err)
	}
	text := res.Flatten()
	if !strings.Contains(text, "a.example") {
		t.Errorf("the rows printed before the failure were dropped: %q", text)
	}
	if strings.Contains(text, "diagnostic") {
		t.Errorf("stderr reached the parser: %q", text)
	}
	if !strings.Contains(text, "exec-artifacts/") {
		t.Errorf("the result does not name the capture: %q", text)
	}

	base := filepath.Join(runDir, "exec-artifacts")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read capture root: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d capture directories, want 1", len(entries))
	}
	root := filepath.Join(base, entries[0].Name())
	stdout, err := os.ReadFile(filepath.Join(root, "stdout"))
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	stderr, err := os.ReadFile(filepath.Join(root, "stderr"))
	if err != nil {
		t.Fatalf("stderr was not captured: %v", err)
	}
	if string(stdout) != "a.example\n" {
		t.Errorf("captured stdout = %q", stdout)
	}
	if string(stderr) != "diagnostic\n" {
		t.Errorf("captured stderr = %q", stderr)
	}
	var meta struct {
		ToolUseID string `json:"tool_use_id"`
		ExitCode  *int   `json:"exit_code"`
		Outcome   string `json:"outcome"`
	}
	rawMeta, err := os.ReadFile(filepath.Join(root, "meta.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if meta.ExitCode == nil || *meta.ExitCode != 7 || meta.Outcome != execbox.OutcomeExited {
		t.Errorf("manifest = exit %v/%q, want 7/exited", meta.ExitCode, meta.Outcome)
	}
	if meta.ToolUseID != "call-capture" {
		t.Errorf("tool_use_id = %q, want the calling call's id", meta.ToolUseID)
	}
}

// threadsFixtureTOML declares a thread count, the shape every HTTP and
// credential tool ships with.
const threadsFixtureTOML = `
id = "fixture-threads"
name = "Fixture threads"
description = "proves a declared thread count is clamped to the per-target cap"
category = "recon"
accepts = ["domain"]
requires = ["bash"]

[params]
threads = { type = "number", label = "Threads", default = "50" }

[command]
program = "bash"
args = ["-c", "printf '{{ params.threads }}\n'"]
timeout_seconds = 30

[limits]
param = "threads"
unit = "threads"

[emit]
parser = "lines"
fields = ["value"]
`

// A manifest declaring 50 threads under a cap of 3 must run with 3: the cap
// counts scans, not the workers inside one, so without the clamp the operator's
// per-target intent is violated by 47 threads. A count under the cap is left
// alone, and the run record says when it was clamped.
func TestRunToolClampsDeclaredThreads(t *testing.T) {
	old := engagementLimits
	engagementLimits = limits.New(limits.Policy{MaxConcurrentPerTarget: 3, MaxConcurrentTotal: 3, MaxRequestsPerMinute: 100})
	t.Cleanup(func() { engagementLimits = old })

	f := installFakeClient(t)
	f.stdout = "a.example\n"
	s, _ := fixtureServer(t, threadsFixtureTOML)
	ctx := execbox.WithSession(context.Background(), netpolicy.Session{ID: "manifest-run", Purpose: netpolicy.PurposeTesting})

	run := func(params map[string]any) (string, string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"tool": "fixture-threads", "target": "example.com", "params": params})
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.toolRunManifest().Call(ctx, raw, &actool.ToolContext{})
		if err != nil {
			t.Fatalf("run_tool returned an error: %v", err)
		}
		spec, _, ok := f.last()
		if !ok {
			t.Fatal("the tool never reached the execution boundary")
		}
		return strings.Join(spec.Argv, " "), res.Flatten()
	}

	argv, text := run(map[string]any{"threads": 50})
	if !strings.Contains(argv, "printf '3") {
		t.Errorf("argv = %q, want the declared 50 threads clamped to the cap of 3", argv)
	}
	if !strings.Contains(text, "threads clamped from 50 to 3") {
		t.Errorf("the run record does not say the thread count was clamped: %q", text)
	}

	argv, text = run(map[string]any{"threads": 2})
	if !strings.Contains(argv, "printf '2") {
		t.Errorf("argv = %q, want the declared 2 threads unchanged", argv)
	}
	if strings.Contains(text, "clamped") {
		t.Errorf("a count under the cap was reported as clamped: %q", text)
	}
}

// installFixtureTOML is a manifest with an install script, so the install
// request can be built without a database or a supervisor.
const installFixtureTOML = `
id = "fixture-install"
name = "Fixture install"
description = "proves the install script gets the session proxy"
category = "recon"
accepts = ["domain"]
requires = ["fixture"]

[command]
program = "fixture"
args = ["{{ target.value }}"]
timeout_seconds = 30

[install]
script = "curl -fsSL https://example.invalid/fixture -o \"$PREFIX/bin/fixture\""

[emit]
parser = "lines"
fields = ["value"]

[[emit.facts]]
kind = "line"
data = { value = "{{ record.value }}" }
`

// TestInstallScriptGetsTheSessionProxyEnv proves an install can download: the
// script runs in the session's own /tmp and carries the install session's proxy
// environment, so it reaches the gateway with that session's credential instead
// of the direct network.
func TestInstallScriptGetsTheSessionProxyEnv(t *testing.T) {
	s, m := fixtureServer(t, installFixtureTOML)
	s.m.globalProxy = "http://127.0.0.1:8888"
	sess := netpolicy.Session{ID: "install-1", Purpose: netpolicy.PurposeInstall, Credential: "cred-1"}

	spec := s.installSpec(sess, m)
	if spec.Dir != "/tmp" {
		t.Errorf("install working directory = %q, want the session's private /tmp", spec.Dir)
	}
	env := strings.Join(spec.Env, " ")
	for _, want := range []string{
		"HTTP_PROXY=http://cred-1@127.0.0.1:8888",
		"HTTPS_PROXY=http://cred-1@127.0.0.1:8888",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("install environment %v is missing %q: the script cannot download", spec.Env, want)
		}
	}
}

// TestRunToolRefusesWithoutASession proves there is no direct-execution fallback:
// with the client installed and no session, the tool returns the capability error
// and nothing is started.
func TestRunToolRefusesWithoutASession(t *testing.T) {
	f := installFakeClient(t)
	s, _ := fixtureServer(t, fixtureManifestTOML)

	text := callRunTool(t, s, context.Background(), "fixture-run", "example.com").Flatten()
	if !strings.Contains(text, execboxRefusal) {
		t.Fatalf("run_tool without a session = %q, want the capability error", text)
	}
	if runOnce, run, runFiles := f.counts(); runOnce+run+runFiles != 0 {
		t.Fatalf("a refused run still reached the supervisor: runOnce=%d run=%d runFiles=%d", runOnce, run, runFiles)
	}
}

// TestRunToolRefusesWithoutAClient proves the tool does not fall back to
// spawning in the backend's own network namespace when no boundary is installed.
func TestRunToolRefusesWithoutAClient(t *testing.T) {
	execbox.Install(nil)
	t.Cleanup(func() { execbox.Install(nil) })
	s, _ := fixtureServer(t, fixtureManifestTOML)
	ctx := execbox.WithSession(context.Background(), netpolicy.Session{ID: "manifest-run", Purpose: netpolicy.PurposeTesting})

	text := callRunTool(t, s, ctx, "fixture-run", "example.com").Flatten()
	if !strings.Contains(text, execbox.ErrUnavailable.Error()) {
		t.Fatalf("run_tool without a client = %q, want the capability error", text)
	}
}

// kernelManifestTOML builds the boundary probe: one manifest whose program reports
// its uid and what its network admits. The gateway port is the only address the
// session may reach; another loopback port and an external address must fail.
func kernelManifestTOML(gatewayPort, otherPort int) string {
	script := fmt.Sprintf(
		`echo uid=$(id -u); `+
			`echo gateway=$( (timeout 3 bash -c \"exec 3<>/dev/tcp/127.0.0.1/%d\" >/dev/null 2>&1 && echo ok) || echo fail); `+
			`echo other=$( (timeout 3 bash -c \"exec 3<>/dev/tcp/127.0.0.1/%d\" >/dev/null 2>&1 && echo ok) || echo fail); `+
			`echo external=$( (timeout 3 bash -c \"exec 3<>/dev/tcp/1.1.1.1/443\" >/dev/null 2>&1 && echo ok) || echo fail)`,
		gatewayPort, otherPort)
	return `
id = "fixture-boundary"
name = "Fixture boundary"
description = "proves run_tool runs inside the session boundary"
category = "recon"
accepts = ["domain"]
requires = ["bash"]

[command]
program = "bash"
args = ["-c", "` + script + `"]
timeout_seconds = 60

[emit]
parser = "lines"
fields = ["value"]

[[emit.facts]]
kind = "probe"
data = { line = "{{ record.value }}" }
`
}

// requireExecboxKernel reports BLOCKED with the reason instead of passing
// silently: a green skip is not proof of enforcement.
func requireExecboxKernel(t *testing.T) {
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

// startExecboxSupervisor runs a real supervisor for one test and returns its
// client. The test binary stands in for the product binary, which is why
// TestMain dispatches execbox.ChildMode.
func startExecboxSupervisor(t *testing.T, gateway string) execbox.Client {
	client, _ := startExecboxSupervisorWithWorkspace(t, gateway)
	return client
}

// startExecboxSupervisorWithWorkspace also returns the session workspace, so a
// test can point a tool context at a directory the session may write.
func startExecboxSupervisorWithWorkspace(t *testing.T, gateway string) (execbox.Client, string) {
	t.Helper()
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := execbox.DefaultConfig()
	cfg.Socket = filepath.Join(base, "supervisor.sock")
	cfg.StateDir = filepath.Join(base, "state")
	cfg.CgroupRoot = filepath.Join("/sys/fs/cgroup", "execbox-server-test-"+strconv.Itoa(os.Getpid()))
	cfg.WritableRoots = []string{ws}
	cfg.Gateway = gateway
	cfg.Resolver = "127.0.0.1:5353"
	if self, err := os.Executable(); err == nil {
		cfg.Self = self
	}
	cfg.Logf = t.Logf
	sup, err := execbox.NewSupervisor(cfg)
	if err != nil {
		t.Fatalf("BLOCKED: supervisor refused to start: %v", err)
	}
	if !sup.Report().OK() {
		t.Fatalf("BLOCKED: capability self-test failed: %s", sup.Report().String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = sup.Serve(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(cfg.Socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("supervisor socket %s never appeared", cfg.Socket)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		_ = sup.Close()
		_ = os.Remove(cfg.CgroupRoot)
	})
	return execbox.NewClient(cfg.Socket), ws
}

// TestKernelRunToolReachesOnlyTheGateway is the boundary proof for the manifest
// path: a real supervisor starts the tool inside a session, where the gateway
// address is reachable and nothing else is.
func TestKernelRunToolReachesOnlyTheGateway(t *testing.T) {
	requireExecboxKernel(t)
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
	// A second host service on a port the session must not reach.
	other, err := net.Listen("tcp", "127.0.0.1:0")
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
	gwNum, _ := strconv.Atoi(gwPort)
	otherNum, _ := strconv.Atoi(otherPort)

	client := startExecboxSupervisor(t, "127.0.0.1:"+gwPort)
	execbox.Install(client)
	t.Cleanup(func() { execbox.Install(nil) })

	s, _ := fixtureServer(t, kernelManifestTOML(gwNum, otherNum))
	sess := netpolicy.Session{ID: "manifest-boundary", TaskID: 1, Purpose: netpolicy.PurposeTesting, Revision: 1}
	text := callRunTool(t, s, execbox.WithSession(context.Background(), sess), "fixture-boundary", "example.com").Flatten()
	t.Logf("run_tool session output:\n%s", text)
	for _, want := range []string{"uid=1000", "gateway=ok", "other=fail", "external=fail"} {
		if !strings.Contains(text, want) {
			t.Errorf("result %q is missing %q", text, want)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// TestMain also serves the two modes this binary is re-executed in: the session
// child the supervisor starts, and the bridge subcommand a caller that can only
// spawn a process runs. Both are the product's own entry points, so the test
// exercises them exactly as the deployed binary runs them.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "execbox" {
		switch os.Args[2] {
		case execbox.ChildMode:
			os.Exit(execbox.RunChild(os.Args[3:]))
		case "bridge":
			os.Exit(runExecboxBridge(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

// requireBridgeKernel reports BLOCKED with the reason instead of passing
// silently: a green skip is not proof of enforcement.
func requireBridgeKernel(t *testing.T) {
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

// startBridgeSupervisor runs a real supervisor for one test and returns its
// configuration, so the bridge subprocess reaches it through the socket.
func startBridgeSupervisor(t *testing.T) execbox.Config {
	t.Helper()
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := execbox.DefaultConfig()
	cfg.Socket = filepath.Join(base, "supervisor.sock")
	cfg.StateDir = filepath.Join(base, "state")
	cfg.CgroupRoot = filepath.Join("/sys/fs/cgroup", "execbox-bridge-test-"+strconv.Itoa(os.Getpid()))
	cfg.WritableRoots = []string{ws}
	cfg.ToolboxRoot = filepath.Join(base, "toolbox")
	cfg.Gateway = "127.0.0.1:1"
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
	return cfg
}

// envList flattens the bridge's environment map into the entries exec.Command
// takes.
func envList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// TestKernelBridgeReturnsTheChildExitCode is the stdin EOF proof end to end: the
// program reads stdin to EOF, finishes on its own, and the bridge process exits
// with the program's code instead of the 255 a killed session produced. The
// stderr it wrote on the way out arrives complete.
func TestKernelBridgeReturnsTheChildExitCode(t *testing.T) {
	requireBridgeKernel(t)
	cfg := startBridgeSupervisor(t)
	t.Setenv(execbox.SocketEnv, cfg.Socket)

	for _, code := range []int{0, 1, 23} {
		t.Run("exit "+strconv.Itoa(code), func(t *testing.T) {
			sess := netpolicy.Session{
				ID: "bridge-" + strconv.Itoa(code), TaskID: 1, ConversationID: 1,
				Purpose: netpolicy.PurposeTesting, Revision: 1,
			}
			script := fmt.Sprintf("cat >/dev/null; echo out-%d; echo err-%d >&2; exit %d", code, code, code)
			cmd, args, env, err := execbox.BridgeCommand(sess, []string{"bash", "-c", script}, nil)
			if err != nil {
				t.Fatalf("BridgeCommand: %v", err)
			}
			c := exec.Command(cmd, args...)
			c.Env = append(os.Environ(), envList(env)...)
			c.Stdin = strings.NewReader("input\n")
			var stdout, stderr bytes.Buffer
			c.Stdout, c.Stderr = &stdout, &stderr
			runErr := c.Run()
			got := 0
			var exit *exec.ExitError
			switch {
			case runErr == nil:
			case errors.As(runErr, &exit):
				got = exit.ExitCode()
			default:
				t.Fatalf("bridge: %v", runErr)
			}
			if got != code {
				t.Fatalf("bridge exit = %d, want the program's %d (stdout %q, stderr %q)",
					got, code, stdout.String(), stderr.String())
			}
			if want := fmt.Sprintf("out-%d", code); !strings.Contains(stdout.String(), want) {
				t.Errorf("stdout = %q, want %q", stdout.String(), want)
			}
			if want := fmt.Sprintf("err-%d", code); !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want %q: what the program wrote before exiting was lost", stderr.String(), want)
			}
		})
	}
}

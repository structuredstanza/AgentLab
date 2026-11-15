package execbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// TestNewSessionServesThePrivateTmp proves the deployed roots serve a caller
// that asks for /tmp. The guest configures only the task and session
// workspaces, and run_tool, toolbox_install and the stdio bridge all ask for
// /tmp, so it must resolve to the session's own tmpfs and never to a host bind.
func TestNewSessionServesThePrivateTmp(t *testing.T) {
	s := &Supervisor{cfg: Config{
		WritableRoots: []string{t.TempDir()},
		ToolboxRoot:   t.TempDir(),
		Gateway:       "127.0.0.1:8788",
		Resolver:      "127.0.0.1:53",
	}}
	for _, purpose := range []netpolicy.Purpose{netpolicy.PurposeTesting, netpolicy.PurposeInstall} {
		sess, err := s.newSession(request{
			Session: &sessionWire{ID: "private-tmp", Purpose: string(purpose)},
			Spec:    &Spec{Argv: []string{"true"}, Dir: "/tmp"},
		})
		if err != nil {
			t.Fatalf("%s: /tmp was refused with the deployed roots: %v", purpose, err)
		}
		if sess.spec.Dir != "/tmp" {
			t.Errorf("%s: working directory = %q, want /tmp", purpose, sess.spec.Dir)
		}
		for _, w := range sess.spec.Writable {
			if w == "/tmp" {
				t.Errorf("%s: /tmp is bind-mounted from the host: %v", purpose, sess.spec.Writable)
			}
		}
	}
}

// TestProbeUsesItsOwnState proves a probe cannot touch a live supervisor's
// sessions: it works in state, cgroup and toolbox directories of its own, and
// its cleanup leaves the live ones alone.
func TestProbeUsesItsOwnState(t *testing.T) {
	liveState, liveToolbox := t.TempDir(), t.TempDir()
	// A session handle is twelve hex characters, which is what the sweep looks
	// for in the state directory.
	handle := "0123456789ab"
	liveSession := filepath.Join(liveState, handle)
	if err := os.MkdirAll(liveSession, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: liveState, CgroupRoot: "/sys/fs/cgroup/execbox-live", ToolboxRoot: liveToolbox}

	probe, cleanup, err := probeConfig(cfg)
	if err != nil {
		t.Fatalf("probeConfig: %v", err)
	}
	defer cleanup()
	for _, dir := range []struct{ name, got, want string }{
		{"state", probe.StateDir, cfg.StateDir},
		{"cgroup", probe.CgroupRoot, cfg.CgroupRoot},
		{"toolbox", probe.ToolboxRoot, cfg.ToolboxRoot},
	} {
		if dir.got == dir.want {
			t.Errorf("the probe shares the live supervisor's %s directory %q", dir.name, dir.got)
		}
	}
	cleanup()
	if _, err := os.Stat(liveSession); err != nil {
		t.Errorf("the probe removed a live session's state: %v", err)
	}
}

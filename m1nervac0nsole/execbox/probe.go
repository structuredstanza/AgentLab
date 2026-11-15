package execbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Report is the verified capability report the server shows at startup. It is
// produced by running a real session, not by inspecting configuration: a
// configured-but-unexercised namespace is not proof of enforcement.
type Report struct {
	// Isolation is true only when every required capability was exercised.
	Isolation bool `json:"isolation"`
	// Checked lists what the self-test exercised.
	Checked []string `json:"checked"`
	// Missing names the capabilities that failed.
	Missing []string `json:"missing,omitempty"`
	// Detail carries the first failure's message.
	Detail string `json:"detail,omitempty"`
}

// OK reports whether the boundary is verified.
func (r Report) OK() bool { return r.Isolation && len(r.Missing) == 0 }

// String renders the report for a startup log line.
func (r Report) String() string {
	if r.OK() {
		return "isolation verified (" + strings.Join(r.Checked, ", ") + ")"
	}
	msg := "isolation NOT available: missing " + strings.Join(r.Missing, ", ")
	if r.Detail != "" {
		msg += " (" + r.Detail + ")"
	}
	return msg
}

// probe exercises the boundary end to end. A failure names the stage that
// failed, because "the namespace did not work" is not actionable.
func (s *Supervisor) probe() Report {
	rep := Report{Checked: []string{
		"root", "netns", "veth", "iptables", "route-localnet", "resolver",
		"cgroup-v2", "mount-namespace", "pivot-root", "setpriv", "uid-drop",
	}}
	if err := s.requirePlatform(); err != nil {
		var capErr *CapabilityError
		if errors.As(err, &capErr) {
			rep.Missing = append(rep.Missing, capErr.Missing...)
			rep.Detail = capErr.Detail
			return rep
		}
		rep.Missing = append(rep.Missing, "platform")
		rep.Detail = err.Error()
		return rep
	}
	if err := s.selfTest(); err != nil {
		stage, detail := splitStage(err.Error())
		rep.Missing = append(rep.Missing, stage)
		rep.Detail = detail
		return rep
	}
	rep.Isolation = true
	return rep
}

// selfTest runs one real session that executes /bin/true and checks the exit
// status, so every namespace, the firewall rules, the cgroup and the uid drop
// are exercised together.
func (s *Supervisor) selfTest() error {
	root := s.cfg.WritableRoots[0]
	dir, err := os.MkdirTemp(root, "execbox-selftest-")
	if err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	defer os.RemoveAll(dir)
	sess, err := s.newSession(request{
		Session: &sessionWire{ID: "selftest", Purpose: string(netpolicy.PurposeInstall)},
		Spec: &Spec{
			Argv:        []string{"/bin/true"},
			Dir:         dir,
			Env:         []string{"PATH=/usr/bin:/bin"},
			MergeStderr: true,
		},
	})
	if err != nil {
		return err
	}
	defer sess.teardown()
	if err := sess.start(nil); err != nil {
		return err
	}
	var out strings.Builder
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		if sess.stdoutR != nil {
			_, _ = io.Copy(&out, sess.stdoutR)
		}
	}()
	code := sess.wait()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		sess.closeStreams()
		<-drained
	}
	if code != 0 {
		detail := strings.TrimSpace(out.String())
		if detail == "" {
			detail = "no output"
		}
		return fmt.Errorf("session: exit %d: %s", code, detail)
	}
	return nil
}

// splitStage turns "netns: ip -n ...: exit status 1" into ("netns", rest).
func splitStage(msg string) (string, string) {
	stage, rest, ok := strings.Cut(msg, ": ")
	if !ok {
		return "session", msg
	}
	switch stage {
	case "veth", "veth move", "netns", "ipv6", "route_localnet", "iptables",
		"resolver", "cgroup", "workspace", "session", "read-only", "writable",
		"pivot_root", "new root", "mount namespace", "execbox":
		return stage, rest
	}
	return "session", msg
}

// probeConfig gives the probe state, cgroup and toolbox directories of its
// own, so a probe can never sweep a live supervisor's sessions or staging. The
// returned cleanup removes them.
func probeConfig(cfg Config) (Config, func(), error) {
	base, err := os.MkdirTemp("", "execbox-probe-")
	if err != nil {
		return cfg, nil, err
	}
	handle, err := newHandle()
	if err != nil {
		os.RemoveAll(base)
		return cfg, nil, err
	}
	cfg.StateDir = filepath.Join(base, "state")
	cfg.ToolboxRoot = filepath.Join(base, "toolbox")
	cfg.CgroupRoot = filepath.Join("/sys/fs/cgroup", "execbox-probe-"+handle)
	return cfg, func() {
		os.RemoveAll(base)
		os.Remove(cfg.CgroupRoot)
	}, nil
}

// Probe runs the same verified self-test the supervisor runs at startup, for
// the entry point's startup report and for `execbox probe`. It works in
// directories of its own, so probing a running guest leaves its sessions and
// staging alone.
func Probe(cfg Config) Report {
	cfg, cleanup, err := probeConfig(cfg)
	if err != nil {
		return Report{Missing: []string{"platform"}, Detail: err.Error()}
	}
	defer cleanup()
	s, err := NewSupervisor(cfg)
	if err != nil {
		var capErr *CapabilityError
		if errors.As(err, &capErr) {
			return Report{Missing: capErr.Missing, Detail: capErr.Detail}
		}
		return Report{Missing: []string{"platform"}, Detail: err.Error()}
	}
	return s.report
}

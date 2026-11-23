package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

func TestDirectLaneRequiresLiveVPN(t *testing.T) {
	for _, tc := range []struct {
		name       string
		interfaces []net.Interface
		want       bool
	}{
		{"absent", nil, false},
		{"other", []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, false},
		{"down", []net.Interface{{Name: "tun0", Flags: net.FlagRunning}}, false},
		{"disconnected", []net.Interface{{Name: "tun0", Flags: net.FlagUp}}, false},
		{"live", []net.Interface{{Name: "tun0", Flags: net.FlagUp | net.FlagRunning}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := directLaneVPNAvailable(tc.interfaces); got != tc.want {
				t.Fatalf("VPN available=%v want %v", got, tc.want)
			}
		})
	}
}

func TestDirectLaneInfrastructureDeny(t *testing.T) {
	t.Setenv("M1NERVAC0NSOLE_NATIVE_PROXY_URL", "http://native.fixture:8788")
	lookup := func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "host.microsandbox.internal":
			return []string{"192.0.2.8"}, nil
		case "native.fixture":
			return []string{"192.0.2.9"}, nil
		case "provider.fixture":
			return []string{"192.0.2.10"}, nil
		case "schemeless.fixture":
			return []string{"192.0.2.11"}, nil
		}
		return nil, errors.New("unknown infrastructure")
	}
	deny, err := directLaneDeny(t.Context(), []directLaneEndpoint{{profile: "primary", raw: "https://provider.fixture/v1"}}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, entry := range deny {
		set[entry] = true
	}
	for _, entry := range []string{"127.0.0.0/8", "10.98.0.0/16", "169.254.0.0/16", "192.0.2.8", "192.0.2.9", "192.0.2.10"} {
		if !set[entry] {
			t.Errorf("infrastructure %s is not denied", entry)
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			t.Fatal(err)
		}
		if !set[ip.String()] {
			t.Errorf("guest address %s not denied", ip)
		}
	}
	if set["10.0.0.0/8"] || set["172.16.0.0/12"] || set["192.168.0.0/16"] {
		t.Fatal("VPN destinations excluded wholesale")
	}
	if _, err := directLaneDeny(t.Context(), []directLaneEndpoint{{profile: "unknown", raw: "https://unknown.fixture"}}, lookup); err == nil {
		t.Fatal("unresolved infrastructure silently omitted")
	}
	// A scheme-less host:port is a valid profile endpoint (the agent layer reads
	// it as implicitly http://); it must be denied like any other, not break every
	// spawn while the VPN is up.
	deny, err = directLaneDeny(t.Context(), []directLaneEndpoint{{profile: "local", raw: "schemeless.fixture:11434"}}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(deny, "192.0.2.11") {
		t.Fatal("scheme-less endpoint infrastructure not denied")
	}
	const malformed = "http://[::1"
	if _, err := directLaneDeny(t.Context(), []directLaneEndpoint{{profile: "local", raw: malformed}}, lookup); err == nil ||
		!strings.Contains(err.Error(), `LLM profile "local"`) || strings.Contains(err.Error(), malformed) {
		t.Fatalf("invalid infrastructure must fail closed, name the profile and omit the endpoint: %v", err)
	}
}

func TestDirectManifestProfileRoutes(t *testing.T) {
	manager, _, _ := memoryTestServer(t)
	s, m := fixtureServer(t, fixtureManifestTOML)
	s.m = &Manager{pg: manager.pg, globalProxy: "http://127.0.0.1:8788"}
	m.Command.Args = []string{"{{ proxy | --proxy }}", "{{ target.value }}"}
	task, err := manager.pg.CreateTask("lane route", "local routing fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.pg.DeleteTask(task.ID)
	sess := netpolicy.Session{ID: "route", TaskID: task.ID, Purpose: netpolicy.PurposeTesting, Credential: "cred"}
	ctx := execbox.WithSession(context.Background(), sess)
	fake := installFakeClient(t)
	fake.stdout = "ok\n"
	available := true
	execbox.Install(&directLaneClient{Client: fake, snapshot: func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) {
		if !available {
			return nil, nil
		}
		return testDirectLane(1), nil
	}})
	for _, profile := range []string{"stealth", "careful", "standard", "unbound"} {
		if _, err := manager.pg.UpdateTask(task.ID, db.TaskPatch{SpeedProfile: &profile}); err != nil {
			t.Fatal(err)
		}
		for _, unit := range []string{"rps", "pps", ""} {
			_, direct, err := s.manifestDirectRoute(ctx, unit)
			want := unit == "rps" && (profile == "standard" || profile == "unbound")
			if err != nil || direct != want {
				t.Fatalf("%s/%s direct=%v err=%v", profile, unit, direct, err)
			}
			m.Limits.Unit = manifest.RateUnit(unit)
			res := callRunTool(t, s, ctx, m.ID, "192.0.2.1")
			if res.IsError {
				t.Fatal(res.Flatten())
			}
			spec, _, ok := fake.last()
			if !ok {
				t.Fatal("manifest never executed")
			}
			hasProxyArg := strings.Contains(strings.Join(spec.Argv, " "), "--proxy")
			hasProxyEnv := strings.Contains(strings.Join(spec.Env, " "), "HTTP_PROXY=")
			if hasProxyArg == want || hasProxyEnv == want {
				t.Fatalf("%s/%s route disagrees: argv=%v env=%v", profile, unit, spec.Argv, spec.Env)
			}
		}
	}
	available = false
	_, direct, err := s.manifestDirectRoute(ctx, "rps")
	if err != nil || direct {
		t.Fatalf("unavailable lane removed proxy: %v %v", direct, err)
	}
}

func TestDirectLaneGlobalProxyAndNonTestingFallback(t *testing.T) {
	manager, _, _ := memoryTestServer(t)
	old, _, err := manager.pg.GetSetting(settingGlobalProxy)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.pg.SetSetting(settingGlobalProxy, old)
	if err := manager.pg.SetSetting(settingGlobalProxy, "http://127.0.0.1:3128"); err != nil {
		t.Fatal(err)
	}
	lane, err := directLaneSnapshot(manager.pg, t.Context(), netpolicy.Session{TaskID: 1, Purpose: netpolicy.PurposeTesting})
	if lane != nil || err != nil {
		t.Fatalf("global proxy enabled lane: %+v %v", lane, err)
	}
	for _, purpose := range []netpolicy.Purpose{netpolicy.PurposeResearch, netpolicy.PurposeInstall} {
		lane, err := directLaneSnapshot(nil, t.Context(), netpolicy.Session{TaskID: 1, Purpose: purpose})
		if lane != nil || err != nil {
			t.Fatalf("%s enabled lane: %+v %v", purpose, lane, err)
		}
	}
}
func testDirectLane(rev int64) *execbox.DirectLane {
	return &execbox.DirectLane{Egress: "tun0", Policy: netpolicy.State{Revision: rev}}
}

func TestDirectLaneAllExecutionPaths(t *testing.T) {
	for _, path := range []string{"bash", "script", "manifest"} {
		t.Run(path, func(t *testing.T) {
			f := installFakeClient(t)
			f.stdout = "ok\n"
			c := &directLaneClient{Client: f, snapshot: func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) { return testDirectLane(7), nil }}
			execbox.Install(c)
			sess := netpolicy.Session{ID: "lane-path", TaskID: 1, Purpose: netpolicy.PurposeTesting, Credential: "cred"}
			ctx := execbox.WithSession(context.Background(), sess)
			env := agent.ProxyEnv("http://cred@127.0.0.1:8788", "")
			s, m := fixtureServer(t, fixtureManifestTOML)
			var err error
			switch path {
			case "bash":
				_, err = actool.NewBash().Call(ctx, json.RawMessage(`{"command":"echo ok"}`), &actool.ToolContext{WorkingDir: t.TempDir(), Env: env})
			case "script":
				manager, _, _ := memoryTestServer(t)
				s.m = manager
				_, err = s.runScriptTool(ctx, "fixture", json.RawMessage(`{"code":"print('ok')"}`), nil, &actool.ToolContext{Env: env})
			case "manifest":
				_, _, err = runManifestProcess(ctx, m, []string{"-c", "echo ok"}, 30, "http://cred@127.0.0.1:8788", "")
			}
			if err != nil {
				t.Fatal(err)
			}
			spec, _, ok := f.last()
			if !ok || spec.Lane == nil || spec.Lane.Policy.Revision != 7 {
				t.Fatalf("%s did not carry its lane: %+v", path, spec)
			}
			if !strings.Contains(strings.Join(spec.Env, " "), "HTTP_PROXY=http://cred@127.0.0.1:8788") {
				t.Fatalf("interactive recorder env lost: %v", spec.Env)
			}
		})
	}
}

type refreshingLaneClient struct {
	execbox.Client
	applied chan *execbox.DirectLane
	fail    bool
}

func (c *refreshingLaneClient) RunOnce(ctx context.Context, _ netpolicy.Session, _ execbox.Spec) (execbox.Result, error) {
	<-ctx.Done()
	return execbox.Result{}, ctx.Err()
}
func (c *refreshingLaneClient) SetDirectLane(ctx context.Context, _ netpolicy.Session, lane *execbox.DirectLane) error {
	if c.fail {
		return errors.New("apply failed")
	}
	select {
	case c.applied <- lane:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDirectLaneRefreshRevokesWithoutToolCall(t *testing.T) {
	base := &refreshingLaneClient{applied: make(chan *execbox.DirectLane, 2)}
	var revoked atomic.Bool
	c := &directLaneClient{Client: base, snapshot: func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) {
		lane := testDirectLane(1)
		if !revoked.Load() {
			lane.Policy.Rules = []netpolicy.Rule{{ID: 1, Effect: "include", Pattern: "192.0.2.1", Protocol: "tcp", Authorized: true}}
		} else {
			lane.Policy.Revision = 2
		}
		return lane, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.RunOnce(ctx, netpolicy.Session{ID: "revoke", Purpose: netpolicy.PurposeTesting}, execbox.Spec{})
		done <- err
	}()
	select {
	case <-base.applied:
	case <-ctx.Done():
		t.Fatal("initial refresh missing")
	}
	revoked.Store(true)
	select {
	case lane := <-base.applied:
		if lane.Policy.Revision != 2 || len(lane.Policy.Rules) != 0 {
			t.Fatalf("old grant retained: %+v", lane)
		}
	case <-ctx.Done():
		t.Fatal("revocation required another call")
	}
	cancel()
	<-done
}

func TestDirectLaneRefreshFailureCancels(t *testing.T) {
	for _, failure := range []string{"read", "apply", "egress"} {
		t.Run(failure, func(t *testing.T) {
			base := &refreshingLaneClient{applied: make(chan *execbox.DirectLane, 1), fail: failure == "apply"}
			var reads atomic.Int32
			c := &directLaneClient{Client: base, snapshot: func(ctx context.Context, _ netpolicy.Session) (*execbox.DirectLane, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("unbounded policy read")
				}
				if reads.Add(1) > 1 {
					switch failure {
					case "read":
						return nil, errors.New("policy unavailable")
					case "egress":
						return nil, nil
					}
				}
				return testDirectLane(1), nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			sess := netpolicy.Session{ID: failure, Purpose: netpolicy.PurposeTesting}
			sessionCtx := executionSessionContext(ctx, &Manager{}, sess)
			_, err := c.RunOnce(sessionCtx, sess, execbox.Spec{})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("failed refresh did not cancel the process: %v", err)
			}
			if sessionCtx.Err() != nil {
				t.Fatalf("refresh failure cancelled the task execution context: %v", context.Cause(sessionCtx))
			}
		})
	}
}

func TestDirectLaneProcessExitDuringRefresh(t *testing.T) {
	for _, policyErr := range []error{nil, errors.New("policy unavailable")} {
		sess := netpolicy.Session{ID: "exit-race", Purpose: netpolicy.PurposeTesting}
		sessionCtx := executionSessionContext(context.Background(), &Manager{}, sess)
		processCtx, cancelProcess := context.WithCancel(sessionCtx)
		base := &refreshingLaneClient{applied: make(chan *execbox.DirectLane, 1)}
		c := &directLaneClient{Client: base, snapshot: func(ctx context.Context, _ netpolicy.Session) (*execbox.DirectLane, error) {
			cancelProcess() // the process exits while its refresh is in flight
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return testDirectLane(1), policyErr
		}}
		done := make(chan struct{})
		go func() { c.monitor(processCtx, cancelProcess, sess); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * laneRefreshInterval):
			t.Fatal("monitor did not observe process exit")
		}
		if sessionCtx.Err() != nil {
			t.Fatalf("refresh failure cancelled the execution session: %v", context.Cause(sessionCtx))
		}
	}
}

func TestDirectManifestCannotFallBackAfterSelection(t *testing.T) {
	c := &directLaneClient{snapshot: func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) { return nil, nil }}
	ctx := context.WithValue(context.Background(), requireLaneKey{}, true)
	_, cancel, _, err := c.prepare(ctx, netpolicy.Session{}, execbox.Spec{})
	defer cancel()
	if err == nil {
		t.Fatal("direct argv would execute without a lane")
	}
}

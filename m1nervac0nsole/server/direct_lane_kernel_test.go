package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// This fixture routes only into a disposable local namespace, never a VPN or a
// real target. It exercises backend refresh through the real supervisor socket.
func TestKernelServerDirectLaneRevocation(t *testing.T) {
	requireExecboxKernel(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("BLOCKED: python3 is not installed")
	}
	iface := fmt.Sprintf("sld%d", os.Getpid())
	peer := fmt.Sprintf("slp%d", os.Getpid())
	ns := fmt.Sprintf("server-lane-%d", os.Getpid())
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	forwarding, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Fatal(err)
	}
	ip("netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", iface).Run()
		_ = exec.Command("ip", "netns", "del", ns).Run()
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", forwarding, 0644); err != nil {
			t.Errorf("restore forwarding: %v", err)
		}
	})
	ip("link", "add", iface, "type", "veth", "peer", "name", peer)
	ip("link", "set", peer, "netns", ns)
	ip("addr", "add", "198.18.254.1/30", "dev", iface)
	ip("link", "set", iface, "up")
	ip("-n", ns, "addr", "add", "198.18.254.2/30", "dev", peer)
	ip("-n", ns, "link", "set", peer, "up")
	ip("-n", ns, "link", "set", "lo", "up")
	target := exec.Command("ip", "netns", "exec", ns, "python3", "-u", "-c", `
import socket,threading,time
listeners=[]
def serve(s):
 while True:
  c,_=s.accept()
  c.close()
for port in (18081,18082):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind(('198.18.254.2',port));s.listen();listeners.append(s)
 threading.Thread(target=serve,args=(s,),daemon=True).start()
print('ready',flush=True)
time.sleep(60)
`)
	ready, err := target.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	target.Stderr = os.Stderr
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Process.Kill(); _ = target.Wait() })
	if !bufio.NewScanner(ready).Scan() {
		t.Fatal("local target did not start")
	}
	gateway, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	base := startExecboxSupervisor(t, gateway.Addr().String())
	var revoked atomic.Bool
	lane := func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) {
		rules := []netpolicy.Rule{}
		if !revoked.Load() {
			rules = append(rules, netpolicy.Rule{ID: 1, Effect: "include", Pattern: "198.18.254.2", Protocol: "tcp", Ports: []int{18081}, Authorized: true})
		}
		return &execbox.DirectLane{Egress: iface, Policy: netpolicy.State{Rules: rules}}, nil
	}
	client := &directLaneClient{Client: base, snapshot: lane}
	sess := netpolicy.Session{ID: "server-lane-local", TaskID: 1, Purpose: netpolicy.PurposeTesting}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	spec := execbox.Spec{Dir: "/tmp", MergeStderr: true, Argv: []string{"bash", "-c", `probe() { timeout .3 bash -c "exec 3<>/dev/tcp/198.18.254.2/$1" >/dev/null 2>&1; }; for i in {1..30}; do if probe 18081; then a=ok; else a=fail; fi; if probe 18082; then b=ok; else b=fail; fi; echo allowed=$a offscope=$b; sleep .1; done`}}
	rw, err := client.Run(ctx, sess, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	scanner := bufio.NewScanner(rw)
	if !scanner.Scan() || scanner.Text() != "allowed=ok offscope=fail" {
		t.Fatalf("initial route: %q %v", scanner.Text(), scanner.Err())
	}
	revoked.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	stopped := false
	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, "offscope=ok") {
			t.Fatal("off-scope fixture port was reachable")
		}
		if text == "allowed=fail offscope=fail" {
			stopped = true
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation did not cut live process within refresh bound")
		}
	}
	if !stopped {
		t.Fatalf("no revocation result: %v", scanner.Err())
	}
	_ = rw.Close()
	// No VPN/global-proxy selection produces nil: the same target is no longer
	// reachable, even though the tool ignores every HTTP proxy variable.
	fallback := &directLaneClient{Client: base, snapshot: func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) { return nil, nil }}
	spec.Argv = []string{"bash", "-c", `if timeout .3 bash -c "exec 3<>/dev/tcp/198.18.254.2/18081" >/dev/null 2>&1; then echo escaped; else echo isolated; fi`}
	result, err := fallback.RunOnce(ctx, sess, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result.Output), "isolated") || strings.Contains(string(result.Output), "escaped") {
		t.Fatalf("no-lane fallback: %s", result.Output)
	}
}

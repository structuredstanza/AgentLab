package server

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

func realToolLaneFixture(t *testing.T) (*directLaneClient, string) {
	t.Helper()
	requireExecboxKernel(t)
	for _, program := range []string{"python3", "nmap", "ffuf"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Fatalf("BLOCKED: %s is required", program)
		}
	}
	iface := fmt.Sprintf("srt%d", os.Getpid())
	peer := fmt.Sprintf("srp%d", os.Getpid())
	ns := fmt.Sprintf("server-real-tools-%d", os.Getpid())
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
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
	ip("addr", "add", "198.18.253.1/30", "dev", iface)
	ip("link", "set", iface, "up")
	ip("-n", ns, "addr", "add", "198.18.253.2/30", "dev", peer)
	ip("-n", ns, "link", "set", peer, "up")
	ip("-n", ns, "link", "set", "lo", "up")
	target := exec.Command("ip", "netns", "exec", ns, "python3", "-u", "-c", `
import http.server,socket,threading,time
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'fixture hit' if self.path=='/hit' else b'missing'
  self.send_response(200 if self.path=='/hit' else 404);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args): pass
http=http.server.ThreadingHTTPServer(('198.18.253.2',18081),Handler)
threading.Thread(target=http.serve_forever,daemon=True).start()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('198.18.253.2',18083))
def echo():
 while True:
  data,addr=udp.recvfrom(65535);udp.sendto(b'fixture reply',addr)
threading.Thread(target=echo,daemon=True).start()
# A listening but unauthorized TCP port must remain filtered, not open.
other=socket.socket();other.bind(('198.18.253.2',18085));other.listen()
print('ready',flush=True)
time.sleep(120)
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
	scanner := bufio.NewScanner(ready)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatal("local services did not start")
	}
	gateway, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	base, workspace := startExecboxSupervisorWithWorkspace(t, gateway.Addr().String())
	c := &directLaneClient{Client: base, snapshot: func(context.Context, netpolicy.Session) (*execbox.DirectLane, error) {
		return &execbox.DirectLane{Egress: iface, Policy: netpolicy.State{Revision: 1, Rules: []netpolicy.Rule{
			{ID: 1, Effect: "include", Pattern: "198.18.253.2", Protocol: "tcp", Ports: []int{18081, 18082}, Authorized: true},
			{ID: 2, Effect: "include", Pattern: "198.18.253.2", Protocol: "udp", Ports: []int{18083, 18084}, Authorized: true},
		}}}, nil
	}}
	return c, workspace
}

type fixtureNmapXML struct {
	Hosts []struct {
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				ID       int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
			} `xml:"port"`
			Extra []struct {
				State   string `xml:"state,attr"`
				Reasons []struct {
					Ports string `xml:"ports,attr"`
				} `xml:"extrareasons"`
			} `xml:"extraports"`
		} `xml:"ports"`
	} `xml:"host"`
}

func TestKernelServerRealNmapModes(t *testing.T) {
	c, _ := realToolLaneFixture(t)
	sess := netpolicy.Session{ID: "actual-nmap", TaskID: 1, Purpose: netpolicy.PurposeTesting}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	uid, err := c.RunOnce(ctx, sess, execbox.Spec{Argv: []string{"id", "-u"}, Dir: "/tmp"})
	if err != nil || strings.TrimSpace(string(uid.Output)) != "1000" {
		t.Fatalf("scanner uid: %s %v", uid.Output, err)
	}
	for _, mode := range []string{"sS", "sU", "sT"} {
		t.Run(mode, func(t *testing.T) {
			ports := "18081,18082,18085"
			want := map[int]string{18081: "open", 18082: "closed", 18085: "filtered"}
			if mode == "sU" {
				ports = "18083,18084"
				want = map[int]string{18083: "open", 18084: "closed"}
			}
			m := builtinManifests.Get("nmap")
			params, err := m.Effective(map[string]string{"ports": ports, "service": "false", "scan": mode})
			if err != nil {
				t.Fatal(err)
			}
			args, err := m.Resolve("198.18.253.2", params, "")
			if err != nil {
				t.Fatal(err)
			}
			argv := append([]string{m.Command.Program}, args...)
			argv = append(argv, "--max-retries", "0", "--host-timeout", "10s", "--initial-rtt-timeout", "200ms", "--max-rtt-timeout", "500ms")
			result, err := c.RunOnce(ctx, sess, execbox.Spec{Argv: argv, Dir: "/tmp"})
			t.Logf("uid=1000 command=%s\n%s", strings.Join(argv, " "), result.Output)
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("real nmap failed: %v exit=%d output=%s", err, result.ExitCode, result.Output)
			}
			var report fixtureNmapXML
			if err := xml.Unmarshal(result.Stdout, &report); err != nil {
				t.Fatalf("nmap XML: %v stdout=%s", err, result.Stdout)
			}
			states := map[int]string{}
			for _, host := range report.Hosts {
				for _, port := range host.Ports.Ports {
					states[port.ID] = port.State.State
				}
				for _, extra := range host.Ports.Extra {
					for _, reason := range extra.Reasons {
						for _, p := range strings.Split(reason.Ports, ",") {
							var number int
							if _, err := fmt.Sscan(p, &number); err == nil {
								states[number] = extra.State
							}
						}
					}
				}
			}
			for port, state := range want {
				if states[port] != state {
					t.Errorf("%s port %d=%q want %q", mode, port, states[port], state)
				}
			}
		})
	}
}

func TestKernelServerRealFFUFManifest(t *testing.T) {
	c, workspace := realToolLaneFixture(t)
	dsn := os.Getenv("M1NERVAC0NSOLE_PG_DSN")
	if dsn == "" {
		t.Fatal("BLOCKED: provide a disposable fixture PostgreSQL DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	manager := &Manager{pg: pg}
	task, err := manager.pg.CreateTask("ffuf fixture", "disposable local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.pg.DeleteTask(task.ID)
	s, _ := fixtureServer(t, fixtureManifestTOML)
	s.m = &Manager{pg: manager.pg, globalProxy: "http://127.0.0.1:1"}
	execbox.Install(c)
	t.Cleanup(func() { execbox.Install(nil) })
	words := filepath.Join(workspace, "words.txt")
	if err := os.WriteFile(words, []byte("miss\nhit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sess := netpolicy.Session{ID: "actual-ffuf", TaskID: task.ID, Purpose: netpolicy.PurposeTesting, Credential: "fixture"}
	ctx, cancel := context.WithTimeout(execbox.WithSession(context.Background(), sess), 30*time.Second)
	defer cancel()
	raw, _ := json.Marshal(map[string]any{"tool": "ffuf", "target": "http://198.18.253.2:18081", "params": map[string]any{"wordlist": words, "rate": "2", "match_codes": "200"}})
	result, err := s.toolRunManifest().Call(ctx, raw, &actool.ToolContext{WorkingDir: workspace, ToolUseID: "ffuf-local-proof"})
	t.Logf("real run_tool ffuf (two words, default Standard profile, unreachable recorder fallback):\n%s", result.Flatten())
	if err != nil || result.IsError {
		streams, _ := filepath.Glob(filepath.Join(workspace, "exec-artifacts", "*", "std*"))
		for _, stream := range streams {
			if body, e := os.ReadFile(stream); e == nil {
				t.Logf("%s: %s", filepath.Base(stream), body)
			}
		}
		t.Fatalf("ffuf manifest: %v %s", err, result.Flatten())
	}
	if !strings.Contains(result.Flatten(), "http://198.18.253.2:18081/hit") || !strings.Contains(result.Flatten(), "1 facts") {
		t.Fatalf("missing parsed ffuf hit: %s", result.Flatten())
	}
}

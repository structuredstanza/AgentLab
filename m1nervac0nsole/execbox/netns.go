package execbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Network isolation for one session: a private network namespace whose only
// link is a veth pair to the root namespace, where the root namespace admits
// exactly the gateway port and the session resolver and rejects the rest.
//
// The session reaches the gateway through a DNAT to the gateway's loopback
// address (route_localnet on the veth), so a gateway that binds 127.0.0.1 stays
// reachable without being exposed on any other interface. The resolver is a
// relay the supervisor runs on the veth's root-side address: the session's
// resolv.conf names that address, and forwarding to the operator's resolver is
// the supervisor's decision rather than a route the session can take itself.

// netnsName is the /run/netns entry for a session handle.
func netnsName(handle string) string { return "eb-" + handle }

// vethNames returns the root-side and session-side interface names, both within
// the kernel's 15-character limit.
func vethNames(handle string) (outer, inner string) { return "eb" + handle + "o", "eb" + handle + "i" }

// linkSessionNetns bind-mounts a process's network namespace at
// /run/netns/<name> so `ip -n <name>` can configure it. This is what
// `ip netns add` does internally; doing it ourselves keeps the name tied to the
// session handle and lets teardown be symmetric.
func linkSessionNetns(name string, pid int) error {
	if err := os.MkdirAll("/run/netns", 0o755); err != nil {
		return fmt.Errorf("netns: %w", err)
	}
	target := "/run/netns/" + name
	// The mountpoint is a regular file, the way `ip netns add` creates it: the
	// namespace is a file in nsfs, not a directory.
	f, err := os.OpenFile(target, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return fmt.Errorf("netns: %w", err)
	}
	_ = f.Close()
	src := "/proc/" + strconv.Itoa(pid) + "/ns/net"
	if err := mountBind(src, target); err != nil {
		return fmt.Errorf("netns bind: %w", err)
	}
	return nil
}

func unlinkSessionNetns(name string) {
	target := "/run/netns/" + name
	_ = syscall.Unmount(target, syscall.MNT_DETACH)
	_ = os.Remove(target)
}

// mountBind bind-mounts src at dst, which must already exist.
func mountBind(src, dst string) error {
	return syscall.Mount(src, dst, "", syscall.MS_BIND, "")
}

// setupNetwork creates the veth pair, configures both ends, installs the
// per-session firewall rules and starts the resolver relay. Every step is
// reported with its stage so a missing capability is named rather than guessed.
func (s *session) setupNetwork() error {
	outer, inner := vethNames(s.handle)
	s.vethOuter, s.vethInner = outer, inner

	// One /30 per session out of 10.98.0.0/16. A collision with another live
	// session is retried with a fresh subnet rather than failing the tool.
	ready := false
	for attempt := range 8 {
		if attempt > 0 {
			rootIP, sessIP, err := randomSubnet()
			if err != nil {
				return fmt.Errorf("veth: %w", err)
			}
			s.rootIP, s.sessIP = rootIP, sessIP
		}
		if err := s.ip("link", "add", outer, "type", "veth", "peer", "name", inner); err != nil {
			return fmt.Errorf("veth: %w", err)
		}
		if err := s.ip("link", "set", inner, "netns", netnsName(s.handle)); err != nil {
			s.ip("link", "del", outer)
			return fmt.Errorf("veth move: %w", err)
		}
		if err := s.ip("addr", "add", s.rootIP+"/30", "dev", outer); err != nil {
			s.ip("link", "del", outer)
			continue
		}
		ready = true
		break
	}
	if !ready {
		return fmt.Errorf("veth: no free session subnet")
	}

	steps := [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", inner, "up"},
		{"addr", "add", s.sessIP + "/30", "dev", inner},
		{"route", "add", "default", "via", s.rootIP},
	}
	for _, args := range steps {
		if err := s.ipNS(args...); err != nil {
			return fmt.Errorf("netns: %w", err)
		}
	}
	if err := s.ip("link", "set", outer, "up"); err != nil {
		return fmt.Errorf("veth up: %w", err)
	}
	// IPv6 must not exist on the session link: no address, no router
	// advertisements, nothing to route around the IPv4 rules.
	if err := writeSysctl("/proc/sys/net/ipv6/conf/"+outer+"/disable_ipv6", "1"); err != nil {
		return fmt.Errorf("ipv6: %w", err)
	}
	// route_localnet lets the DNAT below deliver to the gateway's loopback
	// address on this interface only.
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+outer+"/route_localnet", "1"); err != nil {
		return fmt.Errorf("route_localnet: %w", err)
	}

	if err := s.installRules(); err != nil {
		return err
	}
	if err := s.installSessionRules(); err != nil {
		return err
	}

	stop, err := startResolver(s.rootIP+":53", s.cfg.Resolver)
	if err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	s.stopResolver = stop
	return nil
}

// installRules writes the per-session firewall rules. Two chains keep teardown
// exact: the session's own chain holds the admissions, and one jump per hook
// points at it, so a stale rule can only ever be a stale jump that the startup
// sweep removes by name.
func (s *session) installRules() error {
	chain := s.chain
	outer := s.vethOuter
	gwHost, gwPort, err := net.SplitHostPort(s.cfg.Gateway)
	if err != nil {
		return fmt.Errorf("iptables: gateway %q: %w", s.cfg.Gateway, err)
	}
	run := func(table string, args ...string) error {
		full := args
		if table != "" {
			full = append([]string{"-t", table}, args...)
		}
		if out, err := exec.Command("iptables", full...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %v: %s", strings.Join(full, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run("filter", "-N", chain); err != nil {
		return err
	}
	rules := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", gwPort, "-j", "ACCEPT"},
		{"-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		{"-j", "REJECT"},
	}
	for _, r := range rules {
		if err := run("filter", append([]string{"-A", chain}, r...)...); err != nil {
			return err
		}
	}
	if err := run("filter", "-A", "INPUT", "-i", outer, "-j", chain); err != nil {
		return err
	}
	if err := run("filter", "-A", "FORWARD", "-i", outer, "-j", "REJECT"); err != nil {
		return err
	}
	if err := run("nat", "-A", "PREROUTING", "-i", outer, "-p", "tcp", "--dport", gwPort,
		"-j", "DNAT", "--to-destination", net.JoinHostPort(gwHost, gwPort)); err != nil {
		return err
	}
	return nil
}

// installSessionRules writes the session's own default-deny rules. They are
// defence in depth: the root namespace already rejects everything but the
// gateway and the resolver, and these rules die with the namespace, so a
// supervisor crash cannot leave a session with an open path.
func (s *session) installSessionRules() error {
	_, gwPort, err := net.SplitHostPort(s.cfg.Gateway)
	if err != nil {
		return fmt.Errorf("iptables session: gateway %q: %w", s.cfg.Gateway, err)
	}
	run := func(args ...string) error {
		full := append([]string{"netns", "exec", netnsName(s.handle), "iptables"}, args...)
		if out, err := exec.Command("ip", full...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables session %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	rules := [][]string{
		{"-o", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", gwPort, "-j", "ACCEPT"},
		{"-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		{"-j", "REJECT"},
	}
	for _, r := range rules {
		if err := run(append([]string{"-A", "OUTPUT"}, r...)...); err != nil {
			return err
		}
	}
	return nil
}

// removeRules deletes the session's rules. Missing rules are not an error: a
// crash may have taken the chain with it, and teardown must still finish.
func (s *session) removeRules() {
	if s.chain != "" {
		removeChain(s.chain)
	}
}

func (s *session) ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *session) ipNS(args ...string) error {
	return s.ip(append([]string{"-n", netnsName(s.handle)}, args...)...)
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}

// randomSubnet returns a root-side and session-side address for a fresh /30.
func randomSubnet() (root, sess string, err error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", "", err
	}
	third := int(b[0])
	b2 := make([]byte, 1)
	if _, err := io.ReadFull(randReader, b2); err != nil {
		return "", "", err
	}
	fourth := (int(b2[0]) & 0x3f) << 2
	root = fmt.Sprintf("10.98.%d.%d", third, fourth+1)
	sess = fmt.Sprintf("10.98.%d.%d", third, fourth+2)
	return root, sess, nil
}

// startResolver runs a forwarding DNS relay on addr (the session's view of the
// resolver) and returns a stop function. It forwards to upstream only; it is not
// a general network path, and the session cannot reach the upstream directly.
func startResolver(addr, upstream string) (func(), error) {
	up, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		return nil, fmt.Errorf("resolver upstream %q: %w", upstream, err)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolver listen %s: %w", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("resolver listen tcp %s: %w", addr, err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := net.DialUDP("udp", nil, up)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(query); err != nil {
					return
				}
				reply := make([]byte, 4096)
				n, err := conn.Read(reply)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(reply[:n], from)
			}()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, conn) }()
				_, _ = io.Copy(conn, up)
			}()
		}
	}()
	return func() {
		pc.Close()
		ln.Close()
		wg.Wait()
	}, nil
}

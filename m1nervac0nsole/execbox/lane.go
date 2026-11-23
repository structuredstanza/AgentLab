package execbox

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// The direct lane lets a session's raw tools (fuzzers, scanners) reach the
// operator-authorized scope without the recording proxy. The boundary stays in
// the root namespace: a per-session FORWARD chain admits exactly the authorized
// addresses in BOTH directions, so revoking a rule cuts a flow that is already
// established, not only new connections. A session without a lane never gets a
// path out other than the gateway and the resolver.

// DirectLane is one session's direct-path snapshot. A nil lane means the
// session reaches the gateway and the resolver only.
type DirectLane struct {
	// Policy is the state the lane is judged against. Only the task's rules
	// matter: an unauthorized include authorizes nothing, an exclusion always
	// binds.
	Policy netpolicy.State `json:"policy"`
	// Egress is the root-namespace interface the lane leaves through, for
	// example "tun0". The lane refuses to exist while it is absent or down, so
	// traffic never falls back to the default route.
	Egress string `json:"egress"`
	// Deny lists CIDRs (or bare addresses) that are always refused: the guest,
	// the host and the provider proxy. 127.0.0.0/8 is always refused as well.
	Deny []string `json:"deny,omitempty"`
}

// ErrEgressUnavailable reports a lane whose egress interface is missing or down.
var ErrEgressUnavailable = errors.New("execbox: direct lane egress interface unavailable")

// EgressError names the interface and why the lane was refused. It matches
// ErrEgressUnavailable.
type EgressError struct {
	Iface  string
	Reason string
}

func (e *EgressError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrEgressUnavailable.Error(), e.Iface, e.Reason)
}

func (e *EgressError) Is(target error) bool { return target == ErrEgressUnavailable }

var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// checkEgress refuses a lane before any rule is written when its interface
// cannot carry traffic.
func checkEgress(name string) error {
	if !ifaceName.MatchString(name) {
		return &EgressError{Iface: name, Reason: "invalid interface name"}
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return &EgressError{Iface: name, Reason: "does not exist"}
	}
	if ifc.Flags&net.FlagUp == 0 {
		return &EgressError{Iface: name, Reason: "is down"}
	}
	return nil
}

// maxDynamic bounds the addresses one session's DNS relay may add. A hostile
// zone could otherwise grow the chain without limit.
const maxDynamic = 4096

// dynEntry is one address the DNS relay learned for an authorized hostname rule.
// Rule is the include rule narrowed to the ports its exclusions leave.
type dynEntry struct {
	Name    string
	Addr    netip.Addr
	Rule    netpolicy.Rule
	Expires time.Time
}

type dynKey struct {
	rule int64
	addr netip.Addr
	name string
}

// laneState is a session's live lane. It exists only for a session started with
// a lane: the session's own OUTPUT rules are built at start, so a session that
// began without one has no path to widen later.
type laneState struct {
	mu        sync.Mutex
	cur       *DirectLane
	dyn       map[dynKey]dynEntry
	applied   string
	jumped    bool
	closed    bool
	natEgress string
	timer     *time.Timer
}

// laneChain names the session's FORWARD chain. It keeps the EB- prefix so the
// startup sweep and the leftover checks find it.
func laneChain(handle string) string { return "EB-F-" + handle }

// ipv4Net returns the IPv4 network a rule pattern names; false for a hostname
// (handled by the DNS relay) or an IPv6 pattern (the session link has no IPv6).
func ipv4Net(pattern string) (netip.Prefix, bool) {
	p := strings.TrimSpace(pattern)
	if pf, err := netip.ParsePrefix(p); err == nil {
		return pf.Masked(), pf.Addr().Is4()
	}
	if a, err := netip.ParseAddr(p); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), a.Is4()
	}
	return netip.Prefix{}, false
}

func isHostnamePattern(pattern string) bool {
	p := strings.TrimSpace(pattern)
	if _, err := netip.ParsePrefix(p); err == nil {
		return false
	}
	_, err := netip.ParseAddr(p)
	return err != nil
}

func isRuleAny(r netpolicy.Rule) bool {
	p := strings.ToLower(strings.TrimSpace(r.Protocol))
	return p == "" || p == "any"
}

// ruleProtos lists the iptables protocols a rule covers. A portless "any" is a
// single rule with no -p match, which also admits icmp; ports need tcp or udp.
func ruleProtos(r netpolicy.Rule) []string {
	switch strings.ToLower(strings.TrimSpace(r.Protocol)) {
	case "tcp", "http", "ws":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	case "dns":
		return []string{"udp", "tcp"}
	}
	if len(r.Ports) > 0 {
		return []string{"tcp", "udp"}
	}
	return []string{""}
}

// protoMatches renders the match arguments for one protocol and port list.
// multiport takes at most 15 ports, so a longer list becomes several rules.
func protoMatches(proto string, ports []int, flag string) [][]string {
	if proto == "" {
		return [][]string{nil}
	}
	if len(ports) == 0 {
		return [][]string{{"-p", proto}}
	}
	var out [][]string
	for i := 0; i < len(ports); i += 15 {
		end := min(i+15, len(ports))
		parts := make([]string, 0, 15)
		for _, p := range ports[i:end] {
			parts = append(parts, strconv.Itoa(p))
		}
		out = append(out, []string{"-p", proto, "-m", "multiport", flag, strings.Join(parts, ",")})
	}
	return out
}

// compileLane renders the full rewrite of the session's FORWARD chain for
// iptables-restore --noflush. Order is the policy: refusals (loopback, Deny,
// exclusions) come first, then the authorized accepts, so a broad include never
// covers an excluded subrange. Both directions are written so every packet of
// an established flow is re-judged against the current scope.
//
// Hostname include rules are not compiled here; the DNS relay turns their
// answers into dyn entries. A nil lane yields an empty chain.
func compileLane(chain, sessIP string, l *DirectLane, dyn []dynEntry) (string, error) {
	var lines []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			lines = append(lines, s)
		}
	}
	lines = append(lines, "*filter", ":"+chain+" - [0:0]", "-F "+chain)
	if l == nil {
		lines = append(lines, "COMMIT")
		return strings.Join(lines, "\n") + "\n", nil
	}
	if !ifaceName.MatchString(l.Egress) {
		return "", &EgressError{Iface: l.Egress, Reason: "invalid interface name"}
	}
	out := fmt.Sprintf("-A %s -s %s -o %s", chain, sessIP, l.Egress)
	back := fmt.Sprintf("-A %s -i %s -d %s", chain, l.Egress, sessIP)
	join := func(parts ...[]string) string {
		var s []string
		for _, p := range parts {
			s = append(s, p...)
		}
		return strings.Join(s, " ")
	}
	reject := func(n netip.Prefix, proto string, ports []int) {
		for _, m := range protoMatches(proto, ports, "--dports") {
			add(join([]string{out, "-d", n.String()}, m, []string{"-j", "REJECT", "--reject-with", "icmp-admin-prohibited"}))
		}
		// The return direction is dropped, not rejected: an ICMP error aimed at
		// the egress side would itself be traffic nobody authorized.
		for _, m := range protoMatches(proto, ports, "--sports") {
			add(join([]string{back, "-s", n.String()}, m, []string{"-j", "DROP"}))
		}
	}
	accept := func(n netip.Prefix, r netpolicy.Rule) {
		for _, proto := range ruleProtos(r) {
			for _, m := range protoMatches(proto, r.Ports, "--dports") {
				add(join([]string{out, "-d", n.String()}, m, []string{"-j", "ACCEPT"}))
			}
			state := "ESTABLISHED"
			if proto == "" {
				state = "ESTABLISHED,RELATED"
			}
			for _, m := range protoMatches(proto, r.Ports, "--sports") {
				add(join([]string{back, "-s", n.String()}, m, []string{"-m", "conntrack", "--ctstate", state, "-j", "ACCEPT"}))
			}
			if proto != "" {
				// An ICMP error about an admitted flow is RELATED and carries
				// no port, so the port-matched rule above never sees it.
				add(join([]string{back, "-s", n.String(), "-p", "icmp", "-m", "conntrack", "--ctstate", "RELATED", "-j", "ACCEPT"}))
			}
		}
	}

	reject(netip.MustParsePrefix("127.0.0.0/8"), "", nil)
	for _, d := range l.Deny {
		n, ok := ipv4Net(d)
		if !ok {
			// An IPv6 entry is moot (the session link has no IPv6); anything
			// else is a malformed line that must not silently widen the lane.
			if isHostnamePattern(d) {
				return "", fmt.Errorf("execbox: direct lane deny %q is not an address or CIDR", d)
			}
			continue
		}
		reject(n, "", nil)
	}
	for _, r := range l.Policy.Rules {
		if r.Effect != "exclude" {
			continue
		}
		n, ok := ipv4Net(r.Pattern)
		if !ok {
			continue
		}
		for _, proto := range ruleProtos(r) {
			reject(n, proto, r.Ports)
		}
	}
	for _, r := range l.Policy.Rules {
		if r.Effect != "include" || !r.Authorized {
			continue
		}
		if n, ok := ipv4Net(r.Pattern); ok {
			accept(n, r)
		}
	}
	for _, e := range dyn {
		accept(netip.PrefixFrom(e.Addr, 32), e.Rule)
	}
	lines = append(lines, "COMMIT")
	return strings.Join(lines, "\n") + "\n", nil
}

// grantedPorts judges one answered address for one hostname include rule with
// netpolicy's own predicate, so the lane can never authorize what the gateway
// would refuse. Only that rule and the exclusions take part: another include
// must not vouch for this rule's name. Ports are judged one at a time, so an
// exclusion written for one port narrows the entry instead of dropping it.
func grantedPorts(st netpolicy.State, r netpolicy.Rule, name string, ip netip.Addr) ([]int, bool) {
	rules := []netpolicy.Rule{r}
	for _, x := range st.Rules {
		if x.Effect == "exclude" {
			rules = append(rules, x)
		}
	}
	judged := netpolicy.State{Revision: st.Revision, Rules: rules}
	protos := []string{strings.ToLower(strings.TrimSpace(r.Protocol))}
	if isRuleAny(r) {
		protos = []string{"tcp", "udp"}
	}
	ports := r.Ports
	if len(ports) == 0 {
		ports = []int{0}
	}
	var kept []int
	for _, port := range ports {
		ok := true
		// A name-level exclusion cannot become an IP REJECT (that would
		// conflate unrelated names). Check transport aliases as well: http
		// and tcp both compile to TCP. A portless hostname grant is refused
		// conservatively if any covered port is excluded.
		for _, x := range st.Rules {
			if x.Effect != "exclude" || !isHostnamePattern(x.Pattern) {
				continue
			}
			overlap := false
			for _, a := range ruleProtos(r) {
				for _, b := range ruleProtos(x) {
					overlap = overlap || a == "" || b == "" || a == b
				}
			}
			if !overlap {
				continue
			}
			probe := port
			if len(x.Ports) != 0 {
				if port == 0 {
					probe = x.Ports[0]
				} else if !slices.Contains(x.Ports, port) {
					continue
				}
			}
			proto := x.Protocol
			if isRuleAny(x) {
				proto = "tcp"
			}
			grant := netpolicy.Rule{Effect: "include", Pattern: name, Protocol: "any", Authorized: true}
			d := netpolicy.Decide(netpolicy.PurposeTesting, netpolicy.State{Rules: []netpolicy.Rule{grant, x}},
				netpolicy.Destination{Host: name, Port: probe, Protocol: proto}, []net.IP{ip.AsSlice()})
			if !d.Allow {
				ok = false
				break
			}
		}
		for _, proto := range protos {
			d := netpolicy.Decide(netpolicy.PurposeTesting, judged,
				netpolicy.Destination{Host: name, Port: port, Protocol: proto}, []net.IP{ip.AsSlice()})
			if !d.Allow {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, port)
		}
	}
	if len(kept) == 0 {
		return nil, false
	}
	if len(r.Ports) == 0 {
		return nil, true
	}
	return kept, true
}

// restoreRules feeds one atomic ruleset to iptables-restore. --noflush keeps
// every other chain; the text itself flushes and refills only this one.
func restoreRules(text string) error {
	cmd := exec.Command("iptables-restore", "--noflush", "-w")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func iptables(args ...string) error {
	if out, err := exec.Command("iptables", append([]string{"-w"}, args...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setLane replaces this session's lane. nil empties the chain and removes the
// masquerade; the jumps stay and fall through to the session's REJECT.
func (s *session) setLane(l *DirectLane) error {
	ls := s.lane
	if ls == nil {
		return nil
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return nil
	}
	dyn := map[dynKey]dynEntry{}
	if l != nil {
		// A revoked rule, or a name an exclusion now covers, must not survive
		// as a learned address.
		for _, e := range ls.dyn {
			if !e.Expires.After(time.Now()) {
				continue
			}
			for _, r := range l.Policy.Rules {
				if r.ID != e.Rule.ID || r.Effect != "include" || !r.Authorized || !isHostnamePattern(r.Pattern) {
					continue
				}
				if ports, ok := grantedPorts(l.Policy, r, e.Name, e.Addr); ok {
					nr := r
					nr.Ports = ports
					dyn[dynKey{r.ID, e.Addr, e.Name}] = dynEntry{Name: e.Name, Addr: e.Addr, Rule: nr, Expires: e.Expires}
				}
			}
		}
	}
	return s.applyLane(ls, l, dyn)
}

// applyLane installs l with dyn. The caller holds ls.mu.
func (s *session) applyLane(ls *laneState, l *DirectLane, dyn map[dynKey]dynEntry) (err error) {
	defer func() {
		if err != nil {
			// A failed replacement must not leave a stale grant usable. Kill
			// the whole cgroup; the normal exit path owns resource teardown.
			ls.closed = true
			s.kill()
		}
	}()
	if l != nil {
		if err := checkEgress(l.Egress); err != nil {
			return err
		}
	}
	entries := make([]dynEntry, 0, len(dyn))
	for _, e := range dyn {
		entries = append(entries, e)
	}
	// Map order is random; sort so the same snapshot always renders the same
	// chain.
	sortDyn(entries)
	text, err := compileLane(laneChain(s.handle), s.sessIP, l, entries)
	if err != nil {
		return err
	}
	if l != nil {
		// A lane forwards, and the guest leaves forwarding off by default.
		if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(b)) != "1" {
			if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
				return fmt.Errorf("execbox: ip_forward: %w", err)
			}
		}
	}
	if text != ls.applied {
		if err := restoreRules(text); err != nil {
			return err
		}
		ls.applied = text
	}
	if !ls.jumped {
		chain := laneChain(s.handle)
		for _, dir := range []string{"-i", "-o"} {
			if err := iptables("-I", "FORWARD", "1", dir, s.vethOuter, "-j", chain); err != nil {
				return err
			}
		}
		ls.jumped = true
	}
	if err := s.syncMasquerade(ls, l); err != nil {
		return err
	}
	ls.cur, ls.dyn = l, dyn
	s.scheduleExpiry(ls)
	return nil
}

// syncMasquerade keeps exactly one POSTROUTING rule for the session, tagged
// with the chain name so the startup sweep can find it without knowing the
// session address.
func (s *session) syncMasquerade(ls *laneState, l *DirectLane) error {
	rule := func(egress string) []string {
		return []string{"-t", "nat", "POSTROUTING", "-s", s.sessIP, "-o", egress,
			"-m", "comment", "--comment", s.chain, "-j", "MASQUERADE"}
	}
	want := ""
	if l != nil {
		want = l.Egress
	}
	if ls.natEgress == want {
		return nil
	}
	if ls.natEgress != "" {
		r := rule(ls.natEgress)
		if err := iptables(append([]string{"-t", "nat", "-D"}, r[2:]...)...); err != nil {
			return err
		}
		ls.natEgress = ""
	}
	if want != "" {
		r := rule(want)
		if err := iptables(append([]string{"-t", "nat", "-A"}, r[2:]...)...); err != nil {
			return err
		}
		ls.natEgress = want
	}
	return nil
}

// observeDNS is called with every reply the relay forwards. An answer for a
// name an authorized hostname rule covers becomes part of the lane before the
// session sees the reply, so its first connect already finds the path.
func (s *session) observeDNS(reply []byte) {
	ls := s.lane
	if ls == nil {
		return
	}
	var m dns.Msg
	if m.Unpack(reply) != nil || !m.Response || m.Rcode != dns.RcodeSuccess || len(m.Question) == 0 {
		return
	}
	name := strings.ToLower(strings.TrimSuffix(m.Question[0].Name, "."))
	var addrs []netip.Addr
	// A CNAME can outlive neither its alias nor its address. Taking the
	// smallest answer TTL conservatively bounds the complete chain.
	ttl := uint32(^uint32(0))
	for _, rr := range m.Answer {
		ttl = min(ttl, rr.Header().Ttl)
		if a, ok := rr.(*dns.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
				addrs = append(addrs, ip)
			}
		}
	}
	if len(addrs) == 0 || ttl == 0 {
		return
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.cur == nil || ls.closed {
		return
	}
	dyn := make(map[dynKey]dynEntry, len(ls.dyn))
	for k, v := range ls.dyn {
		dyn[k] = v
	}
	changed := false
	refreshed := false
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	for _, r := range ls.cur.Policy.Rules {
		if r.Effect != "include" || !r.Authorized || !isHostnamePattern(r.Pattern) {
			continue
		}
		for _, ip := range addrs {
			ports, ok := grantedPorts(ls.cur.Policy, r, name, ip)
			if !ok {
				continue
			}
			k := dynKey{r.ID, ip, name}
			prev, have := dyn[k]
			if !have && len(dyn) >= maxDynamic {
				s.cfg.Logf("[execbox] session %s: direct lane address set is full; %s not added", s.handle, ip)
				continue
			}
			changed = changed || !have || !slices.Equal(prev.Rule.Ports, ports)
			nr := r
			nr.Ports = ports
			dyn[k] = dynEntry{Name: name, Addr: ip, Rule: nr, Expires: expires}
			refreshed = true
		}
	}
	if !changed {
		if refreshed {
			ls.dyn = dyn
			s.scheduleExpiry(ls)
		}
		return
	}
	if err := s.applyLane(ls, ls.cur, dyn); err != nil {
		s.cfg.Logf("[execbox] session %s: direct lane update failed: %v", s.handle, err)
	}
}

func sortDyn(e []dynEntry) {
	slices.SortFunc(e, func(a, b dynEntry) int {
		if c := cmp.Compare(a.Rule.ID, b.Rule.ID); c != 0 {
			return c
		}
		if c := a.Addr.Compare(b.Addr); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
}

// scheduleExpiry is called with the lane mutex held. DNS authority expires
// even when the process makes no more queries; policy refresh never renews it.
func (s *session) scheduleExpiry(ls *laneState) {
	if ls.timer != nil {
		ls.timer.Stop()
		ls.timer = nil
	}
	var next time.Time
	for _, e := range ls.dyn {
		if next.IsZero() || e.Expires.Before(next) {
			next = e.Expires
		}
	}
	if !next.IsZero() {
		ls.timer = time.AfterFunc(max(time.Until(next), 0), s.expireDNS)
	}
}

func (s *session) expireDNS() {
	ls := s.lane
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closed {
		return
	}
	now := time.Now()
	dyn := make(map[dynKey]dynEntry, len(ls.dyn))
	for k, e := range ls.dyn {
		if e.Expires.After(now) {
			dyn[k] = e
		}
	}
	if len(dyn) == len(ls.dyn) {
		s.scheduleExpiry(ls)
		return
	}
	if err := s.applyLane(ls, ls.cur, dyn); err != nil {
		s.cfg.Logf("[execbox] session %s: DNS expiry failed: %v", s.handle, err)
	}
}


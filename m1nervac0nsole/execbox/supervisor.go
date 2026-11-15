package execbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

var randReader io.Reader = rand.Reader

// Config is the supervisor's deployment configuration.
type Config struct {
	// Socket is the Unix socket the client connects to.
	Socket string
	// StateDir holds per-session scratch (config files, the new root).
	StateDir string
	// CgroupRoot is the cgroup v2 subtree the supervisor owns.
	CgroupRoot string
	// ControllerUID is the only uid allowed to talk to the supervisor.
	ControllerUID int
	// SessionUID and SessionGID are the unprivileged identity of a session.
	SessionUID int
	SessionGID int
	// WritableRoots are the only directories a session may use as its working
	// directory, and the only ones bind-mounted read-write. The session's own
	// /tmp is always writable and needs no entry here.
	WritableRoots []string
	// ReadOnlyPaths are bind-mounted read-only into every session.
	ReadOnlyPaths []string
	// ToolboxRoot holds the published tools (bin/) and the install staging
	// prefixes (staging/). It lives under /state, so a published tool survives
	// sandbox recreation.
	ToolboxRoot string
	// Gateway is the host:port a session may reach, as seen from the root
	// namespace (the recording gateway normally binds loopback).
	Gateway string
	// Resolver is the upstream resolver the session relay forwards to.
	Resolver string
	// MemoryMax and PidsMax bound a session's cgroup; CPUMax is a cpu.max
	// quota (empty means unlimited).
	MemoryMax int64
	PidsMax   int64
	CPUMax    string
	// Self is the binary re-executed for the session child.
	Self string
	// Setpriv is the privilege-dropping binary inside the session root.
	Setpriv string
	// Logf receives supervisor diagnostics; nil discards them.
	Logf func(format string, args ...any)
}

// DefaultConfig returns the guest deployment configuration.
func DefaultConfig() Config {
	return Config{
		Socket:        SocketPath(),
		StateDir:      "/run/execbox",
		CgroupRoot:    "/sys/fs/cgroup/execbox",
		ControllerUID: 0,
		SessionUID:    1000,
		SessionGID:    1000,
		WritableRoots: []string{"/state/m1nervac0nsole/tasks"},
		ReadOnlyPaths: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/dist", "/sys"},
		ToolboxRoot:   ToolboxRoot(),
		Gateway:       "127.0.0.1:8788",
		Resolver:      guestResolver(),
		MemoryMax:     2 << 30,
		PidsMax:       1024,
	}
}

// guestResolver reads the guest's first nameserver, so the session relay
// forwards to whatever the deployment configured rather than a constant.
func guestResolver() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return net.JoinHostPort(fields[1], "53")
		}
	}
	return ""
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Socket == "" {
		c.Socket = d.Socket
	}
	if c.StateDir == "" {
		c.StateDir = d.StateDir
	}
	if c.CgroupRoot == "" {
		c.CgroupRoot = d.CgroupRoot
	}
	if c.SessionUID == 0 {
		c.SessionUID = d.SessionUID
	}
	if c.SessionGID == 0 {
		c.SessionGID = d.SessionGID
	}
	if len(c.WritableRoots) == 0 {
		c.WritableRoots = d.WritableRoots
	}
	if len(c.ReadOnlyPaths) == 0 {
		c.ReadOnlyPaths = d.ReadOnlyPaths
	}
	if c.ToolboxRoot == "" {
		c.ToolboxRoot = d.ToolboxRoot
	}
	if c.Gateway == "" {
		c.Gateway = d.Gateway
	}
	if c.Resolver == "" {
		c.Resolver = d.Resolver
	}
	if c.MemoryMax == 0 {
		c.MemoryMax = d.MemoryMax
	}
	if c.PidsMax == 0 {
		c.PidsMax = d.PidsMax
	}
	if c.Self == "" {
		if exe, err := os.Executable(); err == nil {
			c.Self = exe
		}
	}
	if c.Setpriv == "" {
		if p, err := exec.LookPath("setpriv"); err == nil {
			c.Setpriv = p
		}
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return c
}

// BinDir is the persistent directory published tools live in. Every session
// sees it read-only on PATH.
func (c Config) BinDir() string { return filepath.Join(c.ToolboxRoot, "bin") }

// StagingRoot holds one writable prefix per install session.
func (c Config) StagingRoot() string { return filepath.Join(c.ToolboxRoot, "staging") }

// Supervisor owns every privileged operation of the execution boundary.
type Supervisor struct {
	cfg    Config
	report Report

	mu       sync.Mutex
	ln       *net.UnixListener
	sessions map[string]*session
	wg       sync.WaitGroup
	closed   chan struct{}
}

// NewSupervisor prepares the supervisor: it sweeps state left by a previous
// process, then verifies its capabilities with a real self-test session.
func NewSupervisor(cfg Config) (*Supervisor, error) {
	cfg = cfg.withDefaults()
	s := &Supervisor{cfg: cfg, sessions: map[string]*session{}, closed: make(chan struct{})}
	if err := s.requirePlatform(); err != nil {
		return nil, err
	}
	// The toolbox directories are the supervisor's: bin/ is mounted read-only
	// into every session, staging/ holds the writable prefixes install sessions
	// publish from. Both live under /state, which survives sandbox recreation.
	if err := os.MkdirAll(s.cfg.BinDir(), 0o755); err != nil {
		return nil, fmt.Errorf("execbox: toolbox bin: %w", err)
	}
	if err := os.MkdirAll(s.cfg.StagingRoot(), 0o700); err != nil {
		return nil, fmt.Errorf("execbox: toolbox staging: %w", err)
	}
	s.sweepStaging()
	s.cfg.ReadOnlyPaths = append(s.cfg.ReadOnlyPaths, s.cfg.BinDir())
	// A configured runtime path that does not exist on this host is skipped
	// rather than failing every session: the guest and a test host do not carry
	// the same trees.
	present := make([]string, 0, len(s.cfg.ReadOnlyPaths))
	for _, p := range s.cfg.ReadOnlyPaths {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		} else {
			s.cfg.Logf("[execbox] runtime path %s is absent; not mounted", p)
		}
	}
	s.cfg.ReadOnlyPaths = present
	s.sweep()
	s.report = s.probe()
	if !s.report.OK() {
		cfg.Logf("[execbox] capability self-test failed: %s", s.report.String())
	}
	return s, nil
}

// Report returns the verified capability report.
func (s *Supervisor) Report() Report { return s.report }

// requirePlatform refuses to run where the mechanism cannot exist at all.
func (s *Supervisor) requirePlatform() error {
	if runtime.GOOS != "linux" {
		return &CapabilityError{Missing: []string{"linux"}, Detail: "the execution boundary needs Linux namespaces"}
	}
	if os.Geteuid() != 0 {
		return &CapabilityError{Missing: []string{"root"}, Detail: "the supervisor must run as root"}
	}
	var missing []string
	for _, bin := range []string{"ip", "iptables"} {
		if _, err := exec.LookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	if s.cfg.Setpriv == "" {
		missing = append(missing, "setpriv")
	}
	if s.cfg.Self == "" {
		missing = append(missing, "self")
	}
	if s.cfg.Resolver == "" {
		missing = append(missing, "resolver")
	}
	if _, _, err := net.SplitHostPort(s.cfg.Gateway); err != nil {
		missing = append(missing, "gateway")
	}
	if _, _, err := net.SplitHostPort(s.cfg.Resolver); err != nil {
		missing = append(missing, "resolver")
	}
	if len(missing) > 0 {
		return &CapabilityError{Missing: missing, Detail: "required binaries or configuration are absent"}
	}
	return nil
}

// Serve accepts session requests until ctx is cancelled.
func (s *Supervisor) Serve(ctx context.Context) error {
	dir := filepath.Dir(s.cfg.Socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("execbox: socket dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("execbox: socket dir mode: %w", err)
	}
	_ = os.Remove(s.cfg.Socket)
	addr := &net.UnixAddr{Name: s.cfg.Socket, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("execbox: listen %s: %w", s.cfg.Socket, err)
	}
	if err := os.Chmod(s.cfg.Socket, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("execbox: socket mode: %w", err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.cfg.Logf("[execbox] supervisor listening on %s; %s", s.cfg.Socket, s.report.String())

	go func() {
		select {
		case <-ctx.Done():
		case <-s.closed:
		}
		ln.Close()
	}()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("execbox: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Close stops the listener and tears down every live session.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.ln != nil {
		s.ln.Close()
	}
	sessions := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	for _, sess := range sessions {
		sess.kill()
	}
	s.wg.Wait()
	return nil
}

// handle serves one client connection.
func (s *Supervisor) handle(conn *net.UnixConn) {
	defer conn.Close()
	if err := s.checkPeer(conn); err != nil {
		_ = newWireConn(conn).write(frame{Type: frameError, Message: err.Error()})
		return
	}
	w := newWireConn(conn)
	var req request
	fds, err := w.readFirst(&req)
	if err != nil {
		return
	}
	extra := make([]*os.File, 0, len(fds))
	for _, fd := range fds {
		extra = append(extra, os.NewFile(uintptr(fd), "extra"))
	}
	defer func() {
		for _, f := range extra {
			f.Close()
		}
	}()
	switch req.Op {
	case opCapabilities:
		rep := s.report
		_ = w.write(frame{Type: frameReport, Report: &rep})
	case opStart:
		s.startSession(w, req, extra)
	case opPublish:
		s.publish(w, req)
	default:
		_ = w.write(frame{Type: frameError, Message: "unknown op " + req.Op})
	}
}

// checkPeer refuses a connection that is not the trusted controller in the root
// namespaces: a session process must never be able to ask for another session.
func (s *Supervisor) checkPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("execbox: peer: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("execbox: peer: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("execbox: peer credentials: %w", credErr)
	}
	if int(cred.Uid) != s.cfg.ControllerUID {
		return fmt.Errorf("execbox: peer uid %d is not the controller uid %d", cred.Uid, s.cfg.ControllerUID)
	}
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("execbox: own netns: %w", err)
	}
	peer, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cred.Pid))
	if err != nil {
		return fmt.Errorf("execbox: peer netns: %w", err)
	}
	if peer != own {
		return fmt.Errorf("execbox: peer pid %d is inside a session network namespace", cred.Pid)
	}
	return nil
}

// startSession validates the request, runs the session and reports its exit.
func (s *Supervisor) startSession(w *wireConn, req request, extra []*os.File) {
	// A missing capability is a refusal, never a fallback to unisolated
	// execution. The report is verified at startup, so this is the same answer
	// the client sees from Capabilities.
	if !s.report.OK() {
		_ = w.write(errorFrame(&CapabilityError{Missing: s.report.Missing, Detail: s.report.Detail}))
		return
	}
	sess, err := s.newSession(req)
	if err != nil {
		_ = w.write(errorFrame(err))
		return
	}
	defer sess.teardown()
	if err := sess.start(extra); err != nil {
		_ = w.write(errorFrame(err))
		return
	}
	if err := w.write(frame{Type: frameReady, Handle: sess.handle}); err != nil {
		return
	}
	code := sess.pump(w)
	// Tear down before reporting the exit, so a caller that sees the exit code
	// can rely on the session's namespaces, rules and cgroup being gone. The
	// teardown also closes stdin, which makes the accepted byte count final.
	sess.teardown()
	accepted := sess.stdinAccepted.Load()
	s.cfg.Logf("[execbox] session %s (task %d, %s) exited %d", sess.handle, sess.sess.TaskID, sess.sess.Purpose, code)
	_ = w.write(frame{Type: frameExit, Code: code, StdinAccepted: &accepted})
}

func errorFrame(err error) frame {
	var capErr *CapabilityError
	if errors.As(err, &capErr) {
		return frame{Type: frameError, Message: capErr.Error(), Missing: capErr.Missing, Detail: capErr.Detail}
	}
	return frame{Type: frameError, Message: err.Error()}
}

// privateTmp is the scratch directory every session gets as its own tmpfs. A
// caller that asks for it is served the private mount the child builds, never
// the host's /tmp, which is not a writable root and is shared with every
// process on the machine.
const privateTmp = "/tmp"

// newSession validates the request against the supervisor's policy. The
// capability check lives in startSession so the startup self-test, which runs
// before the report exists, can use this path.
func (s *Supervisor) newSession(req request) (*session, error) {
	sess := sessionFromWire(req.Session)
	if strings.TrimSpace(sess.ID) == "" || !sess.Purpose.Valid() {
		return nil, fmt.Errorf("execbox: session identity is required (id=%q purpose=%q)", sess.ID, sess.Purpose)
	}
	if req.Spec == nil || len(req.Spec.Argv) == 0 {
		return nil, fmt.Errorf("execbox: a program is required")
	}
	spec := *req.Spec
	if spec.ExtraFiles < 0 || spec.ExtraFiles > 8 {
		return nil, fmt.Errorf("execbox: extra files out of range")
	}
	dir := filepath.Clean(spec.Dir)
	var writable []string
	var err error
	if dir != privateTmp {
		if dir, err = s.sessionDir(spec.Dir); err != nil {
			return nil, err
		}
		writable = append(writable, dir)
	}
	spec.Dir = dir
	for _, w := range spec.Writable {
		// The private tmpfs is already mounted read-write and needs no bind.
		if filepath.Clean(w) == privateTmp {
			continue
		}
		resolved, err := s.sessionDir(w)
		if err != nil {
			return nil, err
		}
		if resolved != dir {
			writable = append(writable, resolved)
		}
	}
	spec.Writable = writable
	// An install session stages what it will publish in a writable prefix of its
	// own under the toolbox root. Every other purpose sees that root read-only
	// and gets no staging path at all.
	staging := ""
	if sess.Purpose == netpolicy.PurposeInstall {
		staging, err = s.stagingDir(sess.ID)
		if err != nil {
			return nil, err
		}
		if err := prepareStaging(staging); err != nil {
			return nil, err
		}
		spec.Writable = append(spec.Writable, staging)
	}
	if spec.Rows <= 0 {
		spec.Rows = 24
	}
	if spec.Cols <= 0 {
		spec.Cols = 80
	}
	for _, kv := range spec.Env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.ContainsAny(k, " \t\x00") {
			return nil, fmt.Errorf("execbox: malformed environment entry %q", kv)
		}
	}
	handle, err := newHandle()
	if err != nil {
		return nil, err
	}
	rootIP, sessIP, err := randomSubnet()
	if err != nil {
		return nil, err
	}
	return &session{
		sup:     s,
		cfg:     s.cfg,
		handle:  handle,
		spec:    spec,
		sess:    sess,
		staging: staging,
		dir:     filepath.Join(s.cfg.StateDir, handle),
		cgroup:  filepath.Join(s.cfg.CgroupRoot, handle),
		chain:   "EB-" + handle,
		netns:   netnsName(handle),
		rootIP:  rootIP,
		sessIP:  sessIP,
	}, nil
}

// sessionDir validates the working directory: absolute, existing, and inside a
// configured writable root after symlink resolution.
func (s *Supervisor) sessionDir(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("execbox: a working directory is required")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("execbox: working directory %q is not absolute", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("execbox: working directory %q: %w", dir, err)
	}
	for _, root := range s.cfg.WritableRoots {
		r, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if resolved == r || strings.HasPrefix(resolved, r+string(filepath.Separator)) {
			fi, err := os.Stat(resolved)
			if err != nil {
				return "", fmt.Errorf("execbox: working directory %q: %w", dir, err)
			}
			if !fi.IsDir() {
				return "", fmt.Errorf("execbox: working directory %q is not a directory", dir)
			}
			return resolved, nil
		}
	}
	return "", fmt.Errorf("execbox: working directory %q is outside the session workspace roots", dir)
}

// gatewayPort returns the port of a host:port gateway address.
func gatewayPort(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(port)
}

// newHandle generates a session handle: the name shared by its state
// directory, cgroup, network namespace, veth pair and firewall chain.
func newHandle() (string, error) {
	b := make([]byte, 6)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// session is one live isolated process.
type session struct {
	sup    *Supervisor
	cfg    Config
	handle string
	spec   Spec
	sess   netpolicy.Session
	// staging is the writable prefix of an install session, empty for every
	// other purpose. It outlives the session so the supervisor can publish from
	// it.
	staging string
	dir     string
	cgroup  string
	chain   string
	netns   string

	vethOuter    string
	vethInner    string
	rootIP       string
	sessIP       string
	stopResolver func()

	proc   *exec.Cmd
	readyW *os.File
	stdinR *os.File
	stdinW *os.File
	// stdinMu guards stdinW: the frame reader writes and closes it while the
	// request path may close the session's streams.
	stdinMu   sync.Mutex
	stdoutR   *os.File
	stdoutW   *os.File
	stderrR   *os.File
	stderrW   *os.File
	ttyMaster *os.File
	ttySlave  *os.File
	// stdinAccepted is the number of bytes the program's stdin pipe (or its
	// terminal) accepted, and stdinWrites tracks a write already inside it so
	// the count is final before the exit frame reports it.
	stdinAccepted atomic.Int64
	stdinWrites   sync.WaitGroup

	waitOnce sync.Once
	exitCode int
	killOnce sync.Once
	// teardownOnce makes teardown safe to call from the request path and from
	// the deferred safety net.
	teardownOnce sync.Once
}

// start creates the cgroup, spawns the child, configures the network and
// releases the child to build its filesystem.
func (s *session) start(extra []*os.File) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("execbox: session dir: %w", err)
	}
	if err := s.setupCgroup(); err != nil {
		return err
	}
	if err := s.chownWorkspace(); err != nil {
		return err
	}
	cfgPath := filepath.Join(s.dir, "child.json")

	readyR, readyW, err := os.Pipe()
	if err != nil {
		return err
	}
	s.readyW = readyW
	if err := s.openStreams(); err != nil {
		readyR.Close()
		readyW.Close()
		return err
	}

	cmd := exec.Command(s.cfg.Self, "execbox", ChildMode, cfgPath)
	cmd.Stdin = s.childStdin()
	cmd.Stdout = s.childStdout()
	cmd.Stderr = s.childStderr()
	cmd.ExtraFiles = append([]*os.File{readyR}, extra...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// The child is born in the session's namespaces; the network namespace
		// is empty until the supervisor moves the veth into it below.
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		// A supervisor crash must not leave a session running: the child dies
		// with it, which takes the pid and network namespaces with it.
		Pdeathsig: syscall.SIGKILL,
		Setsid:    true,
	}
	if err := cmd.Start(); err != nil {
		readyR.Close()
		readyW.Close()
		s.closeStreams()
		return fmt.Errorf("execbox: start child: %w", err)
	}
	s.proc = cmd
	readyR.Close()
	s.closeParentEnds()

	if err := linkSessionNetns(s.netns, cmd.Process.Pid); err != nil {
		return err
	}
	if err := s.setupNetwork(); err != nil {
		return err
	}
	// The child reads its configuration only after the ready byte, so the
	// resolver address it names is the one the veth actually got.
	childCfg := childConfig{
		Handle:     s.handle,
		Argv:       s.spec.Argv,
		Dir:        s.spec.Dir,
		Env:        s.spec.Env,
		TTY:        s.spec.TTY,
		ExtraFiles: s.spec.ExtraFiles,
		UID:        s.cfg.SessionUID,
		GID:        s.cfg.SessionGID,
		NewRoot:    filepath.Join(s.dir, "root"),
		ReadOnly:   s.cfg.ReadOnlyPaths,
		Writable:   s.spec.Writable,
		Prefix:     s.staging,
		BinDir:     s.cfg.BinDir(),
		ResolvConf: "nameserver " + s.rootIP + "\n",
		Setpriv:    s.cfg.Setpriv,
		Hostname:   "execbox-" + s.handle,
		Cgroup:     s.cgroup,
	}
	if port, err := gatewayPort(s.cfg.Gateway); err == nil {
		childCfg.GatewayPort = port
		childCfg.GatewayAddr = net.JoinHostPort(s.rootIP, strconv.Itoa(port))
	}
	cfgBytes, err := json.Marshal(childCfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		return fmt.Errorf("execbox: child config: %w", err)
	}
	if _, err := s.readyW.Write([]byte{1}); err != nil {
		return fmt.Errorf("execbox: release child: %w", err)
	}
	s.readyW.Close()
	s.readyW = nil
	s.sup.mu.Lock()
	s.sup.sessions[s.handle] = s
	s.sup.mu.Unlock()
	return nil
}

func (s *session) openStreams() error {
	if s.spec.TTY {
		master, slave, err := pty.Open()
		if err != nil {
			return fmt.Errorf("execbox: pty: %w", err)
		}
		if err := pty.Setsize(master, &pty.Winsize{Rows: uint16(s.spec.Rows), Cols: uint16(s.spec.Cols)}); err != nil {
			master.Close()
			slave.Close()
			return fmt.Errorf("execbox: pty size: %w", err)
		}
		s.ttyMaster = master
		s.ttySlave = slave
		return nil
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return err
	}
	s.stdinW, s.stdoutR = inW, outR
	s.stdinR, s.stdoutW = inR, outW
	if !s.spec.MergeStderr {
		errR, errW, err := os.Pipe()
		if err != nil {
			s.closeStreams()
			return err
		}
		s.stderrR, s.stderrW = errR, errW
	}
	return nil
}

func (s *session) childStdin() *os.File {
	if s.ttySlave != nil {
		return s.ttySlave
	}
	return s.stdinR
}

func (s *session) childStdout() *os.File {
	if s.ttySlave != nil {
		return s.ttySlave
	}
	return s.stdoutW
}

func (s *session) childStderr() *os.File {
	if s.ttySlave != nil {
		return s.ttySlave
	}
	if s.stderrW != nil {
		return s.stderrW
	}
	return s.stdoutW
}

// closeParentEnds drops the descriptors the child owns, so the supervisor's
// reads see EOF when the session ends.
func (s *session) closeParentEnds() {
	if s.ttySlave != nil {
		s.ttySlave.Close()
		s.ttySlave = nil
	}
	for _, f := range []**os.File{&s.stdinR, &s.stdoutW, &s.stderrW} {
		if *f != nil {
			(*f).Close()
			*f = nil
		}
	}
}

func (s *session) closeStreams() {
	s.closeParentEnds()
	s.closeStdin()
	for _, f := range []**os.File{&s.stdoutR, &s.stderrR, &s.ttyMaster} {
		if *f != nil {
			(*f).Close()
			*f = nil
		}
	}
}

// pump relays the session's streams to the client until the program exits.
func (s *session) pump(w *wireConn) int {
	streamsDone := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		copyStream := func(r io.Reader, typ string) {
			defer wg.Done()
			buf := make([]byte, 32<<10)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					if werr := w.write(frame{Type: typ, Data: buf[:n]}); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}
		if s.ttyMaster != nil {
			wg.Add(1)
			go copyStream(s.ttyMaster, frameStdout)
		} else {
			if s.stdoutR != nil {
				wg.Add(1)
				go copyStream(s.stdoutR, frameStdout)
			}
			if s.stderrR != nil {
				wg.Add(1)
				go copyStream(s.stderrR, frameStderr)
			}
		}
		wg.Wait()
		close(streamsDone)
	}()

	go func() {
		for {
			var f frame
			if err := w.read(&f); err != nil {
				s.kill()
				return
			}
			switch f.Type {
			case frameStdin:
				s.writeStdin(f.Data)
			case frameStdinEOF:
				s.closeStdin()
			case frameResize:
				if s.ttyMaster != nil && f.Rows > 0 && f.Cols > 0 {
					_ = pty.Setsize(s.ttyMaster, &pty.Winsize{Rows: uint16(f.Rows), Cols: uint16(f.Cols)})
				}
			case frameClose:
				s.kill()
				return
			}
		}
	}()

	code := s.wait()
	select {
	case <-streamsDone:
	case <-time.After(2 * time.Second):
		s.closeStreams()
		<-streamsDone
	}
	return code
}

// writeStdin sends input to the program: the terminal for a PTY session, the
// stdin pipe otherwise. The descriptor is read under the lock and written
// outside it, because a write to a pipe whose reader stopped blocks and teardown
// must not wait behind it. The accepted byte count is what the pipe or terminal
// took, which is not the same as what the program read.
func (s *session) writeStdin(data []byte) {
	s.stdinMu.Lock()
	f := s.stdinW
	if s.ttyMaster != nil {
		f = s.ttyMaster
	}
	if f != nil {
		s.stdinWrites.Add(1)
	}
	s.stdinMu.Unlock()
	if f == nil {
		return
	}
	n, _ := f.Write(data)
	s.stdinAccepted.Add(int64(n))
	s.stdinWrites.Done()
}

// closeStdin gives the program EOF on stdin by closing the write end of its
// pipe, the way a shell sees its input end. The session, its streams and its
// process tree stay up, so the program can finish and report its own exit code.
// A PTY has no separate stdin to close, so it is a no-op there and the client
// refuses the request instead.
func (s *session) closeStdin() {
	s.stdinMu.Lock()
	f := s.stdinW
	s.stdinW = nil
	s.stdinMu.Unlock()
	if f != nil {
		// Closing unblocks a write already inside the pipe, so the wait below
		// terminates and the accepted count is final.
		_ = f.Close()
	}
	s.stdinWrites.Wait()
}

// wait returns the program's exit code, waiting for the child once.
func (s *session) wait() int {
	s.waitOnce.Do(func() {
		if s.proc == nil {
			s.exitCode = -1
			return
		}
		err := s.proc.Wait()
		var ee *exec.ExitError
		switch {
		case err == nil:
			s.exitCode = 0
		case errors.As(err, &ee):
			s.exitCode = ee.ExitCode()
		default:
			s.exitCode = -1
		}
	})
	return s.exitCode
}

// kill terminates the session's whole process tree through the cgroup, which
// reaches grandchildren the supervisor cannot signal directly.
func (s *session) kill() {
	s.killOnce.Do(func() {
		if s.cgroup != "" {
			_ = os.WriteFile(filepath.Join(s.cgroup, "cgroup.kill"), []byte("1"), 0o644)
		}
		if s.proc != nil && s.proc.Process != nil {
			_ = s.proc.Process.Kill()
		}
	})
}

// teardown removes everything the session created. It runs on exit,
// cancellation, crash of the program and supervisor shutdown, and tolerates
// resources a crash already removed. It is idempotent: the request path calls
// it before reporting the exit code, and the deferred call is the safety net.
func (s *session) teardown() {
	s.teardownOnce.Do(s.teardownResources)
}

func (s *session) teardownResources() {
	s.kill()
	_ = s.wait()
	s.closeStreams()
	if s.readyW != nil {
		s.readyW.Close()
		s.readyW = nil
	}
	s.sup.mu.Lock()
	delete(s.sup.sessions, s.handle)
	s.sup.mu.Unlock()
	s.removeCgroup()
	s.removeRules()
	if s.vethOuter != "" {
		_ = exec.Command("ip", "link", "del", s.vethOuter).Run()
	}
	unlinkSessionNetns(s.netns)
	if s.stopResolver != nil {
		s.stopResolver()
		s.stopResolver = nil
	}
	_ = os.RemoveAll(s.dir)
}

// chownWorkspace makes the writable paths usable by the session uid. The
// backend runs as root, so a workspace it created is root-owned; without this
// the session could read it but not write it. Every start re-walks: the
// backend's in-process file tools write root-owned files into an owned
// workspace between sessions, and a skip would leave them read-only to the
// session.
func (s *session) chownWorkspace() error {
	uid, gid := s.cfg.SessionUID, s.cfg.SessionGID
	for _, root := range s.spec.Writable {
		err := filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			_ = os.Lchown(path, uid, gid)
			return nil
		})
		if err != nil {
			return fmt.Errorf("execbox: workspace ownership: %w", err)
		}
	}
	return nil
}

// --- cgroup v2 ---

func (s *session) setupCgroup() error {
	if err := os.MkdirAll(s.cfg.CgroupRoot, 0o755); err != nil {
		return fmt.Errorf("cgroup: %w", err)
	}
	enableControllers("/sys/fs/cgroup")
	enableControllers(s.cfg.CgroupRoot)
	if err := os.Mkdir(s.cgroup, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("cgroup: %w", err)
	}
	limits := map[string]string{
		"memory.max": strconv.FormatInt(s.cfg.MemoryMax, 10),
		"pids.max":   strconv.FormatInt(s.cfg.PidsMax, 10),
	}
	if s.cfg.CPUMax != "" {
		limits["cpu.max"] = s.cfg.CPUMax
	}
	for name, value := range limits {
		if err := os.WriteFile(filepath.Join(s.cgroup, name), []byte(value), 0o644); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("cgroup: %s unavailable: %w", name, err)
			}
			return fmt.Errorf("cgroup: %s: %w", name, err)
		}
	}
	return nil
}

// enableControllers turns on the controllers a session limit needs, at the root
// and at the supervisor's own subtree. Both writes are idempotent.
func enableControllers(dir string) {
	avail, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return
	}
	have := string(avail)
	want := []string{"memory", "pids", "cpu"}
	var add []string
	for _, c := range want {
		if !strings.Contains(have, c) {
			continue
		}
		add = append(add, "+"+c)
	}
	if len(add) == 0 {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(strings.Join(add, " ")), 0o644)
}

func (s *session) removeCgroup() {
	if s.cgroup == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(s.cgroup, "cgroup.kill"), []byte("1"), 0o644)
	for range 50 {
		if err := os.Remove(s.cgroup); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --- startup sweep ---

// sweep removes state a previous supervisor left behind after a crash. The
// state directory is the record of what was created, so the sweep is driven by
// it: a handle with no directory never created anything, and a handle with a
// directory may have left a cgroup, a network namespace, a veth pair, firewall
// rules and scratch files. It runs before the capability self-test, so a crashed
// run cannot make the next one look healthy.
func (s *Supervisor) sweep() {
	entries, err := os.ReadDir(s.cfg.StateDir)
	if err != nil {
		return
	}
	cleaned := 0
	for _, e := range entries {
		handle := e.Name()
		if len(handle) != 12 {
			continue
		}
		s.cleanHandle(handle)
		cleaned++
	}
	if cleaned > 0 {
		s.cfg.Logf("[execbox] swept %d stale session(s)", cleaned)
	}
}

// cleanHandle removes everything one session handle may have left behind.
func (s *Supervisor) cleanHandle(handle string) {
	cgroup := filepath.Join(s.cfg.CgroupRoot, handle)
	_ = os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0o644)
	for range 25 {
		if os.Remove(cgroup) == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	outer, _ := vethNames(handle)
	_ = exec.Command("ip", "link", "del", outer).Run()
	unlinkSessionNetns(netnsName(handle))
	removeChain("EB-" + handle)
	_ = os.RemoveAll(filepath.Join(s.cfg.StateDir, handle))
}

// removeChain deletes one session's firewall chain, the hooks that jump to it
// and the NAT rule for its veth.
func removeChain(chain string) {
	handle := strings.TrimPrefix(chain, "EB-")
	outer, _ := vethNames(handle)
	for _, hook := range []string{"INPUT", "FORWARD"} {
		rules, err := exec.Command("iptables", "-S", hook).Output()
		if err != nil {
			continue
		}
		for _, rule := range strings.Split(string(rules), "\n") {
			if !strings.Contains(rule, "-i "+outer) {
				continue
			}
			args := strings.Fields(rule)
			if len(args) == 0 || args[0] != "-A" {
				continue
			}
			args[0] = "-D"
			_ = exec.Command("iptables", args...).Run()
		}
	}
	nat, err := exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").Output()
	if err == nil {
		for _, rule := range strings.Split(string(nat), "\n") {
			if !strings.Contains(rule, "-i "+outer) {
				continue
			}
			args := strings.Fields(rule)
			if len(args) == 0 || args[0] != "-A" {
				continue
			}
			args[0] = "-D"
			_ = exec.Command("iptables", append([]string{"-t", "nat"}, args...)...).Run()
		}
	}
	_ = exec.Command("iptables", "-F", chain).Run()
	_ = exec.Command("iptables", "-X", chain).Run()
}

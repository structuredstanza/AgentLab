package execbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// childConfig is what the supervisor hands the child process (stage 1) that
// builds the session's namespaces. It is written to a root-only file inside the
// supervisor's state directory and removed as soon as it is read, so a session
// process never sees it.
type childConfig struct {
	Handle     string   `json:"handle"`
	Argv       []string `json:"argv"`
	Dir        string   `json:"dir"`
	Env        []string `json:"env"`
	TTY        bool     `json:"tty"`
	ExtraFiles int      `json:"extra_files"`
	UID        int      `json:"uid"`
	GID        int      `json:"gid"`
	NewRoot    string   `json:"new_root"`
	ReadOnly   []string `json:"read_only"`
	Writable   []string `json:"writable"`
	// PublicCA is a supervisor-made copy of the recorder's public CA certificate,
	// bound read-only at PublicCAAt. Only that file is mounted, never its
	// directory, which also holds the signing key. Empty means no CA yet.
	PublicCA   string `json:"public_ca,omitempty"`
	PublicCAAt string `json:"public_ca_at,omitempty"`
	// Prefix is the writable staging prefix of an install session, empty for
	// every other purpose. BinDir is the persistent published-tool directory,
	// which every session sees read-only on PATH.
	Prefix     string `json:"prefix,omitempty"`
	BinDir     string `json:"bin_dir,omitempty"`
	ResolvConf string `json:"resolv_conf"`
	Setpriv    string `json:"setpriv"`
	Hostname   string `json:"hostname"`
	Cgroup     string `json:"cgroup"`
	// GatewayPort and GatewayAddr are the session's loopback port and the
	// gateway's address as seen from the session. The child relays the port so
	// existing proxy configuration (127.0.0.1:<port>) keeps working inside the
	// boundary, where loopback is the session's own.
	GatewayPort int    `json:"gateway_port"`
	GatewayAddr string `json:"gateway_addr"`
	// NetRaw keeps CAP_NET_RAW (ambient and bounding) on the program: a session
	// with a direct lane runs raw-socket tools. Everything else keeps none.
	NetRaw bool `json:"net_raw,omitempty"`
}

// joinCgroup puts this process (and therefore everything it starts) into the
// session's cgroup. It must run before the mount namespace is replaced, because
// the cgroup filesystem is not mounted inside the session.
func joinCgroup(path string) error {
	if path == "" {
		return fmt.Errorf("cgroup: no session cgroup configured")
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte("0"), 0o644); err != nil {
		return fmt.Errorf("cgroup join: %w", err)
	}
	return nil
}

// runChild is stage 1: it is already in the session's network, mount, PID, IPC
// and UTS namespaces (created by clone), waits for the supervisor to finish the
// network setup, builds the session's filesystem, and then starts the program
// as an unprivileged uid with no capabilities.
func runChild(configPath string) int {
	// fd 3 is the ready pipe: the supervisor writes one byte once the veth,
	// firewall rules and resolver relay exist, and only then writes the
	// configuration. EOF means it failed.
	if err := waitReady(3); err != nil {
		fmt.Fprintf(os.Stderr, "execbox child: %v\n", err)
		return childFailure
	}
	cfg, err := readChildConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execbox child: %v\n", err)
		return childFailure
	}
	// Joining the session cgroup before anything else is what makes the limits
	// apply and lets teardown kill the whole tree, including grandchildren the
	// supervisor cannot signal.
	if err := joinCgroup(cfg.Cgroup); err != nil {
		fmt.Fprintf(os.Stderr, "execbox child: %v\n", err)
		return childFailure
	}
	if err := setupSessionRoot(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "execbox child: %v\n", err)
		return childFailure
	}
	// Tools are configured with a loopback proxy address, and inside the
	// session loopback is the session's own. The relay makes that address reach
	// the gateway without any tool needing to know the session's topology.
	if cfg.GatewayPort > 0 && cfg.GatewayAddr != "" {
		if err := startGatewayRelay(cfg.GatewayPort, cfg.GatewayAddr); err != nil {
			fmt.Fprintf(os.Stderr, "execbox child: gateway relay: %v\n", err)
			return childFailure
		}
	}
	return runProgram(cfg)
}

// startGatewayRelay forwards the session's loopback gateway port to the
// gateway's session-visible address. It is a plain TCP forwarder with no
// privilege: the same connection a tool could open itself, on an address the
// packet rules already admit.
func startGatewayRelay(port int, target string) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				up, err := net.DialTimeout("tcp", target, 10*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, conn) }()
				_, _ = io.Copy(conn, up)
			}()
		}
	}()
	return nil
}

// childFailure is the exit code stage 1 uses when it could not build the
// session. It is distinct from any program exit code a tool is likely to
// produce, and the reason is on the session's stderr.
const childFailure = 125

// ChildMode is the hidden subcommand the supervisor re-executes for stage 1 of
// a session. The entry point dispatches it, and a test binary's TestMain must
// dispatch it too, because the supervisor re-executes os.Executable().
const ChildMode = "__child"

// RunChild runs stage 1 of a session: it waits for the supervisor's network
// setup, builds the session filesystem and starts the program. args is the
// subcommand's arguments (one config path).
func RunChild(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "execbox child: expected one config path")
		return childFailure
	}
	return runChild(args[0])
}

func readChildConfig(path string) (*childConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	_ = os.Remove(path)
	var cfg childConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &cfg, nil
}

func waitReady(fd int) error {
	var b [1]byte
	n, err := syscall.Read(fd, b[:])
	if err != nil {
		return fmt.Errorf("wait for supervisor: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("wait for supervisor: %w", ErrUnavailable)
	}
	_ = syscall.Close(fd)
	return nil
}

// setupSessionRoot builds the session's mount namespace and pivots into it.
func setupSessionRoot(cfg *childConfig) error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("mount namespace: %w", err)
	}
	root := cfg.NewRoot
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("new root: %w", err)
	}
	if err := syscall.Mount("tmpfs", root, "tmpfs", 0, "mode=0755,size=32m"); err != nil {
		return fmt.Errorf("new root tmpfs: %w", err)
	}
	for _, d := range []string{"/tmp", "/run", "/dev", "/dev/pts", "/dev/shm", "/proc"} {
		if err := os.MkdirAll(root+d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// The private mounts come before the binds: a tmpfs on /tmp must not hide a
	// workspace that lives under /tmp.
	if err := syscall.Mount("tmpfs", root+"/tmp", "tmpfs", 0, "mode=1777"); err != nil {
		return fmt.Errorf("/tmp: %w", err)
	}
	if err := syscall.Mount("tmpfs", root+"/run", "tmpfs", 0, "mode=0755"); err != nil {
		return fmt.Errorf("/run: %w", err)
	}
	if err := syscall.Mount("tmpfs", root+"/dev", "tmpfs", 0, "mode=0755"); err != nil {
		return fmt.Errorf("/dev: %w", err)
	}
	// The /dev tmpfs hides anything created before it, so its own mountpoints
	// are created after it.
	for _, d := range []string{"/dev/pts", "/dev/shm"} {
		if err := os.MkdirAll(root+d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	if err := syscall.Mount("devpts", root+"/dev/pts", "devpts", 0, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("/dev/pts: %w", err)
	}
	if err := syscall.Mount("tmpfs", root+"/dev/shm", "tmpfs", 0, "mode=1777"); err != nil {
		return fmt.Errorf("/dev/shm: %w", err)
	}
	if err := syscall.Mount("proc", root+"/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	for _, p := range cfg.ReadOnly {
		if err := bindPath(p, root+p, true); err != nil {
			return fmt.Errorf("read-only %s: %w", p, err)
		}
	}
	if cfg.PublicCA != "" {
		if err := bindPath(cfg.PublicCA, root+cfg.PublicCAAt, true); err != nil {
			return fmt.Errorf("read-only %s: %w", cfg.PublicCAAt, err)
		}
	}
	for _, p := range cfg.Writable {
		if err := bindPath(p, root+p, false); err != nil {
			return fmt.Errorf("writable %s: %w", p, err)
		}
	}
	for _, n := range []struct {
		name string
		mode uint32
		dev  int
	}{
		{"null", 0o666, 0x0103}, {"zero", 0o666, 0x0105}, {"full", 0o666, 0x0107},
		{"random", 0o666, 0x0108}, {"urandom", 0o666, 0x0109}, {"tty", 0o666, 0x0500},
	} {
		path := root + "/dev/" + n.name
		if err := syscall.Mknod(path, syscall.S_IFCHR|n.mode, n.dev); err != nil {
			return fmt.Errorf("/dev/%s: %w", n.name, err)
		}
		// mknod is subject to the umask; the session uid must be able to use
		// these nodes, so the mode is set explicitly.
		if err := os.Chmod(path, os.FileMode(n.mode)); err != nil {
			return fmt.Errorf("/dev/%s mode: %w", n.name, err)
		}
	}
	for link, target := range map[string]string{
		"/dev/fd": "/proc/self/fd", "/dev/stdin": "/proc/self/fd/0",
		"/dev/stdout": "/proc/self/fd/1", "/dev/stderr": "/proc/self/fd/2",
		"/dev/ptmx": "pts/ptmx",
	} {
		if err := os.Symlink(target, root+link); err != nil {
			return fmt.Errorf("%s: %w", link, err)
		}
	}
	if cfg.ResolvConf != "" {
		// The session resolver is the supervisor's relay on the veth, so the
		// session's resolv.conf is written here rather than inherited.
		path := root + "/run/resolv.conf"
		if err := os.WriteFile(path, []byte(cfg.ResolvConf), 0o644); err != nil {
			return fmt.Errorf("resolv.conf: %w", err)
		}
		if err := os.MkdirAll(root+"/etc", 0o755); err != nil {
			return fmt.Errorf("/etc: %w", err)
		}
		if _, err := os.Stat(root + "/etc/resolv.conf"); err == nil {
			if err := syscall.Mount(path, root+"/etc/resolv.conf", "", syscall.MS_BIND, ""); err != nil {
				return fmt.Errorf("resolv.conf bind: %w", err)
			}
		}
	}
	old := root + "/.old"
	if err := os.MkdirAll(old, 0o700); err != nil {
		return fmt.Errorf("old root: %w", err)
	}
	if err := syscall.PivotRoot(root, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	if err := syscall.Unmount("/.old", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	_ = os.Remove("/.old")
	if cfg.Hostname != "" {
		_ = syscall.Sethostname([]byte(cfg.Hostname))
	}
	return nil
}

// bindPath bind-mounts src at dst, optionally read-only.
func bindPath(src, dst string, readOnly bool) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDONLY, 0o644)
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return err
	}
	if !readOnly {
		return nil
	}
	// A recursive read-only bind needs mount_setattr(2); this remount covers the
	// top mount, and the configured runtime paths carry no submounts in the
	// guest. shortcut: nested submounts under a read-only path stay writable,
	// upgrade with mount_setattr when a runtime path grows a submount.
	return syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, "")
}

// withEnvDefaults supplies the few variables a program needs to run at all when
// the caller did not name them, and puts the toolbox directories first on PATH.
// A caller that names a key wins, except that PATH always leads with the staged
// prefix and the published bin directory: a tool installed once is found by
// every later session.
func withEnvDefaults(env []string, prefix, binDir string) []string {
	defaults := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "TMPDIR=/tmp"}
	if prefix != "" {
		// An install session gets a prefix it can write, so a script that honours
		// PREFIX (or just writes $HOME) stages what it will publish.
		defaults = []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=" + filepath.Join(prefix, "home"),
			"TMPDIR=" + filepath.Join(prefix, "tmp"),
			"PREFIX=" + prefix,
		}
	}
	have := make(map[string]bool, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			have[k] = true
		}
	}
	out := make([]string, 0, len(defaults)+len(env))
	for _, kv := range defaults {
		if k, _, _ := strings.Cut(kv, "="); !have[k] {
			out = append(out, kv)
		}
	}
	out = append(out, env...)
	return prependToolboxPath(out, prefix, binDir)
}

// prependToolboxPath puts the staged prefix and the published bin directory
// ahead of the program's PATH.
func prependToolboxPath(env []string, prefix, binDir string) []string {
	var dirs []string
	if prefix != "" {
		dirs = append(dirs, filepath.Join(prefix, "bin"))
	}
	if binDir != "" {
		dirs = append(dirs, binDir)
	}
	if len(dirs) == 0 {
		return env
	}
	lead := strings.Join(dirs, ":") + ":"
	for i, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "PATH" {
			env[i] = "PATH=" + lead + v
		}
	}
	return env
}

// lookPathIn resolves a program name against the PATH the program will get,
// which is not this process's PATH: a tool published into the toolbox bin
// directory is on the session PATH and nowhere else.
func lookPathIn(env []string, name string) (string, bool) {
	if strings.ContainsRune(name, '/') {
		return name, false
	}
	for _, kv := range env {
		paths, ok := strings.CutPrefix(kv, "PATH=")
		if !ok {
			continue
		}
		for _, dir := range filepath.SplitList(paths) {
			if dir == "" {
				continue
			}
			candidate := filepath.Join(dir, name)
			if fi, err := os.Stat(candidate); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				return candidate, true
			}
		}
	}
	return name, false
}

// runProgram starts the requested program as the session uid with no
// capabilities, then waits for it and reaps whatever it left behind.
func runProgram(cfg *childConfig) int {
	env := withEnvDefaults(cfg.Env, cfg.Prefix, cfg.BinDir)
	argv := cfg.Argv
	if resolved, ok := lookPathIn(env, argv[0]); ok {
		argv = append([]string{resolved}, argv[1:]...)
	}
	inh, bound := "--inh-caps=-all", "--bounding-set=-all"
	args := []string{
		"--reuid=" + strconv.Itoa(cfg.UID),
		"--regid=" + strconv.Itoa(cfg.GID),
		"--clear-groups",
	}
	if cfg.NetRaw {
		// Ambient survives the exec under no-new-privs; it needs the cap in the
		// inheritable and bounding sets too.
		inh, bound = "--inh-caps=-all,+net_raw", "--bounding-set=-all,+net_raw"
		args = append(args, "--ambient-caps=+net_raw")
	}
	args = append(args, inh, bound, "--no-new-privs", "--")
	args = append(args, argv...)
	cmd := exec.Command(cfg.Setpriv, args...)
	cmd.Dir = cfg.Dir
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cfg.TTY {
		// The program becomes a session leader with the inherited terminal as
		// its controlling terminal, so job control and Ctrl-C reach the
		// foreground process group rather than this supervisor child.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	for i := 0; i < cfg.ExtraFiles; i++ {
		fd := 4 + i
		cmd.ExtraFiles = append(cmd.ExtraFiles, os.NewFile(uintptr(fd), "extra"))
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "execbox child: start %s: %v\n", cfg.Argv[0], err)
		return childFailure
	}
	pid := cmd.Process.Pid
	for {
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return childFailure
		}
		if wpid != pid {
			continue // an orphan we inherited as PID 1; reap and keep going
		}
		if ws.Exited() {
			return ws.ExitStatus()
		}
		if ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return childFailure
	}
}

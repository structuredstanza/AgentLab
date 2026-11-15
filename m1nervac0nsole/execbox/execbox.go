package execbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	sdktool "github.com/structuredstanza/norma/tool"
)

// DefaultSocket is where the supervisor listens inside the guest. Neither the
// socket nor its directory is visible inside a session's mount namespace.
const DefaultSocket = "/run/m1nervac0nsole/execbox.sock"

// SocketEnv overrides DefaultSocket for both the supervisor and the client.
const SocketEnv = "M1NERVAC0NSOLE_EXECBOX_SOCKET"

// SocketPath returns the configured supervisor socket path.
func SocketPath() string {
	if p := strings.TrimSpace(os.Getenv(SocketEnv)); p != "" {
		return p
	}
	return DefaultSocket
}

// DefaultToolboxRoot is the host-backed toolbox directory inside the guest.
// Published tools live in bin/ and install sessions stage into staging/. It is
// under /state, which survives sandbox recreation, so a tool installed once is
// available to later sessions and later boots.
const DefaultToolboxRoot = "/state/m1nervac0nsole/toolbox"

// ToolboxEnv overrides DefaultToolboxRoot for both the supervisor and the
// server, so the two agree on where a published tool lives. Tests point it at a
// temporary directory.
const ToolboxEnv = "M1NERVAC0NSOLE_TOOLBOX_ROOT"

// ToolboxRoot returns the configured toolbox root.
func ToolboxRoot() string {
	if p := strings.TrimSpace(os.Getenv(ToolboxEnv)); p != "" {
		return p
	}
	return DefaultToolboxRoot
}

// ErrUnavailable reports that isolated execution cannot be provided. Callers
// must surface it instead of running the process unisolated.
var ErrUnavailable = errors.New("execbox: isolated execution unavailable")

// ErrNoSession reports a spawn request that carried no backend-issued session.
// It is a programming error in the host wiring, and it fails closed.
var ErrNoSession = errors.New("execbox: no netpolicy session in context")

// ErrNoStdinEOF reports that a session cannot signal EOF on stdin: a PTY has no
// separate stdin to close, so the caller must send ^D or end the session.
var ErrNoStdinEOF = errors.New("execbox: stdin EOF is unsupported for a PTY session")

// CapabilityError names the kernel or configuration capability that is missing.
// It matches ErrUnavailable so a caller can tell "cannot isolate" from "the
// program failed".
type CapabilityError struct {
	Missing []string
	Detail  string
}

func (e *CapabilityError) Error() string {
	if len(e.Missing) == 0 {
		return ErrUnavailable.Error() + ": " + e.Detail
	}
	msg := ErrUnavailable.Error() + ": missing " + strings.Join(e.Missing, ", ")
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

func (e *CapabilityError) Is(target error) bool { return target == ErrUnavailable }

// Spec describes one process to start inside a session.
type Spec struct {
	// Argv is the program and its arguments. It is executed directly; the
	// caller decides whether that is a shell.
	Argv []string
	// Dir is the working directory: a directory inside a configured writable
	// root, which is bind-mounted into the session at the same absolute path,
	// or exactly /tmp, which is the session's own private tmpfs rather than
	// the host's.
	Dir string
	// Writable lists further directories the program may write, each inside a
	// configured writable root. The browser needs its profile and download
	// directories; everything else stays read-only or absent.
	Writable []string
	// Env is the complete environment for the program. The supervisor adds
	// nothing except PATH/HOME/TMPDIR defaults when those keys are absent.
	Env []string
	// TTY attaches a pseudo-terminal to the program's stdin/stdout/stderr.
	TTY bool
	// Rows and Cols size that terminal.
	Rows, Cols int
	// MergeStderr folds stderr into the stdout stream, matching a shell whose
	// two descriptors point at the same file. RunOnce ignores it when the run
	// carries a capture identity: a capture records the two streams apart, and
	// Output still holds both in arrival order.
	MergeStderr bool
	// ExtraFiles is how many client-supplied descriptors to place at fd 3.. in
	// the program. The Chromium CDP pipe uses 2.
	ExtraFiles int
}

// Result is the outcome of a one-shot run.
type Result struct {
	ExitCode int
	// Output is every frame the supervisor delivered, in arrival order. It is
	// what arrived even when the run failed.
	Output []byte
	// Stdout and Stderr hold the two streams separately when the run captured
	// them apart; they are nil when stderr was merged into stdout at the child's
	// descriptors.
	Stdout, Stderr []byte
	// Exited reports that the supervisor sent an exit status. When it is false
	// the run ended for another reason and ExitCode is -1, which is not a
	// successful exit.
	Exited bool
	// StdinEOF reports that the client signalled EOF on stdin.
	StdinEOF bool
	// StdinAccepted is the byte count the supervisor's stdin pipe accepted, or
	// nil when no exit frame arrived.
	StdinAccepted *int64
	// Artifact is the relative pointer to this process's persistent capture, or
	// "" when the run kept none.
	Artifact string
}

// Process is a running session. Run returns it as an io.ReadWriteCloser, the
// shape the execution contract fixes; the same value also implements Process so
// a caller that needs the exit status, the stderr stream or a resize can assert
// it.
type Process interface {
	io.ReadWriteCloser
	// Stderr returns the separate stderr stream, or nil when stderr was merged
	// into the stdout stream. A caller that receives a non-nil stream must read
	// it concurrently with the stdout stream: the client writes each frame to
	// its stream, so ignoring one stalls the other.
	Stderr() io.Reader
	// CloseStdin signals EOF to the program's stdin without ending the session,
	// so a program that reads to EOF finishes and Wait returns its own code. A
	// PTY session has no separate stdin to close and refuses with ErrNoStdinEOF.
	CloseStdin() error
	// Resize changes the terminal size of a TTY session.
	Resize(rows, cols int) error
	// Wait blocks until the program exits and returns its exit code.
	Wait() (int, error)
	// Kill terminates the session's whole process tree.
	Kill() error
}

// Client is the narrow seam the SDK, the server and the browser driver use to
// start a process in a session.
type Client interface {
	// Run starts a streaming process and returns its terminal or pipe streams.
	Run(ctx context.Context, s netpolicy.Session, spec Spec) (io.ReadWriteCloser, error)
	// RunOnce starts a process, waits for it and returns its combined output.
	RunOnce(ctx context.Context, s netpolicy.Session, spec Spec) (Result, error)
	// Capabilities reports what the supervisor verified it can enforce.
	Capabilities(ctx context.Context) (Report, error)
}

// --- session in the trusted context ---

type sessionKey struct{}

// WithSession attaches a backend-issued session to a run's context. The host
// calls this where it knows the task, conversation and purpose; tools never do.
func WithSession(ctx context.Context, s netpolicy.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFrom returns the session attached to ctx.
func SessionFrom(ctx context.Context) (netpolicy.Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(netpolicy.Session)
	return s, ok
}

// ProxyURL returns the proxy URL a run's tool environment carries: addr with the
// credential of the session attached to ctx. It is the one place a tool-facing
// proxy URL is built, so every spawn site (Bash env, WebFetch, Chromium, the
// custom http tool, a manifest run) presents the session of the run it belongs
// to. Empty when ctx carries no session or addr is empty: a run with no session
// gets no proxy rather than a bare address the gateway would refuse.
func ProxyURL(ctx context.Context, addr string) string {
	s, _ := SessionFrom(ctx)
	return netpolicy.ProxyURL(s, addr)
}

// --- process-wide installation ---

var (
	installMu sync.RWMutex
	installed Client
)

// Install makes c the client used by the SDK execution seam, the browser driver
// and any other caller of Installed. It is called once by the entry point.
func Install(c Client) {
	installMu.Lock()
	installed = c
	installMu.Unlock()
	if c == nil {
		sdktool.SetExecutor(nil)
		return
	}
	sdktool.SetExecutor(&toolExecutor{c: c})
}

// Installed returns the installed client, if any.
func Installed() (Client, bool) {
	installMu.RLock()
	defer installMu.RUnlock()
	return installed, installed != nil
}

// requireSession returns the session attached to ctx or a capability error.
func requireSession(ctx context.Context) (netpolicy.Session, error) {
	s, ok := SessionFrom(ctx)
	if !ok {
		return netpolicy.Session{}, fmt.Errorf("%w: %w", ErrUnavailable, ErrNoSession)
	}
	if strings.TrimSpace(s.ID) == "" || !s.Purpose.Valid() {
		return netpolicy.Session{}, fmt.Errorf("%w: incomplete session (id=%q purpose=%q)", ErrUnavailable, s.ID, s.Purpose)
	}
	return s, nil
}

// RequireSession returns the backend-issued session attached to ctx, or a
// capability error. A spawn site that must not run unisolated calls it before
// asking the supervisor for a process.
func RequireSession(ctx context.Context) (netpolicy.Session, error) { return requireSession(ctx) }

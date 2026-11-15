// Modified for AgentLab: execution seam for an isolated process supervisor.

package tool

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
)

// The execution seam. Hosts that run tool processes inside an isolation
// boundary (namespaces, cgroup, unprivileged uid) install an Executor with
// SetExecutor; every spawn site in this package (Bash, background tasks, PTY
// shells, ripgrep) then asks it instead of calling os/exec itself.
//
// A nil Executor keeps the SDK's standalone behaviour of spawning directly.
// That is not an isolation boundary: a host that needs one must install an
// Executor, and the Executor must fail closed when the boundary is unavailable
// rather than spawning unisolated. Session identity is never an argument here;
// the Executor reads it from the context the host attached to the run.

// ExecResult is the outcome of a one-shot spawn.
type ExecResult struct {
	ExitCode int
	Output   string
	// Artifact is the one-line pointer to this process's persistent capture, or
	// "" when the host kept none.
	//
	// Local addition for AgentLab per-call process evidence.
	Artifact string
}

// ExecSession is a running process the SDK drives through a stream: a PTY for
// an interactive shell, or the combined output pipe for a background task.
type ExecSession interface {
	io.ReadWriteCloser
	// Wait blocks until the process exits.
	Wait() error
	// ExitCode reports the exit status after Wait returned.
	ExitCode() int
	// Kill terminates the process and everything it started.
	Kill()
}

// ExecArtifact is implemented by an ExecSession whose process capture was
// written to a persistent artifact. ArtifactRef returns a one-line pointer for
// the tool result, or "" when the process has none.
//
// Local addition for AgentLab per-call process evidence.
type ExecArtifact interface {
	ArtifactRef() string
}

// Executor starts processes for this package's tools.
type Executor interface {
	// RunOnce runs a command to completion and returns its combined output.
	RunOnce(ctx context.Context, spec SpawnSpec) (ExecResult, error)
	// Run starts a streaming process. spec.TTY selects a terminal.
	Run(ctx context.Context, spec SpawnSpec) (ExecSession, error)
}

// ExecIdentity is the per-call identity of one spawn: the tool_use id the call
// answers and the run workspace it belongs to. A host that keeps per-process
// evidence reads it from the context it hands its Executor, so this package
// never needs to know how that evidence is stored.
//
// Local addition for AgentLab per-call process evidence.
type ExecIdentity struct {
	ToolUseID string
	RunDir    string
}

type execIdentityKey struct{}

// WithExecIdentity attaches the call's identity to ctx. An identity missing the
// tool_use id or the run directory records nothing, so the chain is returned
// untouched and a host with no evidence store pays nothing.
func WithExecIdentity(ctx context.Context, id ExecIdentity) context.Context {
	if id.ToolUseID == "" || id.RunDir == "" {
		return ctx
	}
	return context.WithValue(ctx, execIdentityKey{}, id)
}

// ExecIdentityFrom returns the identity attached to ctx.
func ExecIdentityFrom(ctx context.Context) (ExecIdentity, bool) {
	id, ok := ctx.Value(execIdentityKey{}).(ExecIdentity)
	return id, ok
}

// withExecIdentity attaches the identity of a tool call, when it has one.
func withExecIdentity(ctx context.Context, tc *ToolContext) context.Context {
	if tc == nil {
		return ctx
	}
	return WithExecIdentity(ctx, ExecIdentity{ToolUseID: tc.ToolUseID, RunDir: tc.WorkingDir})
}

// artifactRef returns the capture pointer of a task's process, if the host kept
// one.
func artifactRef(t *Task) string {
	if t == nil || t.sess == nil {
		return ""
	}
	if a, ok := t.sess.(ExecArtifact); ok {
		return a.ArtifactRef()
	}
	return ""
}

// withArtifact appends the artifact pointer line, when the host kept one.
func withArtifact(text, ref string) string {
	if ref == "" {
		return text
	}
	return text + "\n" + ref
}

var (
	execMu   sync.RWMutex
	executor Executor
)

// SetExecutor installs the process executor. Passing nil restores the SDK's
// direct-spawn behaviour.
func SetExecutor(e Executor) {
	execMu.Lock()
	executor = e
	execMu.Unlock()
}

// currentExecutor returns the installed executor, or nil.
func currentExecutor() Executor {
	execMu.RLock()
	defer execMu.RUnlock()
	return executor
}

// tcEnv returns the host-supplied environment of a tool call.
func tcEnv(tc *ToolContext) []string {
	if tc == nil {
		return nil
	}
	return tc.Env
}

// localPTY is the direct-spawn ExecSession: the PTY the SDK has always opened
// for an interactive shell. It exists so the shell tools have one shape whether
// or not a host installed an executor.
type localPTY struct {
	cmd  *exec.Cmd
	ptmx *os.File
	code int
}

func (l *localPTY) Read(p []byte) (int, error)  { return l.ptmx.Read(p) }
func (l *localPTY) Write(p []byte) (int, error) { return l.ptmx.Write(p) }
func (l *localPTY) Close() error                { return l.ptmx.Close() }

func (l *localPTY) Wait() error {
	err := l.cmd.Wait()
	if l.cmd.ProcessState != nil {
		l.code = l.cmd.ProcessState.ExitCode()
	}
	return err
}

func (l *localPTY) ExitCode() int { return l.code }

func (l *localPTY) Kill() {
	if l.cmd.Process != nil {
		treeKill(l.cmd.Process)
	}
}

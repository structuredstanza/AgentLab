package execbox

// Per-call process evidence. A spawn that carries an artifact identity gets one
// directory per process under <run workspace>/exec-artifacts/: the stdin the
// client submitted, the stdout and stderr the supervisor delivered (or the one
// terminal stream of a PTY), and a manifest that says what is actually there.
//
// The run workspace is writable by that task's own processes, so these files are
// not tamper-proof on their own: the SHA-256 values in the tool result are the
// integrity anchor. The capture never records the environment, which carries the
// run's proxy credential.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	sdktool "github.com/structuredstanza/norma/tool"
)

// Artifact outcomes. They say how the process ended, not whether it succeeded.
const (
	OutcomeExited         = "exited"
	OutcomeTransportError = "transport_error"
	OutcomeCancelled      = "cancelled"
	OutcomeTimeout        = "timeout"
	OutcomeWriteFailed    = "artifact_write_failed"
)

// Artifact origins: a model-invoked call, or an operator action with no tool
// call (whose capture then has an empty tool_use_id).
const (
	OriginTool     = "tool"
	OriginOperator = "operator"
)

// ArtifactCall names where a process capture goes and what it belongs to.
type ArtifactCall struct {
	// Dir is the run workspace root: the task or conversation directory the
	// capture is written under.
	Dir string
	// ToolUseID is the tool_use id of the call that spawned the process. It is
	// empty only for Origin "operator".
	ToolUseID string
	// Origin is "tool" for a model-invoked call and "operator" for an action
	// with no tool call. Empty means "tool".
	Origin string
}

type artifactKey struct{}

// WithArtifacts attaches per-call process capture to ctx. An unusable call (no
// absolute run directory, or no tool_use id outside the operator origin) records
// nothing, so the context chain is returned untouched.
func WithArtifacts(ctx context.Context, call ArtifactCall) context.Context {
	if !filepath.IsAbs(call.Dir) {
		return ctx
	}
	if call.ToolUseID == "" && call.Origin != OriginOperator {
		return ctx
	}
	if call.Origin == "" {
		call.Origin = OriginTool
	}
	return context.WithValue(ctx, artifactKey{}, call)
}

// ArtifactsFrom returns the capture identity attached to ctx.
func ArtifactsFrom(ctx context.Context) (ArtifactCall, bool) {
	call, ok := ctx.Value(artifactKey{}).(ArtifactCall)
	return call, ok
}

// artifactIdentity resolves a spawn's capture identity: the host's explicit
// call first, then the SDK's tool-call identity.
func artifactIdentity(ctx context.Context) (ArtifactCall, bool) {
	if call, ok := ArtifactsFrom(ctx); ok {
		return call, true
	}
	if id, ok := sdktool.ExecIdentityFrom(ctx); ok {
		return ArtifactCall{Dir: id.RunDir, ToolUseID: id.ToolUseID, Origin: OriginTool}, true
	}
	return ArtifactCall{}, false
}

// ArtifactPointer returns the pointer to a finished run's persistent capture,
// or "" when the run kept none. The method is exported because the interface is
// satisfied outside this package: an unexported method name is package-scoped,
// so a caller's own Process could never match it.
func ArtifactPointer(p Process) string {
	if a, ok := p.(interface{ ArtifactPointer() string }); ok {
		return a.ArtifactPointer()
	}
	return ""
}

// artifactFinish is what the caller learned about the process.
type artifactFinish struct {
	// ExitCode is nil when no exit status arrived.
	ExitCode *int
	// Outcome is one of the Outcome constants.
	Outcome string
	// Err is the failure text, empty on a clean exit.
	Err string
	// StdinAccepted is the byte count the program's stdin pipe (or its terminal)
	// accepted, or nil when no exit frame arrived.
	StdinAccepted *int64
	// Complete reports that every stream was read to its end.
	Complete bool
}

// artifact is one process's capture. A nil *artifact is a no-op.
type artifact struct {
	mu       sync.Mutex
	dir      string
	rel      string
	meta     artifactMeta
	stdinW   *artifactStreamWriter
	stdoutW  *artifactStreamWriter
	stderrW  *artifactStreamWriter
	eof      bool
	finished bool
	pointer  string
	err      error
}

type artifactMeta struct {
	Version        int             `json:"v"`
	ToolUseID      string          `json:"tool_use_id"`
	Origin         string          `json:"origin"`
	TaskID         int64           `json:"task_id"`
	ConversationID int64           `json:"conversation_id"`
	Argv           []string        `json:"argv"`
	Dir            string          `json:"dir"`
	StartedAt      string          `json:"started_at"`
	EndedAt        string          `json:"ended_at"`
	ExitCode       *int            `json:"exit_code"`
	Outcome        string          `json:"outcome"`
	Error          string          `json:"error"`
	Streams        artifactStreams `json:"streams"`
	Merged         bool            `json:"merged"`
}

type artifactStreams struct {
	Stdin  artifactStdin  `json:"stdin"`
	Stdout artifactOutput `json:"stdout"`
	Stderr artifactOutput `json:"stderr"`
}

type artifactStdin struct {
	SubmittedBytes int64  `json:"submitted_bytes"`
	AcceptedBytes  *int64 `json:"accepted_bytes"`
	EOFSent        bool   `json:"eof_sent"`
	SHA256         string `json:"sha256"`
}

type artifactOutput struct {
	Bytes    int64  `json:"bytes"`
	Complete bool   `json:"complete"`
	SHA256   string `json:"sha256"`
}

// artifactStreamWriter counts and hashes the bytes it writes. A write failure is
// recorded on the artifact and never returned: the capture is a side channel, so
// losing it must not disturb the process or its output.
type artifactStreamWriter struct {
	a *artifact
	f *os.File
	h hash.Hash
	n int64
}

func (w *artifactStreamWriter) Write(p []byte) (int, error) {
	if w == nil || w.a == nil {
		return len(p), nil
	}
	a := w.a
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finished || w.f == nil {
		return len(p), nil
	}
	n, err := w.f.Write(p)
	if n > 0 {
		w.n += int64(n)
		_, _ = w.h.Write(p[:n])
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		a.failLocked(err)
	}
	return len(p), nil
}

// newArtifact creates the capture directory for one process. A capture that
// cannot be created is refused: the process still runs, and the result carries
// no pointer rather than a claim that evidence exists.
func newArtifact(call ArtifactCall, sess netpolicy.Session, spec Spec) *artifact {
	dir, rel, err := artifactDir(call.Dir, call.ToolUseID)
	if err != nil {
		return nil
	}
	origin := call.Origin
	if origin == "" {
		origin = OriginTool
	}
	a := &artifact{
		dir: dir,
		rel: rel,
		meta: artifactMeta{
			Version:        1,
			ToolUseID:      call.ToolUseID,
			Origin:         origin,
			TaskID:         sess.TaskID,
			ConversationID: sess.ConversationID,
			Argv:           append([]string(nil), spec.Argv...),
			Dir:            spec.Dir,
			StartedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			Merged:         spec.MergeStderr || spec.TTY,
		},
	}
	a.stdinW = a.open("stdin")
	a.stdoutW = a.open("stdout")
	if !spec.MergeStderr && !spec.TTY {
		a.stderrW = a.open("stderr")
	}
	if a.stdinW == nil || a.stdoutW == nil {
		_ = os.RemoveAll(dir)
		return nil
	}
	return a
}

// open creates one capture file. A file that cannot be created leaves the
// writer nil, which the callers treat as "no capture".
func (a *artifact) open(name string) *artifactStreamWriter {
	f, err := os.OpenFile(filepath.Join(a.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		a.mu.Lock()
		a.failLocked(err)
		a.mu.Unlock()
		return nil
	}
	return &artifactStreamWriter{a: a, f: f, h: sha256.New()}
}

// Stdin returns the writer for the bytes the client submits. It is never nil.
func (a *artifact) Stdin() io.Writer { return a.stdinW }

// Stdout returns the writer for the process's stdout, or its terminal stream
// when the process has a PTY.
func (a *artifact) Stdout() io.Writer { return a.stdoutW }

// Stderr returns the writer for the process's stderr, or nil when stderr is not
// a separate stream.
func (a *artifact) Stderr() io.Writer {
	if a == nil || a.stderrW == nil {
		return nil
	}
	return a.stderrW
}

// SetEOF records that stdin EOF was sent.
func (a *artifact) SetEOF() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.eof = true
	a.mu.Unlock()
}

// ArtifactPointer returns the pointer line written by Finish.
func (a *artifact) ArtifactPointer() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pointer
}

// Finish writes the manifest and returns the pointer line for the tool result.
// It is idempotent and never fails the process: a capture that could not be
// completed is recorded as such, and the pointer is then empty.
func (a *artifact) Finish(f artifactFinish) string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finished {
		return a.pointer
	}
	a.finished = true
	for _, w := range []*artifactStreamWriter{a.stdinW, a.stdoutW, a.stderrW} {
		if w != nil && w.f != nil {
			if err := w.f.Close(); err != nil {
				a.failLocked(err)
			}
		}
	}
	outcome, complete := f.Outcome, f.Complete
	if a.err != nil {
		outcome, complete = OutcomeWriteFailed, false
	}
	a.meta.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	a.meta.ExitCode = f.ExitCode
	a.meta.Outcome = outcome
	a.meta.Error = f.Err
	if a.err != nil {
		a.meta.Error = strings.TrimSpace(a.meta.Error + " " + a.err.Error())
	}
	a.meta.Streams = artifactStreams{
		Stdin: artifactStdin{
			SubmittedBytes: a.stdinW.count(),
			AcceptedBytes:  f.StdinAccepted,
			EOFSent:        a.eof,
			SHA256:         a.stdinW.sum(),
		},
		Stdout: artifactOutput{Bytes: a.stdoutW.count(), Complete: complete, SHA256: a.stdoutW.sum()},
		Stderr: artifactOutput{Complete: true},
	}
	if a.stderrW != nil {
		a.meta.Streams.Stderr = artifactOutput{Bytes: a.stderrW.count(), Complete: complete, SHA256: a.stderrW.sum()}
	}
	if err := a.writeMetaLocked(); err != nil {
		return ""
	}
	a.pointer = a.pointerLine()
	return a.pointer
}

func (w *artifactStreamWriter) count() int64 {
	if w == nil {
		return 0
	}
	return w.n
}

func (w *artifactStreamWriter) sum() string {
	if w == nil || w.h == nil {
		return ""
	}
	return hex.EncodeToString(w.h.Sum(nil))
}

func (a *artifact) failLocked(err error) {
	if a.err == nil {
		a.err = err
	}
}

// writeMetaLocked replaces the manifest atomically: a directory whose manifest
// is missing reads as an incomplete capture, never as a successful one. The temp
// file is opened without following a link, so a workspace that later became
// writable to the task cannot redirect the manifest write.
func (a *artifact) writeMetaLocked() error {
	b, err := json.Marshal(a.meta)
	if err != nil {
		return err
	}
	tmp := filepath.Join(a.dir, "meta.json.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(a.dir, "meta.json"))
}

// pointerLine is the one line a tool result carries: where the capture is and
// the three hashes that anchor it.
func (a *artifact) pointerLine() string {
	stderr := "stderr sha256: " + a.meta.Streams.Stderr.SHA256
	if a.meta.Merged {
		stderr = "stderr: merged into stdout"
	}
	return fmt.Sprintf("[exec artifact: %s (stdin sha256: %s, stdout sha256: %s, %s)]",
		a.rel, a.meta.Streams.Stdin.SHA256, a.meta.Streams.Stdout.SHA256, stderr)
}

// artifactDir creates one process's directory under root and refuses anything
// that would write through a link out of the run workspace.
func artifactDir(root, toolUseID string) (string, string, error) {
	if !filepath.IsAbs(root) {
		return "", "", fmt.Errorf("run directory %q is not absolute", root)
	}
	base := filepath.Join(root, "exec-artifacts")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", "", err
	}
	fi, err := os.Lstat(base)
	if err != nil {
		return "", "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return "", "", fmt.Errorf("%s is not a directory", base)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", "", err
	}
	if resolvedBase != filepath.Join(resolvedRoot, "exec-artifacts") {
		return "", "", fmt.Errorf("%s resolves outside the run workspace", base)
	}
	suffix, err := randomHex(4)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(toolUseID))
	name := hex.EncodeToString(sum[:8]) + "-" + suffix
	dir := filepath.Join(base, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", "", err
	}
	return dir, filepath.Join("exec-artifacts", name), nil
}

// randomHex returns n random bytes as hex. It is the per-process part of the
// directory name, so repeated tool_use ids and several spawns in one call cannot
// collide.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// contextOutcome names why a run ended when its context fired.
func contextOutcome(ctx context.Context) string {
	if ctx.Err() == context.DeadlineExceeded {
		return OutcomeTimeout
	}
	return OutcomeCancelled
}

// errText is the failure text of an error, empty for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

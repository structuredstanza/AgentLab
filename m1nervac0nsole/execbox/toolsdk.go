package execbox

import (
	"context"
	"fmt"
	"io"
	"strings"

	sdktool "github.com/structuredstanza/norma/tool"
)

// toolExecutor adapts the client to the SDK's execution seam. It is the only
// bridge between the agent SDK and the supervisor: the SDK never learns the
// socket path, the session type or the namespace mechanism.
type toolExecutor struct{ c Client }

// sessionSpec builds the supervisor request for one SDK spawn. The session
// comes from the caller's trusted context; a missing one is refused by the
// caller rather than guessed from the working directory.
func (e *toolExecutor) sessionSpec(ctx context.Context, spec sdktool.SpawnSpec) (Spec, error) {
	dir := spec.WorkingDir
	if dir == "" {
		// The SDK allows an empty working directory; a session needs one, and
		// the session's private /tmp is the only safe default.
		dir = "/tmp"
	}
	out := Spec{
		Dir:         dir,
		Env:         toolEnv(spec.Env),
		TTY:         spec.TTY,
		Rows:        spec.Rows,
		Cols:        spec.Cols,
		MergeStderr: !spec.TTY,
	}
	if len(spec.Argv) > 0 {
		out.Argv = spec.Argv
	} else {
		out.Argv = []string{"bash", "-c", spec.Command}
	}
	return out, nil
}

// RunOnce implements the SDK's one-shot spawn. A run that failed after the
// supervisor delivered output returns that output with the error, so the caller
// can show what actually happened instead of nothing.
func (e *toolExecutor) RunOnce(ctx context.Context, spec sdktool.SpawnSpec) (sdktool.ExecResult, error) {
	sess, err := requireSession(ctx)
	if err != nil {
		return sdktool.ExecResult{}, err
	}
	req, err := e.sessionSpec(ctx, spec)
	if err != nil {
		return sdktool.ExecResult{}, err
	}
	res, err := e.c.RunOnce(ctx, sess, req)
	out := sdktool.ExecResult{ExitCode: res.ExitCode, Output: string(res.Output), Artifact: res.Artifact}
	if err != nil {
		return out, err
	}
	return out, nil
}

// Run implements the SDK's streaming spawn (background tasks and PTY shells).
func (e *toolExecutor) Run(ctx context.Context, spec sdktool.SpawnSpec) (sdktool.ExecSession, error) {
	sess, err := requireSession(ctx)
	if err != nil {
		return nil, err
	}
	req, err := e.sessionSpec(ctx, spec)
	if err != nil {
		return nil, err
	}
	rwc, err := e.c.Run(ctx, sess, req)
	if err != nil {
		return nil, err
	}
	p, ok := ProcessOf(rwc)
	if !ok {
		rwc.Close()
		return nil, fmt.Errorf("execbox: client returned a stream without process control")
	}
	return &toolSession{p: p}, nil
}

// toolSession adapts a Process to the SDK's ExecSession.
type toolSession struct {
	p    Process
	code int
}

func (t *toolSession) Read(b []byte) (int, error)  { return t.p.Read(b) }
func (t *toolSession) Write(b []byte) (int, error) { return t.p.Write(b) }
func (t *toolSession) Close() error                { return t.p.Close() }
func (t *toolSession) Kill()                       { _ = t.p.Kill() }

func (t *toolSession) Wait() error {
	code, err := t.p.Wait()
	t.code = code
	return err
}

func (t *toolSession) ExitCode() int { return t.code }

// ArtifactRef returns the pointer to this process's persistent capture, or ""
// when the run kept none.
func (t *toolSession) ArtifactRef() string { return ArtifactPointer(t.p) }

// toolEnv builds the session environment: a minimal base, the SDK's
// non-interactive defaults, then the host's explicit entries. The backend's own
// environment is deliberately not inherited, so a controller secret cannot leak
// into a tool process through an unrelated variable.
func toolEnv(extra []string) []string {
	base := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"LANG=C.UTF-8",
		"PAGER=cat",
		"GIT_PAGER=cat",
		"SYSTEMD_PAGER=cat",
		"DEBIAN_FRONTEND=noninteractive",
	}
	keys := make(map[string]bool, len(extra))
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok {
			keys[k] = true
		}
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		if k, _, ok := strings.Cut(kv, "="); ok && keys[k] {
			continue // the host's explicit value wins
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

var _ io.ReadWriteCloser = (*toolSession)(nil)

var _ sdktool.ExecArtifact = (*toolSession)(nil)

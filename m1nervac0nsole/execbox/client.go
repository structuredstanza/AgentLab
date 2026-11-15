package execbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// socketClient talks to the privileged supervisor.
type socketClient struct{ path string }

// NewClient returns a client for the supervisor socket at path. An empty path
// uses SocketPath().
func NewClient(path string) Client {
	if path == "" {
		path = SocketPath()
	}
	return &socketClient{path: path}
}

func (c *socketClient) dial(ctx context.Context) (*wireConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, &CapabilityError{Missing: []string{"supervisor"}, Detail: fmt.Sprintf("dial %s: %v", c.path, err)}
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, &CapabilityError{Missing: []string{"supervisor"}, Detail: "not a unix connection"}
	}
	return newWireConn(uc), nil
}

func sessionToWire(s netpolicy.Session) *sessionWire {
	return &sessionWire{ID: s.ID, TaskID: s.TaskID, ConversationID: s.ConversationID, Purpose: string(s.Purpose), Revision: s.Revision}
}

func sessionFromWire(w *sessionWire) netpolicy.Session {
	if w == nil {
		return netpolicy.Session{}
	}
	return netpolicy.Session{ID: w.ID, TaskID: w.TaskID, ConversationID: w.ConversationID, Purpose: netpolicy.Purpose(w.Purpose), Revision: w.Revision}
}

// frameErr turns an error frame into an error, keeping the capability shape.
func frameErr(f frame) error {
	if len(f.Missing) > 0 {
		return &CapabilityError{Missing: f.Missing, Detail: f.Detail}
	}
	if f.Message == "" {
		f.Message = "supervisor error"
	}
	return fmt.Errorf("execbox: %s", f.Message)
}

// Capabilities asks the supervisor what it verified it can enforce.
func (c *socketClient) Capabilities(ctx context.Context) (Report, error) {
	w, err := c.dial(ctx)
	if err != nil {
		return Report{}, err
	}
	defer w.c.Close()
	stop := context.AfterFunc(ctx, func() { w.c.Close() })
	defer stop()
	if err := w.write(request{Op: opCapabilities}); err != nil {
		return Report{}, fmt.Errorf("execbox: capabilities: %w", err)
	}
	var f frame
	if err := w.read(&f); err != nil {
		return Report{}, fmt.Errorf("execbox: capabilities: %w", err)
	}
	if f.Type == frameError {
		return Report{}, frameErr(f)
	}
	if f.Type != frameReport || f.Report == nil {
		return Report{}, fmt.Errorf("execbox: capabilities: unexpected frame %q", f.Type)
	}
	return *f.Report, nil
}

// RunOnce starts a process, waits for it and returns its combined output.
//
// A one-shot run has no caller writing stdin, so a non-TTY program is told its
// input ended as soon as the session is ready; otherwise a command that reads to
// EOF waits for input nobody will send. A terminal has no separate stdin to
// close and is left alone.
//
// Output that arrived before a failure is returned with the error, and ExitCode
// is then -1: the caller gets what was actually captured instead of nothing.
func (c *socketClient) RunOnce(ctx context.Context, s netpolicy.Session, spec Spec) (Result, error) {
	w, err := c.dial(ctx)
	if err != nil {
		return Result{}, err
	}
	defer w.c.Close()
	stop := context.AfterFunc(ctx, func() { w.c.Close() })
	defer stop()
	eof := !spec.TTY
	// Per-call evidence needs the two streams apart; Output still carries both
	// in the order their frames arrived.
	call, haveArtifact := artifactIdentity(ctx)
	if haveArtifact && !spec.TTY {
		spec.MergeStderr = false
	}
	split := !spec.MergeStderr
	if err := w.write(request{Op: opStart, Session: sessionToWire(s), Spec: &spec}); err != nil {
		return Result{}, fmt.Errorf("execbox: start: %w", err)
	}
	var out, stdout, stderr []byte
	var art *artifact
	res := Result{ExitCode: -1}
	finish := func(code int, exited bool, accepted *int64, outcome string, runErr error) (Result, error) {
		res.ExitCode = code
		res.Output, res.Stdout, res.Stderr = out, stdout, stderr
		res.Exited, res.StdinEOF, res.StdinAccepted = exited, eof, accepted
		if art != nil {
			var exit *int
			if exited {
				exit = &code
			}
			res.Artifact = art.Finish(artifactFinish{
				ExitCode: exit, Outcome: outcome, Err: errText(runErr),
				StdinAccepted: accepted, Complete: exited,
			})
		}
		return res, runErr
	}
	for {
		var f frame
		if err := w.read(&f); err != nil {
			if ctx.Err() != nil {
				return finish(-1, false, nil, contextOutcome(ctx), ctx.Err())
			}
			return finish(-1, false, nil, OutcomeTransportError, fmt.Errorf("execbox: read: %w", err))
		}
		switch f.Type {
		case frameReady:
			if haveArtifact && art == nil {
				art = newArtifact(call, s, spec)
			}
			if eof {
				if err := w.write(frame{Type: frameStdinEOF}); err != nil {
					return finish(-1, false, nil, OutcomeTransportError, fmt.Errorf("execbox: stdin eof: %w", err))
				}
				// The manifest must show the EOF this path sent, not only the
				// one CloseStdin sends.
				art.SetEOF()
			}
		case frameStdout:
			out = append(out, f.Data...)
			if split {
				stdout = append(stdout, f.Data...)
			}
			if art != nil {
				_, _ = art.Stdout().Write(f.Data)
			}
		case frameStderr:
			out = append(out, f.Data...)
			if split {
				stderr = append(stderr, f.Data...)
			}
			if art != nil {
				if aw := art.Stderr(); aw != nil {
					_, _ = aw.Write(f.Data)
				}
			}
		case frameExit:
			return finish(f.Code, true, f.StdinAccepted, OutcomeExited, nil)
		case frameError:
			return finish(-1, false, nil, OutcomeTransportError, frameErr(f))
		}
	}
}

// Run starts a streaming process. The returned value is an io.ReadWriteCloser
// as the execution contract fixes; it also implements Process.
func (c *socketClient) Run(ctx context.Context, s netpolicy.Session, spec Spec) (io.ReadWriteCloser, error) {
	return c.run(ctx, s, spec, nil)
}

// RunWithFiles starts a streaming process with descriptors placed at fd 3.. in
// the program. The Chromium CDP pipe needs it; Run stays the contract shape.
func (c *socketClient) RunWithFiles(ctx context.Context, s netpolicy.Session, spec Spec, files []*os.File) (io.ReadWriteCloser, error) {
	if len(files) != spec.ExtraFiles {
		return nil, fmt.Errorf("execbox: %d descriptors for %d extra-file slots", len(files), spec.ExtraFiles)
	}
	return c.run(ctx, s, spec, files)
}

func (c *socketClient) run(ctx context.Context, s netpolicy.Session, spec Spec, files []*os.File) (io.ReadWriteCloser, error) {
	w, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := request{Op: opStart, Session: sessionToWire(s), Spec: &spec}
	if len(files) > 0 {
		err = w.writeWithFDs(req, files)
	} else {
		err = w.write(req)
	}
	if err != nil {
		w.c.Close()
		return nil, fmt.Errorf("execbox: start: %w", err)
	}
	var f frame
	if err := w.read(&f); err != nil {
		w.c.Close()
		return nil, fmt.Errorf("execbox: start: %w", err)
	}
	if f.Type == frameError {
		w.c.Close()
		return nil, frameErr(f)
	}
	if f.Type != frameReady {
		w.c.Close()
		return nil, fmt.Errorf("execbox: start: unexpected frame %q", f.Type)
	}
	p := &process{w: w, merged: spec.MergeStderr, tty: spec.TTY, ctx: ctx, done: make(chan struct{})}
	p.outR, p.outW = io.Pipe()
	if !spec.MergeStderr {
		p.errR, p.errW = io.Pipe()
	}
	if call, ok := artifactIdentity(ctx); ok {
		p.art = newArtifact(call, s, spec)
	}
	// Cancelling the caller's context ends the session, the way a directly
	// spawned process dies with its command context.
	p.stopWatch = context.AfterFunc(ctx, func() { _ = p.Kill() })
	go p.pump()
	return p, nil
}

// process is a running session on the client side.
type process struct {
	w      *wireConn
	merged bool
	// tty records that the session's stdin is a terminal, which has no separate
	// stream to close for EOF.
	tty bool
	// ctx is the caller's context, so a capture can say why the run ended.
	ctx context.Context
	// art is the per-call capture, nil when the run keeps none.
	art *artifact

	outR *io.PipeReader
	outW *io.PipeWriter
	errR *io.PipeReader
	errW *io.PipeWriter

	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool
	// stdinAccepted is the count the supervisor reported on the exit frame.
	stdinAccepted *int64

	code int
	err  error
	done chan struct{}
	// stopWatch releases the context cancellation hook.
	stopWatch func() bool
}

func (p *process) pump() {
	for {
		var f frame
		if err := p.w.read(&f); err != nil {
			p.finish(-1, err)
			return
		}
		switch f.Type {
		case frameStdout:
			if p.art != nil {
				_, _ = p.art.Stdout().Write(f.Data)
			}
			if _, err := p.outW.Write(f.Data); err != nil {
				p.finish(-1, err)
				return
			}
		case frameStderr:
			if p.art != nil {
				if aw := p.art.Stderr(); aw != nil {
					_, _ = aw.Write(f.Data)
				}
			}
			if p.errW != nil {
				if _, err := p.errW.Write(f.Data); err != nil {
					p.finish(-1, err)
					return
				}
			}
		case frameExit:
			p.stdinAccepted = f.StdinAccepted
			p.finish(f.Code, nil)
			return
		case frameError:
			p.finish(-1, frameErr(f))
			return
		}
	}
}

func (p *process) finish(code int, err error) {
	p.closeMu.Lock()
	if p.closed {
		p.closeMu.Unlock()
		return
	}
	p.closed = true
	p.code, p.err = code, err
	p.closeMu.Unlock()
	if p.stopWatch != nil {
		p.stopWatch()
	}
	if p.art != nil {
		var exit *int
		if err == nil {
			exit = &code
		}
		p.art.Finish(artifactFinish{
			ExitCode: exit, Outcome: p.outcome(err), Err: errText(err),
			StdinAccepted: p.stdinAccepted, Complete: err == nil,
		})
	}
	_ = p.outW.Close()
	if p.errW != nil {
		_ = p.errW.Close()
	}
	close(p.done)
}

// outcome names why the run ended, for the capture's manifest.
func (p *process) outcome(err error) string {
	if err == nil {
		return OutcomeExited
	}
	if p.ctx.Err() != nil {
		return contextOutcome(p.ctx)
	}
	return OutcomeTransportError
}

// ArtifactPointer returns the capture pointer of a finished run.
func (p *process) ArtifactPointer() string { return p.art.ArtifactPointer() }

func (p *process) Read(b []byte) (int, error) { return p.outR.Read(b) }

func (p *process) Write(b []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.w.write(frame{Type: frameStdin, Data: b}); err != nil {
		return 0, err
	}
	// Recorded after the frame reached the socket: the file holds what was
	// submitted, which is not what the program read.
	if p.art != nil {
		_, _ = p.art.Stdin().Write(b)
	}
	return len(b), nil
}

func (p *process) Stderr() io.Reader {
	if p.errR == nil {
		return nil
	}
	return p.errR
}

// CloseStdin gives the program EOF on stdin without ending the session, so a
// program that reads to EOF exits and Wait returns its own code. A terminal has
// no separate stdin to close, so the request is refused instead of guessed at.
func (p *process) CloseStdin() error {
	if p.tty {
		return ErrNoStdinEOF
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.w.write(frame{Type: frameStdinEOF}); err != nil {
		return err
	}
	p.art.SetEOF()
	return nil
}

func (p *process) Resize(rows, cols int) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.w.write(frame{Type: frameResize, Rows: rows, Cols: cols})
}

func (p *process) Wait() (int, error) {
	<-p.done
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	return p.code, p.err
}

// Kill asks the supervisor to terminate the session's whole process tree. The
// connection stays open so Wait returns only after the supervisor has torn the
// session down, which is what a caller needs before it reuses the workspace or
// reports the task finished.
func (p *process) Kill() error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.w.write(frame{Type: frameClose})
}

// Close ends the session and drops the connection immediately.
func (p *process) Close() error {
	_ = p.Kill()
	_ = p.w.c.Close()
	_ = p.outR.Close()
	if p.errR != nil {
		_ = p.errR.Close()
	}
	return nil
}

// ProcessOf returns the Process behind a Run result.
func ProcessOf(rwc io.ReadWriteCloser) (Process, bool) {
	p, ok := rwc.(Process)
	return p, ok
}

// FDRunner is a client that can hand descriptors to the program it starts.
type FDRunner interface {
	RunWithFiles(ctx context.Context, s netpolicy.Session, spec Spec, files []*os.File) (io.ReadWriteCloser, error)
}

// RunFiles starts a process with extra descriptors. A client that cannot pass
// descriptors is a capability error, never a silent fallback.
func RunFiles(c Client, ctx context.Context, s netpolicy.Session, spec Spec, files []*os.File) (io.ReadWriteCloser, error) {
	r, ok := c.(FDRunner)
	if !ok {
		return nil, &CapabilityError{Missing: []string{"descriptor-passing"}, Detail: "the installed client cannot pass descriptors"}
	}
	return r.RunWithFiles(ctx, s, spec, files)
}

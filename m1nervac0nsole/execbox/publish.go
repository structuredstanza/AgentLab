package execbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// Publication is how an installed tool survives its session. An install session
// writes into a writable staging prefix of its own; when the script succeeds the
// privileged supervisor moves the artifact into the persistent bin directory,
// which every session sees read-only on PATH. That directory is under /state, so
// a tool installed once is available to later sessions and later boots.
//
// The tool never publishes itself: the session uid cannot write the bin
// directory, so the move is the supervisor's, and it is part of the approved
// install rather than a second approval.

// Published is what the supervisor moved into the persistent bin directory.
type Published struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ErrNotStaged reports a publish whose source is absent: the install script
// staged nothing under $PREFIX/bin, so there is nothing to publish. It is not a
// failure of the boundary, and a caller that already had the tool reports the
// install as verified without a publication.
var ErrNotStaged = errors.New("execbox: no staged artifact to publish")

// Publisher is a client that can publish a staged install artifact. The
// supervisor implements it.
type Publisher interface {
	Publish(ctx context.Context, s netpolicy.Session, name string) (Published, error)
}

// PublishArtifact publishes a staged install artifact through a client that can
// publish. A client that cannot is a capability error, never a silent fallback
// to writing the bin directory from the backend.
func PublishArtifact(c Client, ctx context.Context, s netpolicy.Session, name string) (Published, error) {
	p, ok := c.(Publisher)
	if !ok {
		return Published{}, fmt.Errorf("%w: the execution client cannot publish an installed artifact", ErrUnavailable)
	}
	return p.Publish(ctx, s, name)
}

// Publish asks the supervisor to move one staged artifact into the persistent
// bin directory. The install session has ended by the time this runs, so the
// request names the session that staged it rather than attaching to it.
func (c *socketClient) Publish(ctx context.Context, s netpolicy.Session, name string) (Published, error) {
	w, err := c.dial(ctx)
	if err != nil {
		return Published{}, err
	}
	defer w.c.Close()
	stop := context.AfterFunc(ctx, func() { w.c.Close() })
	defer stop()
	if err := w.write(request{Op: opPublish, Session: sessionToWire(s), Publish: &publishRequest{Name: name}}); err != nil {
		return Published{}, fmt.Errorf("execbox: publish: %w", err)
	}
	var f frame
	if err := w.read(&f); err != nil {
		if ctx.Err() != nil {
			return Published{}, ctx.Err()
		}
		return Published{}, fmt.Errorf("execbox: publish: %w", err)
	}
	switch f.Type {
	case framePublished:
		if f.Published == nil {
			return Published{}, errors.New("execbox: publish: no result")
		}
		return *f.Published, nil
	case frameNotStaged:
		return Published{}, fmt.Errorf("%w: %s", ErrNotStaged, f.Message)
	case frameError:
		return Published{}, frameErr(f)
	}
	return Published{}, fmt.Errorf("execbox: publish: unexpected frame %q", f.Type)
}

// publish serves one publish request: only an install session may publish, and
// only a regular file it staged.
func (s *Supervisor) publish(w *wireConn, req request) {
	sess := sessionFromWire(req.Session)
	if sess.Purpose != netpolicy.PurposeInstall {
		_ = w.write(frame{Type: frameError, Message: "execbox: only an install session may publish a tool"})
		return
	}
	if req.Publish == nil {
		_ = w.write(frame{Type: frameError, Message: "execbox: publish needs an artifact name"})
		return
	}
	if !safeComponent(req.Publish.Name) {
		_ = w.write(frame{Type: frameError, Message: fmt.Sprintf("execbox: publish name %q is not a single file name", req.Publish.Name)})
		return
	}
	staging, err := s.stagingDir(sess.ID)
	if err != nil {
		_ = w.write(frame{Type: frameError, Message: err.Error()})
		return
	}
	pub, err := publishArtifact(staging, s.cfg.BinDir(), req.Publish.Name)
	if errors.Is(err, ErrNotStaged) {
		_ = w.write(frame{Type: frameNotStaged, Message: err.Error()})
		return
	}
	if err != nil {
		_ = w.write(frame{Type: frameError, Message: err.Error()})
		return
	}
	// The staged copy has served its purpose; the published one is what later
	// sessions use.
	_ = os.RemoveAll(staging)
	s.cfg.Logf("[execbox] published %s (%d bytes, sha256 %s)", pub.Path, pub.Size, pub.SHA256)
	_ = w.write(frame{Type: framePublished, Published: &pub})
}

// publishArtifact copies one staged file into the bin directory atomically: a
// temp name in the same directory, then a rename. The source must be a regular
// file inside the session's staging bin directory, so a symlink, a directory or
// a path outside staging cannot be published.
func publishArtifact(staging, binDir, name string) (Published, error) {
	if !safeComponent(name) {
		return Published{}, fmt.Errorf("execbox: publish refused: %q is not a single file name", name)
	}
	dir := filepath.Join(staging, "bin")
	// The session owns its staging prefix, so it can replace bin/ with a symlink
	// to somewhere else. Resolving the directory and requiring it to be the one
	// the supervisor created is what keeps the move inside staging.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return Published{}, fmt.Errorf("%w: %v", ErrNotStaged, err)
	}
	if resolved != dir {
		return Published{}, fmt.Errorf("execbox: publish refused: %s resolves to %s, outside the staging root", dir, resolved)
	}
	src := filepath.Join(dir, name)
	fi, err := os.Lstat(src)
	if errors.Is(err, os.ErrNotExist) {
		return Published{}, fmt.Errorf("%w: %s", ErrNotStaged, src)
	}
	if err != nil {
		return Published{}, fmt.Errorf("execbox: publish source: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Published{}, fmt.Errorf("execbox: publish refused: %s is not a regular file", src)
	}

	in, err := os.Open(src)
	if err != nil {
		return Published{}, fmt.Errorf("execbox: publish source: %w", err)
	}
	defer in.Close()
	tmp, err := os.CreateTemp(binDir, "."+name+".tmp-")
	if err != nil {
		return Published{}, fmt.Errorf("execbox: publish temp: %w", err)
	}
	tmpName := tmp.Name()
	digest := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, digest), in)
	if err == nil {
		err = tmp.Sync()
	}
	if err == nil {
		// 0755 is what makes it runnable by the session uid. The owner is root
		// by construction: the supervisor is the process that creates this file,
		// and it refuses to run as anything but root.
		err = tmp.Chmod(0o755)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmpName)
		return Published{}, fmt.Errorf("execbox: publish copy: %w", err)
	}
	dst := filepath.Join(binDir, name)
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return Published{}, fmt.Errorf("execbox: publish rename: %w", err)
	}
	return Published{Name: name, Path: dst, SHA256: hex.EncodeToString(digest.Sum(nil)), Size: size}, nil
}

// safeComponent reports whether s is usable as one path component: a session id
// or an artifact name, never a path.
func safeComponent(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// stagingDir is the writable prefix of one install session. The session id is
// server-issued, and it is still validated as a single path component here
// rather than trusted as one.
func (s *Supervisor) stagingDir(id string) (string, error) {
	if !safeComponent(id) {
		return "", fmt.Errorf("execbox: session id %q is not a usable staging name", id)
	}
	return filepath.Join(s.cfg.StagingRoot(), id), nil
}

// prepareStaging creates the writable prefix of an install session: a bin
// directory the script installs into, and a home and tmp so a script that writes
// $HOME/.config still works.
func prepareStaging(dir string) error {
	for _, sub := range []string{"bin", "home", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return fmt.Errorf("execbox: staging %s: %w", sub, err)
		}
	}
	return nil
}

// sweepStaging removes staging prefixes a previous supervisor left behind. A
// prefix only exists between an install session and its publication, so anything
// found at startup is a leftover from a crash or a refused install.
func (s *Supervisor) sweepStaging() {
	entries, err := os.ReadDir(s.cfg.StagingRoot())
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		_ = os.RemoveAll(filepath.Join(s.cfg.StagingRoot(), e.Name()))
	}
}

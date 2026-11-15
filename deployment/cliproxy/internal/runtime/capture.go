package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/privacy"
)

type turnKey struct{}
type turnIdentity struct{ binding contract.Binding }

const (
	// captureActiveName is the stream the process appends to. Rotation moves it
	// aside under a stamped name, so a file an export already copied is never
	// appended to again and `lab prune` can delete it without racing the writer.
	captureActiveName = "native-sse.ndjson"
	// captureSegmentBytes bounds one segment; a long engagement rotates instead
	// of growing a single file without limit.
	captureSegmentBytes = 64 << 20
)

type captureStore struct {
	mu       sync.Mutex
	dir      string
	file     *os.File
	size     int64
	limit    int64
	requests map[requestKey][]byte
}

type requestKey struct {
	provider contract.Provider
	profile  contract.ProfileID
	model    string
	session  string
}

func newCaptureStore(root string) (*captureStore, error) {
	dir := filepath.Join(root, "captures")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	c := &captureStore{dir: dir, limit: captureSegmentBytes, requests: make(map[requestKey][]byte)}
	if err := c.open(); err != nil {
		return nil, err
	}
	return c, nil
}

// open rotates whatever a previous run left behind, then starts a fresh active
// file: a restart must not append to a segment an export already captured.
func (c *captureStore) open() error {
	path := filepath.Join(c.dir, captureActiveName)
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return errors.New("capture stream is not a regular file")
	case err == nil && info.Size() > 0:
		if err := c.rotate(path); err != nil {
			return err
		}
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	c.file = f
	c.size = 0
	return nil
}

// rotate renames the active stream to an immutable segment and syncs the
// directory so the rename survives a crash.
func (c *captureStore) rotate(path string) error {
	target, err := c.segmentName()
	if err != nil {
		return err
	}
	if err := os.Rename(path, target); err != nil {
		return err
	}
	if dir, err := os.Open(c.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// segmentName reserves a unique immutable name beside the active stream.
func (c *captureStore) segmentName() (string, error) {
	for attempt := range 1000 {
		name := fmt.Sprintf("native-sse-%d.ndjson", time.Now().UnixNano())
		if attempt > 0 {
			name = fmt.Sprintf("native-sse-%d-%d.ndjson", time.Now().UnixNano(), attempt)
		}
		target := filepath.Join(c.dir, name)
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return target, nil
	}
	return "", errors.New("could not reserve a capture segment name")
}

// rotateActive closes the active stream, moves it aside and opens a new one.
func (c *captureStore) rotateActive() error {
	path := c.file.Name()
	if err := c.file.Sync(); err != nil {
		return err
	}
	if err := c.file.Close(); err != nil {
		return err
	}
	if err := c.rotate(path); err != nil {
		return err
	}
	return c.open()
}

func (c *captureStore) Record(rec privacy.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.size >= c.limit {
		if err := c.rotateActive(); err != nil {
			return errors.New("capture persistence failed")
		}
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return errors.New("capture persistence failed")
	}
	line = append(line, '\n')
	n, err := c.file.Write(line)
	c.size += int64(n)
	if err != nil {
		return errors.New("capture persistence failed")
	}
	if err := c.file.Sync(); err != nil {
		return errors.New("capture persistence failed")
	}
	if rec.Direction == privacy.DirectionRequest {
		key := requestKey{provider: rec.Provider, profile: rec.Profile, model: rec.Model, session: rec.SessionID}
		c.requests[key] = append(c.requests[key][:0], rec.Body...)
	}
	return nil
}

func (c *captureStore) captured(ctx context.Context) ([]byte, bool) {
	turn, ok := ctx.Value(turnKey{}).(turnIdentity)
	if !ok {
		return nil, false
	}
	b := turn.binding
	key := requestKey{provider: b.Provider, profile: b.Profile, model: b.Model, session: b.SessionID}
	c.mu.Lock()
	defer c.mu.Unlock()
	body, ok := c.requests[key]
	if !ok {
		return nil, false
	}
	delete(c.requests, key)
	return body, true
}

func (c *captureStore) clearProfile(profile contract.ProfileID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.requests {
		if key.profile == profile {
			delete(c.requests, key)
		}
	}
}

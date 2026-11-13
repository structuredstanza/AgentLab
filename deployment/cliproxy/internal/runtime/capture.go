package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/privacy"
)

type turnKey struct{}
type turnIdentity struct{ binding contract.Binding }

type captureStore struct {
	mu       sync.Mutex
	file     *os.File
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
	path := filepath.Join(dir, "native-sse.ndjson")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	return &captureStore{file: f, requests: make(map[requestKey][]byte)}, nil
}

func (c *captureStore) Record(rec privacy.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := json.NewEncoder(c.file).Encode(rec); err != nil {
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

// Package store keeps per-profile provider grants in a private host directory.
//
// Layout under the state dir (mode 0700):
//
//	<profile>/<provider>.json  grant envelope (mode 0600)
//	<profile>/<provider>.gen   generation counter (mode 0600)
//
// Nothing here is mounted into a guest and nothing here logs record contents.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/artex/cliproxyhost/internal/contract"
)

const (
	dirMode         = 0o700
	fileMode        = 0o600
	envelopeVersion = 1
)

var (
	ErrNotFound        = errors.New("grant not found")
	ErrStaleGeneration = errors.New("grant generation is stale")
	ErrInvalidRecord   = errors.New("invalid grant record")
	ErrUnknownProvider = errors.New("unknown provider")
	ErrNoStateDir      = errors.New("proxy state directory is required")
)

// Store implements contract.Store on a private directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

var _ contract.Store = (*Store)(nil)

// DefaultDir is the proxy-state directory under the host root.
func DefaultDir(root string) string {
	return filepath.Join(root, "proxy-state")
}

// New opens dir as the private state root, creating it with mode 0700.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, ErrNoStateDir
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create proxy state dir: %w", err)
	}
	// MkdirAll does not tighten a directory that already exists.
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("restrict proxy state dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// grantFile is the on-disk envelope. Raw is the validated native auth JSON.
type grantFile struct {
	Version    int             `json:"version"`
	CoreAuthID string          `json:"core_auth_id"`
	Email      string          `json:"email,omitempty"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Raw        json.RawMessage `json:"raw"`
}

// Load returns the stored grant, or ErrNotFound when none exists.
func (s *Store) Load(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (*contract.Record, error) {
	dir, err := s.locate(ctx, profile, provider)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return readGrant(dir, provider)
}

// Generation returns the current generation for one grant; 0 means no grant yet.
func (s *Store) Generation(profile contract.ProfileID, provider contract.Provider) (uint64, error) {
	dir, err := s.locate(context.Background(), profile, provider)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return readGen(dir, provider)
}

// Save replaces the grant when expectedGen matches the stored generation and
// returns the new generation. The grant is replaced first and the generation
// second. A crash between the two leaves the new grant under the old generation;
// the next Save with that generation overwrites it, so no stale grant is kept.
// Load can return the new grant while Generation still reports the old value.
func (s *Store) Save(ctx context.Context, profile contract.ProfileID, provider contract.Provider, expectedGen uint64, rec *contract.Record) (uint64, error) {
	dir, err := s.locate(ctx, profile, provider)
	if err != nil {
		return 0, err
	}
	body, err := encodeGrant(rec)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return 0, fmt.Errorf("create profile dir: %w", err)
	}
	cur, err := readGen(dir, provider)
	if err != nil {
		return 0, err
	}
	if cur != expectedGen {
		return 0, ErrStaleGeneration
	}
	next := cur + 1
	if err := writeFileAtomic(dir, string(provider)+".json", body); err != nil {
		return 0, err
	}
	if err := writeFileAtomic(dir, string(provider)+".gen", []byte(strconv.FormatUint(next, 10))); err != nil {
		return 0, err
	}
	return next, nil
}

// DeleteAll removes the profile directory and every grant in it.
func (s *Store) DeleteAll(ctx context.Context, profile contract.ProfileID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := s.profileDir(profile)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("delete profile grants: %w", err)
	}
	return syncDir(s.dir)
}

func (s *Store) locate(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, ok := contract.ParseProvider(string(provider)); !ok {
		return "", ErrUnknownProvider
	}
	return s.profileDir(profile)
}

// profileDir derives the directory only from a canonical profile ID, so no
// profile string can escape the state root.
func (s *Store) profileDir(profile contract.ProfileID) (string, error) {
	p, err := contract.ParseProfileID(string(profile))
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, string(p)), nil
}

func readGrant(dir string, provider contract.Provider) (*contract.Record, error) {
	raw, err := os.ReadFile(filepath.Join(dir, string(provider)+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read grant: %w", err)
	}
	var f grantFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != envelopeVersion {
		// The decode error is dropped: it can echo fragments of the grant.
		return nil, ErrInvalidRecord
	}
	return &contract.Record{
		CoreAuthID: f.CoreAuthID,
		Email:      f.Email,
		ExpiresAt:  f.ExpiresAt,
		Raw:        []byte(f.Raw),
	}, nil
}

func readGen(dir string, provider contract.Provider) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(dir, string(provider)+".gen"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read generation: %w", err)
	}
	gen, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, ErrInvalidRecord
	}
	return gen, nil
}

func encodeGrant(rec *contract.Record) ([]byte, error) {
	if rec == nil || rec.CoreAuthID == "" || len(rec.Raw) == 0 || !json.Valid(rec.Raw) {
		return nil, ErrInvalidRecord
	}
	return json.Marshal(grantFile{
		Version:    envelopeVersion,
		CoreAuthID: rec.CoreAuthID,
		Email:      rec.Email,
		ExpiresAt:  rec.ExpiresAt,
		Raw:        json.RawMessage(rec.Raw),
	})
}

// writeFileAtomic writes a temp file in dir, fsyncs it, renames it over name
// and fsyncs dir. The temp file is 0600 from CreateTemp; umask can only clear
// bits, so the mode cannot widen.
func writeFileAtomic(dir, name string, data []byte) (err error) {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("replace %s: %w", name, err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}

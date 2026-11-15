package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InlineEvidenceLimit is the size above which a finding's evidence is written to
// a file and referenced by path instead of being stored in the row.
//
// The column is TEXT and unbounded, so a raw HTTP exchange, a stack trace and a
// screenshot pasted as text all end up in the same table — which makes every
// list query that touches the row pay for bytes nobody is reading, and makes an
// export of one engagement drag the whole thing through memory. Evidence above
// this size is content-addressed on disk instead; the row keeps a path.
const InlineEvidenceLimit = 8 << 10

// findingEvidenceDir is the per-task directory holding spilled evidence. Keying
// it by task is what lets an archive or a delete carry the whole set at once.
func (s *Store) findingEvidenceDir(taskID int64) string {
	return filepath.Join(s.Dir, "findings", strconv.FormatInt(taskID, 10))
}

// WriteFindingEvidence stores a finding's evidence as a content-addressed file
// and returns the path relative to the evidence directory.
//
// Content addressing means the same evidence recorded twice (a retest, a
// re-import) writes one file, and the path doubles as an integrity check: the
// name is the digest of the content.
func (s *Store) WriteFindingEvidence(taskID int64, text string) (string, error) {
	if text == "" {
		return "", nil
	}
	sum := sha256.Sum256([]byte(text))
	digest := hex.EncodeToString(sum[:])
	dir := s.findingEvidenceDir(taskID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create evidence dir: %w", err)
	}
	path := filepath.Join(dir, digest+".txt")
	if _, err := os.Stat(path); err == nil {
		// Already recorded; content addressing makes the write unnecessary.
		return s.relPath(path), nil
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write evidence: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("sync evidence: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close evidence: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return "", fmt.Errorf("chmod evidence: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("publish evidence: %w", err)
	}
	return s.relPath(path), nil
}

// ReadFindingEvidence loads evidence previously written by
// WriteFindingEvidence. The path is validated against the store's directory so
// a tampered row cannot read outside it.
func (s *Store) ReadFindingEvidence(relPath string) (string, error) {
	if relPath == "" {
		return "", nil
	}
	clean := filepath.Clean(relPath)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("evidence path %q escapes the store", relPath)
	}
	full := filepath.Join(s.Dir, clean)
	root, err := filepath.EvalSymlinks(s.Dir)
	if err == nil {
		resolved, err := filepath.EvalSymlinks(full)
		if err == nil && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			return "", fmt.Errorf("evidence path %q escapes the store", relPath)
		}
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Store) relPath(full string) string {
	if rel, err := filepath.Rel(s.Dir, full); err == nil {
		return rel
	}
	return full
}

// CopyFindingEvidence copies one task's spilled evidence into dest, the archive
// payload's evidence directory, so a portable package carries the proof its
// findings rows still point at. A task with nothing spilled copies nothing.
func (s *Store) CopyFindingEvidence(taskID int64, dest string) error {
	src := s.findingEvidenceDir(taskID)
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.CopyFS(filepath.Join(dest, "findings", strconv.FormatInt(taskID, 10)), os.DirFS(src))
}

// InstallFindingEvidence puts a task's spilled evidence back from an extracted
// archive package; the restored findings rows still carry their evidence_path.
func (s *Store) InstallFindingEvidence(taskID int64, source string) error {
	src := filepath.Join(source, "findings", strconv.FormatInt(taskID, 10))
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dst := s.findingEvidenceDir(taskID)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return fmt.Errorf("create evidence dir: %w", err)
	}
	return os.CopyFS(dst, os.DirFS(src))
}

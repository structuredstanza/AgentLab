// Package evidence preserves finding evidence independently of disposable traffic.
package evidence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/traffic"
)

type Store struct {
	DB      *db.DB
	Traffic *traffic.Traffic
	Dir     string
}

func New(pg *db.DB, tr *traffic.Traffic, dir string) *Store {
	return &Store{DB: pg, Traffic: tr, Dir: dir}
}

func hashPath(dir, hash string) (string, error) {
	if len(hash) != 64 {
		return "", errors.New("invalid evidence hash")
	}
	if _, err := hex.DecodeString(hash); err != nil || strings.ToLower(hash) != hash {
		return "", errors.New("invalid evidence hash")
	}
	return filepath.Join(dir, "blobs", hash[:2], hash+".bin"), nil
}

func verifyFile(path, hash string, length int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != length || hex.EncodeToString(h.Sum(nil)) != hash {
		return fmt.Errorf("evidence body verification failed: %s", hash)
	}
	return nil
}

// A new body becomes visible only after a durable write. Failed SQL commits may
// leave unreferenced files; GC reaps those after a full day's grace period.
func (s *Store) writeBody(r io.Reader, expectedLength int64, expectedHash string) (hash string, err error) {
	stage := filepath.Join(s.Dir, ".staging")
	if err = os.MkdirAll(stage, 0o700); err != nil {
		return
	}
	f, err := os.CreateTemp(stage, "body-")
	if err != nil {
		return "", err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return "", err
	}
	hash = hex.EncodeToString(h.Sum(nil))
	if n != expectedLength {
		return "", fmt.Errorf("body incomplete: expected %d bytes, read %d bytes", expectedLength, n)
	}
	if expectedHash != "" && expectedHash != hash {
		return "", errors.New("captured traffic body hash mismatch")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return "", err
	}
	if _, err = os.Stat(path); err == nil {
		if err = verifyFile(path, hash, n); err != nil {
			return "", err
		}
		// Refresh the grace period for a restored but not-yet-committed body.
		now := time.Now()
		return hash, os.Chtimes(path, now, now)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer d.Close()
	return hash, d.Sync()
}

// StageFindingsExport freezes bindings/report versions and makes private body
// copies before the HTTP response is started. The caller owns and removes dest.
//
// The lock covers the metadata read only. copySnapshots is O(total body size),
// so holding the process-wide evidence lock across it would stall every evidence
// write for the length of a download; the copied blobs stay readable because
// they are content-addressed and GC keeps unreferenced files for 24h.
func (s *Store) StageFindingsExport(ctx context.Context, findings []*db.DBFinding, dest string, copyBodies bool) error {
	var snapshots []db.TrafficEvidenceSnapshot
	err := s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		for _, f := range findings {
			list, err := db.FindingTrafficTx(tx, f.ID)
			if err != nil {
				return err
			}
			f.TrafficBindings = list.Bindings
			f.TrafficCount = len(list.Bindings)
			f.EvidenceVersion = list.Version
			f.ReportEvidenceVersion = list.ReportVersion
			if err = tx.QueryRow(`SELECT report FROM findings WHERE id=$1`, f.ID).Scan(&f.Report); err != nil {
				return err
			}
			for _, b := range list.Bindings {
				snapshots = append(snapshots, b.Snapshot)
			}
		}
		return nil
	})
	if err != nil || !copyBodies {
		return err
	}
	return s.copySnapshots(snapshots, dest)
}

func (s *Store) prepare(ctx context.Context, refs []db.TrafficRef) ([]db.PreparedTrafficEvidence, error) {
	refs, err := db.NormalizeTrafficRefs(refs)
	if err != nil {
		return nil, err
	}
	out := make([]db.PreparedTrafficEvidence, 0, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	ids := make([]string, len(refs))
	byID := map[string]db.TrafficRef{}
	for i, ref := range refs {
		ids[i] = ref.TrafficID
		byID[ref.TrafficID] = ref
	}
	err = s.Traffic.ReadEvidence(ctx, ids, func(e traffic.EvidenceExchange) error {
		rh, err := s.writeBody(e.Request, e.ReqLen, e.ReqHash)
		if err != nil {
			return err
		}
		ph, err := s.writeBody(e.Response, e.RespLen, e.RespHash)
		if err != nil {
			return err
		}
		v := db.TrafficEvidenceSnapshot{SourceTrafficID: e.ID, CapturedAt: e.TS, URL: e.URL, Method: e.Method, Status: e.Status, ContentType: e.ContentType,
			ReqHead: e.ReqHead, RespHead: e.RespHead, ReqHash: rh, RespHash: ph, ReqLen: e.ReqLen, RespLen: e.RespLen}
		// Raw wire bytes: normalize once here so the ID, the stored row and every
		// downstream consumer (archive, API responses) all see the same text.
		v = v.Normalize()
		v.ID = db.TrafficSnapshotID(v)
		out = append(out, db.PreparedTrafficEvidence{Ref: byID[e.ID], Snapshot: v})
		return nil
	})
	return out, err
}

func (s *Store) Record(ctx context.Context, in db.RecordFindingInput, refs []db.TrafficRef) (out *db.RecordedFinding, err error) {
	// Evidence above the inline limit is written to disk before the transaction
	// opens: a file write inside a transaction that then rolls back would leave
	// an orphan, and the path is only recorded once the row commits.
	spilledPath := ""
	if len(in.Evidence) > InlineEvidenceLimit {
		spilledPath, err = s.WriteFindingEvidence(in.TaskID, in.Evidence)
		if err != nil {
			return nil, err
		}
		in.Evidence = ""
	}
	err = s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockTaskEvidenceTx(tx, in.TaskID); err != nil {
			return err
		}
		prepared, err := s.prepare(ctx, refs)
		if err != nil {
			return err
		}
		out, err = db.RecordFindingTx(ctx, tx, in, prepared)
		if err != nil {
			return err
		}
		if spilledPath != "" {
			if err := db.SetFindingEvidencePathTx(tx, out.FindingID, spilledPath); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (s *Store) Bind(ctx context.Context, findingID int64, refs []db.TrafficRef) (out *db.FindingTraffic, err error) {
	err = s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockFindingEvidenceTx(tx, findingID, nil); err != nil {
			return err
		}
		prepared, err := s.prepare(ctx, refs)
		if err != nil {
			return err
		}
		if err = db.AddFindingTrafficTx(tx, findingID, prepared); err != nil {
			return err
		}
		out, err = db.FindingTrafficTx(tx, findingID)
		return err
	})
	return
}

func (s *Store) WithBinding(ctx context.Context, findingID, bindingID int64, fn func(db.FindingTrafficBinding) error) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		list, err := db.FindingTrafficTx(tx, findingID)
		if err != nil {
			return err
		}
		for _, b := range list.Bindings {
			if b.ID == bindingID {
				return fn(b)
			}
		}
		return db.ErrEvidenceNotFound
	})
}

// Binding resolves one binding's metadata under the evidence lock and releases
// the lock before returning. Callers that then stream a body to a client must
// use this instead of WithBinding: verifyFile+io.Copy is O(body size), so a
// large download (or a slow client) holding WithEvidenceTx would block every
// evidence write process-wide. Reading the blob afterwards is safe — blobs are
// content-addressed and GC only reaps unreferenced files after a 24h grace
// period, and an already-open fd survives an unlink regardless.
func (s *Store) Binding(ctx context.Context, findingID, bindingID int64) (db.FindingTrafficBinding, error) {
	var out db.FindingTrafficBinding
	err := s.WithBinding(ctx, findingID, bindingID, func(b db.FindingTrafficBinding) error {
		out = b
		return nil
	})
	return out, err
}

// OpenBody may be called without holding the evidence lock; see Binding.
func (s *Store) OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error) {
	hash, length := snapshot.ReqHash, snapshot.ReqLen
	if side == "response" {
		hash, length = snapshot.RespHash, snapshot.RespLen
	} else if side != "request" {
		return nil, 0, errors.New("side must be request or response")
	}
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return nil, 0, err
	}
	if err = verifyFile(path, hash, length); err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	return f, length, err
}

// CopySnapshots is used by both report downloads and portable task archives.
// The destination owns real copies, never links into either disposable store.
// The copy runs outside the evidence lock (see StageFindingsExport): it is
// O(body size) and every blob it reads is still referenced, so GC keeps it.
func (s *Store) CopySnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, dest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.copySnapshots(snapshots, dest)
}

func (s *Store) copySnapshots(snapshots []db.TrafficEvidenceSnapshot, dest string) error {
	for _, v := range snapshots {
		for _, side := range []string{"request", "response"} {
			if err := func() error {
				f, length, err := s.OpenBody(v, side)
				if err != nil {
					return err
				}
				defer f.Close()
				hash := v.ReqHash
				if side == "response" {
					hash = v.RespHash
				}
				target, err := hashPath(dest, hash)
				if err != nil {
					return err
				}
				if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					return err
				}
				out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
				if os.IsExist(err) {
					return verifyFile(target, hash, length)
				}
				if err != nil {
					return err
				}
				_, copyErr := io.Copy(out, f)
				syncErr := out.Sync()
				closeErr := out.Close()
				return errors.Join(copyErr, syncErr, closeErr)
			}(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) InstallSnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, source string) error {
	return s.WithInstalledSnapshots(ctx, snapshots, source, func() error { return nil })
}

// WithInstalledSnapshots pins installed bodies until the metadata restore finishes.
// The callback must not acquire another evidence advisory lock.
func (s *Store) WithInstalledSnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, source string, restore func() error) error {
	return s.DB.WithEvidenceTx(ctx, func(*sql.Tx) error {
		for _, v := range snapshots {
			if v.ID != db.TrafficSnapshotID(v) {
				return errors.New("archived evidence snapshot metadata hash mismatch")
			}
			for _, body := range []struct {
				hash   string
				length int64
			}{{v.ReqHash, v.ReqLen}, {v.RespHash, v.RespLen}} {
				if err := func() error {
					path, err := hashPath(source, body.hash)
					if err != nil {
						return err
					}
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()
					_, err = s.writeBody(f, body.length, body.hash)
					return err
				}(); err != nil {
					return err
				}
			}
		}
		return restore()
	})
}

func (s *Store) Collect(ctx context.Context, now time.Time) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots s SET unreferenced_at=$1
WHERE unreferenced_at IS NULL AND NOT EXISTS(SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id=s.id)`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM traffic_evidence_snapshots s WHERE unreferenced_at<$1
AND NOT EXISTS(SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id=s.id)`, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT req_hash FROM traffic_evidence_snapshots UNION SELECT resp_hash FROM traffic_evidence_snapshots`)
		if err != nil {
			return err
		}
		refs := map[string]bool{}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return err
			}
			refs[hash] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, root := range []string{filepath.Join(s.Dir, "blobs"), filepath.Join(s.Dir, ".staging")} {
			err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if os.IsNotExist(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				if refs[strings.TrimSuffix(entry.Name(), ".bin")] {
					return nil
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if now.Sub(info.ModTime()) < 24*time.Hour {
					return nil
				}
				return os.Remove(path)
			})
			if err != nil {
				return err
			}
		}
		// Spilled finding evidence is referenced by findings.evidence_path, not by
		// a snapshot row: a task delete, or a write whose commit failed, leaves the
		// file behind. Reap what no row points at after the same grace period.
		rows, err = tx.Query(`SELECT evidence_path FROM findings WHERE evidence_path <> ''`)
		if err != nil {
			return err
		}
		referenced := map[string]bool{}
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err != nil {
				rows.Close()
				return err
			}
			referenced[filepath.Clean(path)] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		// A pinned pcap is named in the finding's evidence text, not by a path
		// column, so it lives as long as its task still has findings. Deleting
		// the task nulls findings.task_id, which releases the slices to the reap below.
		rows, err = tx.Query(`SELECT DISTINCT task_id FROM findings WHERE task_id IS NOT NULL`)
		if err != nil {
			return err
		}
		pinnedTasks := map[string]bool{}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			pinnedTasks[strconv.FormatInt(id, 10)] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return filepath.WalkDir(filepath.Join(s.Dir, "findings"), func(path string, entry fs.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(s.Dir, path)
			if err != nil {
				return err
			}
			if referenced[rel] || (strings.HasSuffix(rel, ".pcap") && pinnedTasks[filepath.Base(filepath.Dir(rel))]) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if now.Sub(info.ModTime()) < 24*time.Hour {
				return nil
			}
			return os.Remove(path)
		})
	})
}

func (s *Store) RunGC(ctx context.Context) {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			if err := s.Collect(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[evidence] cleanup failed: %v", err)
			}
		}
	}
}

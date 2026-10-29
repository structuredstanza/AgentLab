package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// smokeEnv lets the child process launched by the smoke test skip Bootstrap directly.
//
// Strictly speaking, not adding it would not cause problems: the child process's os.Executable() is artex.new, and the derived
// All paths carry the .new prefix, so the real upgrade file is never touched. But relying on this coincidence is too fragile.
// An explicit short-circuit is clear at a glance, and also saves the subprocess an unnecessary disk probe.
const smokeEnv = "ARTEX_SELFUPDATE_SMOKE"

// Action is the instruction that Bootstrap gives to main.
type Action int

const (
	// Continue: start the server as usual.
	Continue Action = iota
	// Restart: exit immediately with ExitRestart so the supervisor script relaunches the process.
	Restart
)

// State describes the upgrade status at this startup, so that /api/update/check can truthfully tell the frontend
// whether the previous upgrade succeeded or was rolled back.
type State struct {
	Pending     bool   // Swapped in, but not yet confirmed stable
	RolledBack  bool   // An automatic rollback was just performed during this startup.
	FailedStage bool   // The staged file failed verification/smoke test and was discarded.
	Detail      string // One-sentence description for the user.
}

// Bootstrap runs at the very beginning of main and must be called before any port is listened on or any database is opened.
//
// Three situations:
//
//	① If a staged file artex.new exists → verify and smoke-test it; if it passes, swap it in and require a restart; if it fails, discard it and keep running the old version.
//	② Only the marker file remains → this means the swap just completed; count one attempt, and roll back if there have been enough consecutive failures.
//	③ Nothing is present → normal startup.
func Bootstrap() (Action, State) {
	if os.Getenv(smokeEnv) != "" {
		return Continue, State{}
	}
	p, err := ResolvePaths()
	if err != nil {
		log.Printf("[update] Skipping self-bootstrap: %v", err)
		return Continue, State{}
	}

	if _, err := os.Stat(p.New); err == nil {
		return applyStaged(p)
	}

	m, ok := readMarker(p.Marker)
	if !ok {
		return Continue, State{}
	}
	return confirmOrRollback(p, m)
}

// applyStaged handles the case where a staged file exists: if verification passes, swap it in; if it fails, discard it.
//
// This is the only place in the whole upgrade chain that overwrites the executable, and also the last gate. The smoke test catches
// problems such as a corrupted download, the wrong architecture, or missing dynamic libraries. If a binary that cannot run gets through,
// the guard script will tirelessly keep relaunching it, and the Go code will never get a chance to run, so automatic rollback is out of the question.
func applyStaged(p Paths) (Action, State) {
	m, _ := readMarker(p.Marker)

	if err := verifyStaged(p); err != nil {
		log.Printf("[update] Staged new version failed verification and was discarded; continuing to run the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "New version failed verification and was discarded: " + err.Error()}
	}

	if err := swap(p); err != nil {
		log.Printf("[update] Swap failed; continuing to run the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "Failed to swap versions: " + err.Error()}
	}

	// The swap succeeded. Keep the marker and leave it to the next startup (which runs the new version) to confirm whether it is stable.
	m.Attempts = 0
	if m.StagedAt == 0 {
		m.StagedAt = time.Now().Unix()
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] Failed to write upgrade marker (automatic rollback capability lost): %v", err)
	}
	log.Printf("[update] Swapped to %s; exiting to restart (exit %d)", orUnknown(m.To), ExitRestart)
	return Restart, State{Pending: true}
}

// confirmOrRollback handles the "startup after swap": it counts attempts, and if the limit is exceeded, swaps the old version back in.
//
// The counter is only incremented after the Go code has actually started running, so it covers failures where the binary can execute but crashes during initialization
// (incompatible config, port already in use, DB migration blowing up). "Cannot exec at all" is handled by the
// The smoke test blocks, and the two together make the complete check.
func confirmOrRollback(p Paths, m marker) (Action, State) {
	m.Attempts++
	if m.Attempts > maxAttempts {
		if err := rollback(p); err != nil {
			// If the rollback itself has failed, don't restart again, otherwise it will fall into an endless restart loop. Clear the marker,
			// and let the process start with its current state. If it fails to start, the user can at least see the cause in the logs.
			log.Printf("[update] New version failed to start %d times in a row, and rollback failed: %v", maxAttempts, err)
			_ = os.Remove(p.Marker)
			return Continue, State{Detail: "New version failed to start and rollback also failed: " + err.Error()}
		}
		log.Printf("[update] New version failed to start %d times in a row; rolled back to %s; exiting to restart (exit %d)",
			maxAttempts, orUnknown(m.From), ExitRestart)
		_ = os.Remove(p.Marker)
		return Restart, State{RolledBack: true, Detail: fmt.Sprintf("New version failed to start; rolled back to the previous version (%s)", orUnknown(m.From))}
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] Failed to update upgrade marker: %v", err)
	}
	log.Printf("[update] New version starting (attempt %d/%d); the upgrade will be confirmed after a stable run",
		m.Attempts, maxAttempts)
	return Continue, State{Pending: true}
}

// Settle confirms that the new version is running stably and clears the upgrade marker.
//
// Called with a delay by main after the HTTP listener starts. The version only counts as healthy if it survives this period; otherwise the marker stays in place,
// so the next startup keeps accumulating the attempt count until a rollback is triggered.
func Settle() {
	p, err := ResolvePaths()
	if err != nil {
		return
	}
	settle(p)
}

func settle(p Paths) {
	if _, ok := readMarker(p.Marker); !ok {
		return // This is not a startup following an upgrade, so there is nothing to do.
	}
	if err := os.Remove(p.Marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[update] Failed to clear upgrade marker: %v", err)
		return
	}
	log.Printf("[update] New version running stably; upgrade complete (previous version kept as %s)", p.Old)
}

// SettleDelay is the runtime duration required to judge that the "new version has survived."
const SettleDelay = 30 * time.Second

// verifyStaged checks the staged file: it first compares the SHA256, then actually launches it and runs it once.
func verifyStaged(p Paths) error {
	want, err := os.ReadFile(p.Sum)
	if err != nil {
		return fmt.Errorf("failed to read checksum: %w", err)
	}
	got, err := fileSHA256(p.New)
	if err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(want)), got) {
		return errors.New("SHA256 does not match (download is corrupted or tampered)")
	}
	return smokeTest(p.New)
}

// smokeTest launches the new binary with -h to confirm it can really execute on the current system.
// This catches a broad class of problems, including truncated downloads, wrong architecture (exec format error), and missing dependencies.
func smokeTest(bin string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("failed to grant execute permission: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-h")
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return errors.New("smoke test timed out (new binary did not respond)")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("smoke test failed: %v: %s", err, snippet)
	}
	return nil
}

// swap replaces the current binary with the staged new version.
//
// Both Unix and Windows allow rename on a running executable file (what Windows forbids is deleting and
// overwriting it, but rename is not in that list), so there is no need to branch by platform here, and no need to stop the current process first.
func swap(p Paths) error {
	// On Windows, rename does not overwrite an existing target, so the .old file left behind by the previous upgrade must be removed first.
	if err := os.Remove(p.Old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to clean up previous backup %s: %w", p.Old, err)
	}
	if err := os.Rename(p.Current, p.Old); err != nil {
		return fmt.Errorf("failed to back up current version: %w", err)
	}
	if err := os.Rename(p.New, p.Current); err != nil {
		// If the swap fails after the current version has already been moved aside, it must be put back in place; otherwise there is no executable to start next time.
		if rerr := os.Rename(p.Old, p.Current); rerr != nil {
			return fmt.Errorf("new version installation failed (%v), and recovery of the current version also failed: %w", err, rerr)
		}
		return fmt.Errorf("new version installation failed: %w", err)
	}
	_ = os.Remove(p.Sum)
	return nil
}

// rollback swaps the old version kept in the swap backup back into place.
func rollback(p Paths) error {
	if _, err := os.Stat(p.Old); err != nil {
		return fmt.Errorf("no backup to roll back to (%s): %w", p.Old, err)
	}
	// Move the new version that fails to start to .failed for investigation, rather than deleting it outright.
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(p.Current, failed); err != nil {
		return fmt.Errorf("failed to move failed version: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		return fmt.Errorf("failed to restore previous version: %w", err)
	}
	return nil
}

// Rollback is the implementation of /api/update/rollback: it actively reverts to the previous version.
// It only swaps the files in; the restart is likewise left to the guardian script (the caller then exits with ExitRestart).
func Rollback() error {
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Old); err != nil {
		return errors.New("no previous version to roll back to (" + p.Old + " not found)")
	}
	cleanStaged(p)
	if err := smokeTest(p.Old); err != nil {
		return fmt.Errorf("cannot run the previous version; refusing rollback: %w", err)
	}
	// Swap the current and backup versions, so that a rollback can itself be rolled back.
	tmp := p.Current + ".swap"
	_ = os.Remove(tmp)
	if err := os.Rename(p.Current, tmp); err != nil {
		return fmt.Errorf("failed to move current version: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		_ = os.Rename(tmp, p.Current)
		return fmt.Errorf("failed to install previous version: %w", err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		log.Printf("[update] Failed to tidy backup after rollback (does not affect running): %v", err)
	}
	_ = os.Remove(p.Marker)
	return nil
}

// HasBackup reports whether a previous version exists that can be rolled back to, so the frontend can decide whether to show the rollback button.
func HasBackup() bool {
	p, err := ResolvePaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(p.Old)
	return err == nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown version"
	}
	return s
}

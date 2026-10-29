// Package selfupdate implements ARTEX's one-click page update: fetching the new version from a GitHub Release
// binary, verifying it, staging it, and atomically swapping it in on the next startup.
//
// Division of responsibilities (see start.sh / start.bat):
//
//	Startup scripts = a dumb supervisor loop that only decides, based on the exit code, whether to relaunch after the process exits
//	This package    = all the error-prone logic (download / SHA256 verification / smoke test / swap-in / rollback on failure)
//
// The binary swap is done in Go rather than in a script because the sha256 checksum and smoke test behave differently on sh and bat,
// have to be written twice, for sh and bat (sha256sum / shasum / certutil), and this is exactly the step that must not go wrong: swapping in a
// A binary that won't run: the daemon faithfully keeps relaunching it, and the only way out is for a user to step in and fix it by hand on the machine.
//
// A complete upgrade goes through three process starts:
//
//	① The old server receives /api/update/apply → downloads and verifies → stages artex.new → exit 75
//	② The script relaunches the old version → Bootstrap finds artex.new → verifies + smoke-tests → swaps it in → exit 75
//	③ The script relaunches; the new version is now running → Bootstrap records one attempt → clears the marker after a successful start
//
// If any step fails, fall back to the old version: at ②, if verification fails, delete the staged file and keep running the old version; at ③, if 3 consecutive attempts fail to survive until the marker is cleared (i.e., it crashes on startup), automatically swap artex.old back in.
// and if the marker is cleared (the new binary fails to start and crashes), artex.old is automatically swapped back into place.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExitRestart is the exit code meaning "ask the daemon to relaunch me" (EX_TEMPFAIL). When the startup script sees it
// Restart immediately without counting toward crash backoff. Exit code 0 means the user stopped normally (the script exited its loop); anything else is treated as a crash.
const ExitRestart = 75

// maxAttempts is the number of startup attempts allowed after the swap. Each new-version launch increments the counter by 1; if it survives
// settleDelay then clears the marker; crashing maxAttempts times in a row means the new version cannot start at all, so it rolls back automatically.
const maxAttempts = 3

// Paths holds all files involved in one upgrade, all placed under the **directory containing the executable**.
// CWD is deliberately not used: when running as a service, the working directory may be / or any arbitrary path, and using CWD would cause the staged files to land
// somewhere else, which would break the swap logic outright.
type Paths struct {
	Dir     string // Directory containing the executable
	Current string // Currently running binary        artex      / artex.exe
	New     string // Staged new version      artex.new  / artex.new.exe
	Sum     string // new version's sha256 (hex)  artex.new.sha256 / artex.new.exe.sha256
	Old     string // Old version backed up before the swap      artex.old  / artex.old.exe
	Marker  string // Upgrade status marker      artex.upgrade.json
}

// ResolvePaths derives all upgrade paths from the current executable.
//
// On Windows, .new/.old must also carry the .exe suffix, otherwise the smoke test and the executable after the swap will both fail,
// so the suffix is stripped first before concatenating, which keeps the naming symmetric across both platforms.
func ResolvePaths() (Paths, error) {
	exe, err := os.Executable()
	if err != nil {
		return Paths{}, fmt.Errorf("failed to determine executable location: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	name := filepath.Base(exe)
	ext := filepath.Ext(name) // ".exe" on Windows, usually empty on Unix
	stem := strings.TrimSuffix(name, ext)

	join := func(suffix string) string { return filepath.Join(dir, stem+suffix+ext) }
	return Paths{
		Dir:     dir,
		Current: exe,
		New:     join(".new"),
		Sum:     join(".new") + ".sha256",
		Old:     join(".old"),
		Marker:  filepath.Join(dir, stem+".upgrade.json"),
	}, nil
}

// marker records the progress of a swap so that an automatic rollback can be triggered if the new version fails to start.
type marker struct {
	From     string `json:"from"`     // Version before the upgrade
	To       string `json:"to"`       // Target version
	Attempts int    `json:"attempts"` // Number of startup attempts made after the swap
	StagedAt int64  `json:"staged_at"`
}

func readMarker(path string) (marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

func writeMarker(path string, m marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cleanStaged removes the staged files. It is called whenever the swap succeeds, the checksum fails, or the user cancels, so that no leftover
// artex.new is retried on the next startup.
func cleanStaged(p Paths) {
	_ = os.Remove(p.New)
	_ = os.Remove(p.Sum)
}

// CompareVersions compares two version numbers and returns -1/0/1 (a<b / a==b / a>b).
// ok=false means at least one side is not a comparable version number (for example a local development build "dev" or
// git describe output such as "0.3.7-2-gabc1234-dirty"), in which case callers should disable one-click update,
// Otherwise a development build would be "upgraded" to the official release, overwriting uncommitted changes.
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion parses version strings of the form "v0.3.7" / "0.3.7" into [3]int.
//
// Only accept a clean three-part version: build.sh produces it via git describe for non-tag builds
// suffixed versions such as "0.3.7-2-gabc1234", which must be judged incomparable rather than treated as
// 0.3.7 —— otherwise a development build would be misjudged as "already up to date" or overwritten by the official release.
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker reports whether the process is running inside a container. Under Docker, the swapped-in files are written to the container's writable layer,
// and recreating the container with `docker compose up -d` reverts to the version baked into the image. This is the expected behavior.
// (at that point the user was already pulling the new image), but the frontend must be able to explain this clearly based on it.
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}

package server

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/internal/testlock"
)

// TestMain holds the shared cross-package suite lock (testlock.LockKey) for the
// entire server test suite so cross-package DELETE cleanup races with the db and
// agent packages are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	// The execution-boundary test starts a real supervisor, which re-executes
	// this binary as the session child. A test binary stands in for the product
	// binary because the supervisor starts os.Executable().
	if len(os.Args) > 2 && os.Args[1] == "execbox" && os.Args[2] == execbox.ChildMode {
		os.Exit(execbox.RunChild(os.Args[3:]))
	}
	// server.New starts the realtime notifier's background delivery loop
	// (notifyTick) unless this env var is set. The notify integration tests
	// drive stepRealtime/stepDigest directly (see newNotifyFixture) and only
	// that fixture disabled the loop per-test. Other tests construct a server
	// with a live context.Background() that is never cancelled, so their
	// notifier goroutine leaks and keeps ticking for the rest of the binary;
	// when it fires inside a later test's window it claims that test's
	// deliveries out of band and corrupts the exact per-delivery attempt
	// accounting. That is what made TestNotifyDeliveriesHistoryAndRetry flake
	// intermittently ("after retries are exhausted it should be failed, but got pending"). No test asserts on the
	// background loop itself, so disable it suite-wide for determinism; the
	// loop's dispatch is covered through direct stepRealtime/stepDigest calls.
	os.Setenv(notifyBackgroundDisabledEnv, "1")

	dsn, _, err := db.DSN()
	if err != nil {
		dsn = "" // no DB configured — DB-backed tests skip themselves
	}
	os.Exit(testlock.Run(dsn, m.Run))
}

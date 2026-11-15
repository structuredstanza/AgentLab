package db

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/internal/testlock"
)

// TestMain holds the shared cross-package suite lock (testlock.LockKey) for the
// entire db test suite. Packages agent, enrich, guard, intercept, llmrec,
// server and evidence hold the same lock, so parallel `go test ./...` runs
// serialize across packages on the shared dev DB and avoid cross-package
// cleanup races (e.g. DELETE FROM assets WHERE id > X from one package deleting
// assets created by another).
func TestMain(m *testing.M) {
	dsn, _, err := DSN()
	if err != nil {
		dsn = "" // no DB configured — tests that need PG skip themselves
	}
	os.Exit(testlock.Run(dsn, m.Run))
}

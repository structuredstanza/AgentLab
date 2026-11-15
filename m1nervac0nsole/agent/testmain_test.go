package agent

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/internal/testlock"
)

// TestMain holds the shared cross-package suite lock (testlock.LockKey) for the
// entire agent test suite so cross-package DELETE cleanup races with the db and
// server packages are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		dsn = "" // no DB configured — tests that need PG skip themselves
	}
	os.Exit(testlock.Run(dsn, m.Run))
}

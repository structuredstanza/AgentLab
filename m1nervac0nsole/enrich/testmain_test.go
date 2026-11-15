package enrich

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/internal/testlock"
)

// TestMain holds the same cross-package suite lock (testlock.LockKey) that the
// db, agent and server suites hold, so a parallel `go test ./...` run serializes
// on the shared dev database instead of racing this package's cleanup deletes
// against theirs.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		dsn = "" // no DB configured — tests that need PG skip themselves
	}
	os.Exit(testlock.Run(dsn, m.Run))
}

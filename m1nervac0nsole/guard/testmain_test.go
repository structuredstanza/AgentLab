package guard

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/internal/testlock"
)

// TestMain holds the same cross-package suite lock (testlock.LockKey) that
// agent, db, evidence and server hold. Without it this package's DB-backed tests
// run concurrently with another package's, and a schema migration (which takes
// an AccessExclusiveLock) can deadlock against an activity insert.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		dsn = "" // no DB configured — DB-backed tests skip themselves
	}
	os.Exit(testlock.Run(dsn, m.Run))
}

package evidence

import (
	"os"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/internal/testlock"
)

// TestMain initializes an explicitly configured fresh database (schema included)
// before taking the same cross-package suite lock (testlock.LockKey) that db,
// agent and server hold, so the suite never runs its schema init unlocked.
func TestMain(m *testing.M) {
	dsn := os.Getenv("M1NERVAC0NSOLE_PG_DSN")
	if dsn == "" {
		os.Exit(m.Run())
	}
	pg, err := db.Open(dsn)
	if err != nil {
		panic(err)
	}
	pg.Close()
	os.Exit(testlock.Run(dsn, m.Run))
}

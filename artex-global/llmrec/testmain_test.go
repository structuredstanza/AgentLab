package llmrec

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Autumn-27/artex/db"
)

// TestMain acquires the same PostgreSQL advisory lock (7337741002) that agent,
// db, evidence and server hold. Without it this package's DB-backed tests run
// concurrently with another package's, and a schema migration (which takes an
// AccessExclusiveLock) can deadlock against an activity insert.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run()) // no DB configured — DB-backed tests skip themselves
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	os.Exit(m.Run())
}

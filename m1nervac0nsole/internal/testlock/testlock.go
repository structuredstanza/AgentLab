// Package testlock serializes the DB-backed test suites that share one
// PostgreSQL database.
//
// Each such suite holds the same advisory lock for its whole package binary, so
// a parallel `go test ./...` cannot interleave one package's cleanup deletes
// (or a schema migration's AccessExclusiveLock) with another package's rows.
package testlock

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// LockKey is the cross-package test-suite advisory lock. It is reserved:
// 7337741001 is the schema migration lock and 7337741003 the company-scope
// mutation lock.
const LockKey int64 = 7337741002

// Run holds LockKey on one pinned connection around run and returns run's code.
//
// An empty DSN, an open failure or a ping failure runs run unlocked: DB-backed
// tests skip themselves when no database is configured. A reachable database
// whose lock statement fails is different — the suite would then race the other
// packages unlocked — so Run reports the error and returns 1.
//
// The unlock and the connection close happen before Run returns, so callers use
// os.Exit(testlock.Run(dsn, m.Run)) and never leak the lock past the binary.
func Run(dsn string, run func() int) int {
	if dsn == "" {
		return run()
	}
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return run()
	}
	defer pool.Close()
	if err := pool.Ping(); err != nil {
		return run()
	}
	// pg_advisory_lock is session-scoped and database/sql would otherwise hand
	// each statement to a different pooled session, so pin one connection.
	conn, err := pool.Conn(context.Background())
	if err != nil {
		return run()
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, LockKey); err != nil {
		fmt.Fprintf(os.Stderr, "testlock: acquiring advisory lock %d: %v\n", LockKey, err)
		return 1
	}
	code := run()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, LockKey); err != nil {
		// The deferred close still ends the session, which releases the lock.
		fmt.Fprintf(os.Stderr, "testlock: releasing advisory lock %d: %v\n", LockKey, err)
	}
	return code
}

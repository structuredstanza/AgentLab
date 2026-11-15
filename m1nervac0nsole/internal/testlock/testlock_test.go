package testlock

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// testDSN reads the DSN the DB-backed suites are run with. This package cannot
// ask package db for it (that would be an import cycle), so it reads the same
// environment variable.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("M1NERVAC0NSOLE_PG_DSN")
	if dsn == "" {
		t.Skip("M1NERVAC0NSOLE_PG_DSN not set")
	}
	return dsn
}

func openConn(t *testing.T, dsn string) *sql.Conn {
	t.Helper()
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	conn, err := pool.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestLockKeyIsTheSharedSuiteKey(t *testing.T) {
	if LockKey != 7337741002 {
		t.Fatalf("LockKey = %d, want the shared suite key 7337741002", LockKey)
	}
}

func TestRunWithoutDSNRunsUnlocked(t *testing.T) {
	called := false
	code := Run("", func() int {
		called = true
		return 7
	})
	if !called {
		t.Fatal("Run did not call the suite for an empty DSN")
	}
	if code != 7 {
		t.Fatalf("Run returned %d, want the suite's 7", code)
	}
}

func TestRunUnreachableDSNRunsUnlocked(t *testing.T) {
	const dsn = "postgres://testlock:testlock@127.0.0.1:1/testlock?sslmode=disable&connect_timeout=1"
	called := false
	code := Run(dsn, func() int {
		called = true
		return 5
	})
	if !called {
		t.Fatal("Run did not call the suite when the database was unreachable")
	}
	if code != 5 {
		t.Fatalf("Run returned %d, want the suite's 5", code)
	}
}

// TestRunWaitsForHolder is the exclusion check: while another session owns the
// key, Run must not enter the suite.
func TestRunWaitsForHolder(t *testing.T) {
	dsn := testDSN(t)
	holder := openConn(t, dsn)
	if _, err := holder.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, LockKey); err != nil {
		t.Fatalf("holder lock: %v", err)
	}

	entered := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		done <- Run(dsn, func() int {
			close(entered)
			return 0
		})
	}()

	select {
	case <-entered:
		t.Fatal("Run entered the suite while another session held the lock")
	case <-time.After(200 * time.Millisecond):
	}

	if _, err := holder.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, LockKey); err != nil {
		t.Fatalf("holder unlock: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not enter the suite after the lock was released")
	}
	if code := <-done; code != 0 {
		t.Fatalf("Run returned %d, want 0", code)
	}
}

// TestRunFailsWhenReachableLockFails is the tightening: a reachable database
// whose lock statement fails must not run the suite unlocked. The DSN carries a
// statement timeout, so the blocked lock statement errors instead of waiting.
func TestRunFailsWhenReachableLockFails(t *testing.T) {
	dsn := testDSN(t)
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("DSN is not a postgres:// URL, so statement_timeout cannot be appended")
	}
	holder := openConn(t, dsn)
	if _, err := holder.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, LockKey); err != nil {
		t.Fatalf("holder lock: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	called := false
	if code := Run(dsn+sep+"statement_timeout=500", func() int {
		called = true
		return 0
	}); code != 1 {
		t.Fatalf("Run returned %d, want 1 when the lock statement fails", code)
	}
	if called {
		t.Fatal("Run entered the suite without holding the lock")
	}
}

// TestRunReleasesLockAndReturnsCode is the cleanup check: the key is free again
// as soon as Run returns, for both a passing and a failing suite code.
func TestRunReleasesLockAndReturnsCode(t *testing.T) {
	dsn := testDSN(t)
	for _, want := range []int{0, 3} {
		if code := Run(dsn, func() int { return want }); code != want {
			t.Fatalf("Run returned %d, want %d", code, want)
		}
		conn := openConn(t, dsn)
		var got bool
		if err := conn.QueryRowContext(context.Background(), `SELECT pg_try_advisory_lock($1)`, LockKey).Scan(&got); err != nil {
			t.Fatalf("try lock after Run returned %d: %v", want, err)
		}
		if !got {
			t.Fatalf("lock still held after Run returned %d", want)
		}
		if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, LockKey); err != nil {
			t.Fatalf("release probe lock: %v", err)
		}
	}
}

package db

import (
	"fmt"
	"testing"
	"time"
)

// InsertSettingIfAbsent is the safety net for auth.password_hash: the caller's GetSetting check
// can be defeated by a database error, and a concurrent request can cut in front of it (bcrypt takes tens of
// milliseconds). So the guarantee of "set only once, on the first attempt" must live in the primary key constraint, not in an if check
// .
func TestInsertSettingIfAbsentDoesNotOverwrite(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// A test-only key is used so the real auth.password_hash in the development database is left untouched.
	key := fmt.Sprintf("test.insert_if_absent.%d", time.Now().UnixNano())
	defer func() { _, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key) }()

	inserted, err := d.InsertSettingIfAbsent(key, "first")
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("the first write must return inserted=true")
	}

	inserted, err = d.InsertSettingIfAbsent(key, "second")
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("an existing key must return inserted=false")
	}

	got, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		t.Fatalf("GetSetting: ok=%v err=%v", ok, err)
	}
	if got != "first" {
		t.Fatalf("value was overwritten to %q; it must stay %q", got, "first")
	}
}

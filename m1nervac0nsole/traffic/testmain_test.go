package traffic

import (
	"os"
	"testing"
)

// TestMain pins the capture reserve for the whole package. The standalone
// default keeps a fifth of the volume free, so a host whose disk is more than
// 80% full would disable capture and every test that stores a body would fail
// for a reason that has nothing to do with the code under test. The reserve
// policy itself is covered by reserve_test.go, which injects its own numbers.
func TestMain(m *testing.M) {
	os.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_MB", "64")
	os.Setenv("M1NERVAC0NSOLE_CAPTURE_RESERVE_PCT", "1")
	os.Exit(m.Run())
}

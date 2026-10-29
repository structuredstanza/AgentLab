package db

import (
	"fmt"
	"testing"
	"time"
)

func testOAuthProfile(t *testing.T, d *DB, method, format string) int64 {
	t.Helper()
	id, err := d.SaveProfile(&LLMProfile{
		Name:       fmt.Sprintf("t-oauth-%d", time.Now().UnixNano()),
		Format:     format,
		AuthMethod: method,
		Model:      "oauth-test-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	return id
}

// Readiness for SDK-backed profiles is decided by the bridge at resolution time,
// so the pool must list a keyless OAuth profile even without any local grant row.
func TestPoolProfilesListsKeylessOAuthProfile(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id := testOAuthProfile(t, d, "codex", "openai-responses")
	profiles, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		if p.ID == id && p.APIKey == "" && p.AuthMethod == "codex" {
			return
		}
	}
	t.Fatalf("keyless OAuth profile %d was excluded from PoolProfiles", id)
}

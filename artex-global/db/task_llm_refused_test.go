package db

import (
	"fmt"
	"testing"
	"time"
)

// A provider refusal must persist as status 'refused' with its reason, advance the
// chain like a quota failure, and never be written as 'quota_exhausted'.
func TestRefusedChainEntryKeepsRefusedStatus(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	profileIDs := make([]int64, 0, 2)
	for i := range 2 {
		id, err := d.SaveProfile(&LLMProfile{
			Name: fmt.Sprintf("refused-chain-%d-%d", suffix, i), Format: "openai",
			Model: fmt.Sprintf("refused-model-%d", i), APIKey: "test-key",
		})
		if err != nil {
			t.Fatal(err)
		}
		profileIDs = append(profileIDs, id)
	}
	task, err := d.CreateTaskWithOptions("refused chain", "goal", TaskCreateOptions{LLMProfileIDs: profileIDs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		for _, id := range profileIDs {
			_ = d.DeleteProfile(id)
		}
	})

	revision := task.LLMChainRevision
	first, err := d.MarkTaskLLMProfileRefusedAtRevision(task.ID, profileIDs[0], revision, "provider refused the request")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Advanced || first.NextProfileID == nil || *first.NextProfileID != profileIDs[1] {
		t.Fatalf("refusal did not advance to the second profile: %+v", first)
	}
	status, lastErr := chainEntry(t, d, task.ID, profileIDs[0])
	if status != "refused" || lastErr != "provider refused the request" {
		t.Fatalf("refused entry = (%q, %q), want (refused, reason)", status, lastErr)
	}

	end, err := d.MarkTaskLLMProfileQuotaExhausted(task.ID, profileIDs[1], "insufficient_quota")
	if err != nil {
		t.Fatal(err)
	}
	if !end.ChainExhausted {
		t.Fatalf("second profile failure did not exhaust the chain: %+v", end)
	}
	if status, _ := chainEntry(t, d, task.ID, profileIDs[1]); status != "quota_exhausted" {
		t.Fatalf("quota entry status = %q, want quota_exhausted", status)
	}
}

func chainEntry(t *testing.T, d *DB, taskID, profileID int64) (string, string) {
	t.Helper()
	var status, lastErr string
	if err := d.QueryRow(`SELECT status, COALESCE(last_error,'') FROM task_llm_profiles WHERE task_id=$1 AND profile_id=$2`,
		taskID, profileID).Scan(&status, &lastErr); err != nil {
		t.Fatal(err)
	}
	return status, lastErr
}

package db

import "testing"

// Re-saving a credential with a blank password must keep the stored one: the
// agent generates a password, then the operator adds a note without retyping it.
// Before the fix the upsert overwrote the password with ” and flipped the row
// to source=user, destroying the only copy.
func TestUpsertTaskCredentialBlankPasswordKeepsStoredOne(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { d.Close() })

	var expID int64
	if err := d.QueryRow(`INSERT INTO explorations (description, goal) VALUES ('p','p') RETURNING id`).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	var taskID int64
	if err := d.QueryRow(`INSERT INTO tasks (name, description, goal, exploration_id) VALUES ('cred','','',$1) RETURNING id`, expID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_credentials WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	})

	const generated = "G3n3rat3d-By-Agent"
	if _, err := d.UpsertTaskCredential(taskID, TaskCredentialInput{
		Domain: "app.example.com", Username: "admin", Password: generated, Source: "agent",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertTaskCredential(taskID, TaskCredentialInput{
		Domain: "app.example.com", Username: "admin", Password: "", Source: "user", Note: "OTP verified",
	}); err != nil {
		t.Fatal(err)
	}

	list, err := d.TaskCredentials(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("%d credential rows, want 1", len(list))
	}
	if list[0].Password != generated {
		t.Errorf("password = %q, want the stored one preserved", list[0].Password)
	}
	if list[0].Note != "OTP verified" {
		t.Errorf("note = %q, want the new note applied", list[0].Note)
	}
}

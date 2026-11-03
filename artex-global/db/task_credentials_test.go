package db

import "testing"

func TestTaskCredentialPasswordBytes(t *testing.T) {
	for _, source := range []string{"user", "agent"} {
		for _, password := range []string{" secret ", "\tsecret\t", "\u00a0secret\u2003", " \t\n ", ""} {
			in := TaskCredentialInput{Domain: " target.example ", Username: " user ", Password: password, Source: source, Note: " note "}
			got, err := in.normalize()
			if source == "agent" && password == "" {
				if err == nil {
					t.Error("empty agent password accepted")
				}
				continue
			}
			if err != nil {
				t.Errorf("source=%s password=%q: %v", source, password, err)
				continue
			}
			if got.Password != password {
				t.Errorf("source=%s password changed from %q to %q", source, password, got.Password)
			}
			if got.Domain != "target.example" || got.Username != "user" || got.Note != "note" {
				t.Errorf("metadata not normalized: %+v", got)
			}
		}
	}
}

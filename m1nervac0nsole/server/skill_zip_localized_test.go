package server

import "testing"

// TestSkillZipRejectsNonZip: a non-zip upload must be rejected, not accepted.
func TestSkillZipRejectsNonZip(t *testing.T) {
	if _, err := newSkillZipReader([]byte("this is not a zip archive")); err == nil {
		t.Fatal("A non-zip input must return an error")
	}
}

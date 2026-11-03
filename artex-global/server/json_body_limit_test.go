package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A skill file may be up to maxSkillFileBytes (20 MiB) per the documented
// limits, and the editor saves through PUT /api/skills/{name}/files/{path}.
// The shared 8 MiB JSON ceiling must not reject a legitimate save.
func TestSkillFileSaveAcceptsUpToTheDocumentedFileSize(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "probe-skill")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{skillDir: dir}

	const size = 9 << 20 // above 8 MiB, below the 20 MiB per-file limit
	body, _ := json.Marshal(map[string]string{"content": strings.Repeat("x", size)})
	req := httptest.NewRequest("PUT", "/api/skills/probe-skill/files/big.txt", bytes.NewReader(body))
	req.SetPathValue("name", "probe-skill")
	req.SetPathValue("file", "big.txt")
	rec := httptest.NewRecorder()
	s.fsWriteFile(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d for a %d MiB skill file, want 200: %s", rec.Code, size>>20, strings.TrimSpace(rec.Body.String()))
	}
	got, err := os.ReadFile(filepath.Join(skill, "big.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != size {
		t.Fatalf("wrote %d bytes, want %d", len(got), size)
	}
}

// The raised ceiling must still be a ceiling: a skill save beyond the documented
// per-file maximum is refused rather than streamed into memory.
func TestSkillFileSaveRejectsBeyondTheDocumentedSize(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "probe-skill")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{skillDir: dir}

	body, _ := json.Marshal(map[string]string{"content": strings.Repeat("x", 25<<20)})
	req := httptest.NewRequest("PUT", "/api/skills/probe-skill/files/huge.txt", bytes.NewReader(body))
	req.SetPathValue("name", "probe-skill")
	req.SetPathValue("file", "huge.txt")
	rec := httptest.NewRecorder()
	s.fsWriteFile(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status=%d for a 25 MiB skill file, want 400", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(skill, "huge.txt")); !os.IsNotExist(err) {
		t.Error("the rejected file was written anyway")
	}
}

// The workspace editor is capped at maxWorkspaceRead (2 MiB) on the read side,
// so its write path stays inside the shared JSON ceiling.
func TestWorkspaceWriteStaysInsideTheSharedCeiling(t *testing.T) {
	if maxWorkspaceRead >= maxJSONBodyBytes {
		t.Fatalf("maxWorkspaceRead (%d) >= maxJSONBodyBytes (%d): the workspace editor can now exceed the shared cap",
			maxWorkspaceRead, maxJSONBodyBytes)
	}
}

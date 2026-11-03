package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func uploadRequestFor(t *testing.T, work, name, content string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	hdr := map[string][]string{"Content-Disposition": {`form-data; name="file"; filename="` + name + `"`}}
	part, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: work}}
	req := httptest.NewRequest("POST", "/api/workspace/?path=", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.wsUpload(rec, req)
	return rec
}

// The upload stages into a temp name and renames on success so a failed copy
// cannot destroy the file already on disk. This covers the success path — the
// overwrite still happens, and nothing is left behind — which is what the rename
// changed. A copy that fails partway is not reachable from a unit test without
// injecting a write error; that case was verified separately with RLIMIT_FSIZE.
func TestWorkspaceUploadReplacesTheFileAndLeavesNoStagingArtifact(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "report.md"), []byte("OLD CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := uploadRequestFor(t, work, "report.md", "NEW CONTENT")
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	got, err := os.ReadFile(filepath.Join(work, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW CONTENT" {
		t.Fatalf("file = %q, want the uploaded content", got)
	}

	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "report.md" {
			t.Errorf("staging artifact left behind: %s", e.Name())
		}
	}
}

// A client that vanishes mid-upload is rejected by the multipart parser before
// any file is opened, so the existing content is untouched. This guards that
// the parse-time rejection keeps winning as the handler changes.
func TestWorkspaceUploadTruncatedBodyLeavesTheFileAlone(t *testing.T) {
	work := t.TempDir()
	const original = "the finished analysis that must survive\n"
	if err := os.WriteFile(filepath.Join(work, "report.md"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	hdr := map[string][]string{"Content-Disposition": {`form-data; name="file"; filename="report.md"`}}
	part, _ := mw.CreatePart(hdr)
	io.WriteString(part, "truncated replacement")
	mw.Close()
	full := body.Bytes()
	truncated := full[:len(full)-len(mw.Boundary())-6]

	s := &Server{m: &Manager{dir: work}}
	req := httptest.NewRequest("POST", "/api/workspace/?path=", bytes.NewReader(truncated))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.wsUpload(rec, req)

	got, err := os.ReadFile(filepath.Join(work, "report.md"))
	if err != nil {
		t.Fatalf("the existing file disappeared: %v", err)
	}
	if string(got) != original {
		t.Fatalf("file changed on a rejected upload: %q", got)
	}
}

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func workspaceUploadRequest(t *testing.T, target, name, content string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, target, &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func TestWorkspaceRoutesConfineOutsideSymlinks(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body string
		handler                  func(*Server, http.ResponseWriter, *http.Request)
		upload                   bool
	}{
		{"list", "GET", "out", "", (*Server).wsList, false},
		{"read leaf", "GET", "leaf.txt", "", (*Server).wsRead, false},
		{"read parent", "GET", "out/sentinel.txt", "", (*Server).wsRead, false},
		{"download leaf", "GET", "leaf.txt", "", (*Server).wsDownload, false},
		{"download parent", "GET", "out/sentinel.txt", "", (*Server).wsDownload, false},
		{"write leaf", "POST", "leaf.txt", `{"path":"leaf.txt","content":"replaced"}`, (*Server).wsWrite, false},
		{"write parent", "POST", "out/sentinel.txt", `{"path":"out/sentinel.txt","content":"replaced"}`, (*Server).wsWrite, false},
		{"mkdir parent", "POST", "out/new", `{"path":"out/new"}`, (*Server).wsMkdir, false},
		{"delete parent", "DELETE", "out/sentinel.txt", "", (*Server).wsDelete, false},
		{"upload parent", "POST", "out", "", (*Server).wsUpload, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			work, outside := t.TempDir(), t.TempDir()
			secret := "OUTSIDE PRIVATE SENTINEL"
			if err := os.WriteFile(filepath.Join(outside, "sentinel.txt"), []byte(secret), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(work, "out")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "sentinel.txt"), filepath.Join(work, "leaf.txt")); err != nil {
				t.Fatal(err)
			}
			s := &Server{m: &Manager{dir: work}}
			target := "/api/workspace/?path=" + url.QueryEscape(test.path)
			request := httptest.NewRequest(test.method, target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.upload {
				request = workspaceUploadRequest(t, target, "sentinel.txt", "replaced")
			}
			response := httptest.NewRecorder()
			test.handler(s, response, request)
			if response.Code >= 200 && response.Code < 300 {
				t.Errorf("outside path accepted: %d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), secret) {
				t.Error("outside contents disclosed")
			}
			data, err := os.ReadFile(filepath.Join(outside, "sentinel.txt"))
			if err != nil || string(data) != secret {
				t.Errorf("outside file changed: %q %v", data, err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 1 || entries[0].Name() != "sentinel.txt" {
				t.Errorf("outside directory changed: %v %v", entries, err)
			}
		})
	}
}

func TestWorkspaceRelativeSymlinksOverwriteAndDownloadRanges(t *testing.T) {
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested", filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: work}}
	write := httptest.NewRecorder()
	s.wsWrite(write, httptest.NewRequest("POST", "/", strings.NewReader(`{"path":"link/note.txt","content":"abcdef"}`)))
	if write.Code != 200 {
		t.Fatalf("internal symlink write: %d %s", write.Code, write.Body.String())
	}
	read := httptest.NewRecorder()
	s.wsRead(read, httptest.NewRequest("GET", "/?path=link/note.txt", nil))
	var view struct {
		Content, Path string
		Binary        bool
	}
	if err := json.Unmarshal(read.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if read.Code != 200 || view.Content != "abcdef" || view.Path != "link/note.txt" || view.Binary {
		t.Fatalf("read: %d %+v", read.Code, view)
	}
	download := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/?path=link/note.txt", nil)
	request.Header.Set("Range", "bytes=1-3")
	s.wsDownload(download, request)
	if download.Code != 206 || download.Body.String() != "bcd" || download.Header().Get("Content-Range") != "bytes 1-3/6" {
		t.Fatalf("range: %d %s %v", download.Code, download.Body.String(), download.Header())
	}
	upload := httptest.NewRecorder()
	s.wsUpload(upload, workspaceUploadRequest(t, "/?path=link", "note.txt", "replacement"))
	if upload.Code != 200 {
		t.Fatalf("workspace overwrite: %d %s", upload.Code, upload.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(work, "nested", "note.txt"))
	if err != nil || string(data) != "replacement" {
		t.Fatalf("workspace upload did not overwrite the internal target: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(work, "nested", "note-1.txt")); !os.IsNotExist(err) {
		t.Fatalf("workspace upload unexpectedly used attachment suffixes: %v", err)
	}
	deleted := httptest.NewRecorder()
	s.wsDelete(deleted, httptest.NewRequest("DELETE", "/?path=link/note.txt", nil))
	if deleted.Code != 200 {
		t.Fatalf("delete internal target: %d %s", deleted.Code, deleted.Body.String())
	}
	if _, err := os.Stat(filepath.Join(work, "nested", "note.txt")); !os.IsNotExist(err) {
		t.Fatalf("delete left its target: %v", err)
	}
}

type workspaceSwapReader struct {
	io.Reader
	once sync.Once
	swap func()
}

func (reader *workspaceSwapReader) Read(data []byte) (int, error) {
	reader.once.Do(reader.swap)
	return reader.Reader.Read(data)
}

func TestWorkspaceUploadRejectsDirectorySwapAfterValidation(t *testing.T) {
	work, outside := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	request := workspaceUploadRequest(t, "/?path=sub", "sentinel.txt", "must remain inside")
	request.Body = io.NopCloser(&workspaceSwapReader{Reader: request.Body, swap: func() {
		if err := os.Rename(filepath.Join(work, "sub"), filepath.Join(work, "original-sub")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(work, "sub")); err != nil {
			t.Fatal(err)
		}
	}})
	response := httptest.NewRecorder()
	(&Server{m: &Manager{dir: work}}).wsUpload(response, request)
	if response.Code >= 200 && response.Code < 300 {
		t.Fatalf("swapped outside directory accepted: %d %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(outside, "sentinel.txt")); !os.IsNotExist(err) {
		t.Fatalf("upload escaped after validation: %v", err)
	}
}

func TestWorkspaceReadPreservesBinaryAndSizeLimits(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "binary"), []byte{'a', 0, 'b'}, 0o600); err != nil {
		t.Fatal(err)
	}
	large, err := os.Create(filepath.Join(work, "large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(maxWorkspaceRead + 1); err != nil {
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"binary", "large"} {
		response := httptest.NewRecorder()
		(&Server{m: &Manager{dir: work}}).wsRead(response, httptest.NewRequest("GET", "/?path="+name, nil))
		var view struct {
			Binary   bool
			TooLarge bool `json:"too_large"`
			Content  string
		}
		if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if response.Code != 200 || !view.Binary || view.TooLarge != (name == "large") || view.Content != "" {
			t.Fatalf("%s: %d %+v", name, response.Code, view)
		}
	}
}

func TestChatUploadConfinesParentLinksAndSkipsDanglingDestinations(t *testing.T) {
	t.Run("parent escape", func(t *testing.T) {
		work, outside := t.TempDir(), t.TempDir()
		if err := os.Symlink(outside, filepath.Join(work, "sessions")); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		(&Server{m: &Manager{dir: work}}).chatUpload(response, workspaceUploadRequest(t, "/?scope=session&id=s1", "a.txt", "private attachment"))
		if response.Code >= 200 && response.Code < 300 {
			t.Fatalf("outside attachment parent accepted: %d %s", response.Code, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(outside, "s1")); !os.IsNotExist(err) {
			t.Fatalf("attachment directory escaped: %v", err)
		}
	})
	t.Run("existing file and dangling leaf", func(t *testing.T) {
		work, outside := t.TempDir(), t.TempDir()
		dir := filepath.Join(work, "sessions", "s1", "uploads")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sample.txt"), []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "missing"), filepath.Join(dir, "sample-1.txt")); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		(&Server{m: &Manager{dir: work}}).chatUpload(response, workspaceUploadRequest(t, "/?scope=session&id=s1", "sample.txt", "new attachment"))
		var result struct {
			Attachments []chatAttachment `json:"attachments"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if response.Code != 200 || len(result.Attachments) != 1 || result.Attachments[0].Path != "uploads/sample-2.txt" {
			t.Fatalf("reservation: %d %+v %s", response.Code, result, response.Body.String())
		}
		for name, want := range map[string]string{"sample.txt": "original", "sample-2.txt": "new attachment"} {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(data) != want {
				t.Fatalf("%s changed: %q %v", name, data, err)
			}
		}
		if _, err := os.Stat(filepath.Join(outside, "missing")); !os.IsNotExist(err) {
			t.Fatalf("dangling link was followed: %v", err)
		}
	})
}

func TestChatConcurrentUploadsKeepIndependentContents(t *testing.T) {
	work := t.TempDir()
	s := &Server{m: &Manager{dir: work}}
	const count = 16
	start := make(chan struct{})
	type uploadResult struct {
		response *httptest.ResponseRecorder
		payload  string
	}
	results := make(chan uploadResult, count)
	for index := range count {
		payload := fmt.Sprintf("independent payload %02d", index)
		request := workspaceUploadRequest(t, "/?scope=session&id=s1", "same.txt", payload)
		go func() {
			<-start
			response := httptest.NewRecorder()
			s.chatUpload(response, request)
			results <- uploadResult{response, payload}
		}()
	}
	close(start)
	seen := make(map[string]bool)
	for range count {
		result := <-results
		var body struct {
			Attachments []chatAttachment `json:"attachments"`
		}
		if err := json.Unmarshal(result.response.Body.Bytes(), &body); err != nil {
			t.Error(err)
			continue
		}
		if result.response.Code != 200 || len(body.Attachments) != 1 {
			t.Errorf("upload failed: %d %s", result.response.Code, result.response.Body.String())
			continue
		}
		attachment := body.Attachments[0]
		if seen[attachment.Path] {
			t.Errorf("concurrent attachment reused %s", attachment.Path)
		}
		seen[attachment.Path] = true
		data, err := os.ReadFile(attachment.Abs)
		if err != nil || string(data) != result.payload || attachment.Size != int64(len(result.payload)) {
			t.Errorf("attachment clobbered: %s %q %v", attachment.Path, data, err)
		}
	}
}

func TestMultipartUploadRoutesRemoveSpilledStorage(t *testing.T) {
	for _, chat := range []bool{false, true} {
		t.Run(fmt.Sprint("chat=", chat), func(t *testing.T) {
			work, spill := t.TempDir(), t.TempDir()
			t.Setenv("TMPDIR", spill)
			payload := strings.Repeat("attachment", 128)
			target := "/?path=."
			if chat {
				target = "/?scope=session&id=s1"
			}
			request := workspaceUploadRequest(t, target, "spilled.txt", payload)
			if err := request.ParseMultipartForm(1); err != nil {
				t.Fatal(err)
			}
			files, err := os.ReadDir(spill)
			if err != nil || len(files) != 1 {
				t.Fatalf("expected one real multipart spill file: %v %v", files, err)
			}
			response := httptest.NewRecorder()
			s := &Server{m: &Manager{dir: work}}
			if chat {
				s.chatUpload(response, request)
			} else {
				s.wsUpload(response, request)
			}
			if response.Code != 200 {
				t.Fatalf("upload failed: %d %s", response.Code, response.Body.String())
			}
			for _, file := range files {
				if _, err := os.Stat(filepath.Join(spill, file.Name())); !os.IsNotExist(err) {
					t.Errorf("multipart temporary storage retained: %s %v", file.Name(), err)
				}
			}
			path := filepath.Join(work, "spilled.txt")
			if chat {
				path = filepath.Join(work, "sessions", "s1", "uploads", "spilled.txt")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != payload {
				t.Fatalf("persisted upload changed: %q %v", data, err)
			}
		})
	}
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// maxChatUpload caps a single chat-attachment upload request (memory + spill).
const maxChatUpload = 128 << 20 // 128 MiB

// User-facing error responses for chatUpload (English). They are exposed to the UI as-is via writeErr. Terminology:
// Use "attachment"; scope/id/file are request field names and remain unchanged. scope validation follows the pattern in intercept.go
// The "value must be one of … " pattern; the wording for deleting a work item follows the same sentence structure as goals_api.go; "invalid id"
// follows the same pattern as workspace.go errWsIllegalPath("Invalid path"). The three "...failed" messages
// are concatenated with a prefix constant + err.Error(), following the precedent at task_archives.go:229.
const (
	errChatUploadScopeInvalid = "The scope value must be one of task, session, or staging"
	errChatUploadBadID        = "Invalid id"
	errChatUploadTaskDeleting = "The task is being deleted, so attachments cannot be uploaded"
	errChatUploadMkdir        = "Failed to create directory: "
	errChatUploadParse        = "Failed to parse the upload, or it exceeded the size limit: "
	errChatUploadNoFile       = "There is no file to upload (form field file)"
	errChatUploadSaveFailed   = "Failed to save: "
)

// safeChatID guards the {id} path segment against traversal — task ids are numeric,
// session ids are alnum/_/- ; anything with "/" or ".." is rejected.
var safeChatID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// chatAttachment is one uploaded file as the frontend + agent see it. Path is relative
// to the chat's working dir (e.g. "uploads/report.txt"), which is the agent's CWD, so
// it can Read/Bash the file directly; Name/Size drive the UI card.
type chatAttachment struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Abs is the absolute path where the file is written to disk (m.dir is already absolute). Before the task is created, while staged (scope=staging), the frontend uses it to
	// write into the task description. task/session go through composeAgentMessage, which builds the path on the backend and does not depend on this field.
	Abs string `json:"abs,omitempty"`
}

// chatUpload implements method-1 file support: it saves one or more files into a chat's
// working dir under uploads/, so the agent opens them with its existing Read/Bash tools
// and the sent message carries their paths. No LLM-layer change, no multimodal.
//
// POST /api/chat/upload?scope=task|session|staging&id=<id>, multipart field "file"
// (repeatable). Returns {attachments:[{name,path,size,abs}]}. Target dir mirrors the
// agent CWD layout:
//
//	scope=task    → <workDir>/tasks/<id>/uploads/
//	scope=session → <workDir>/sessions/<id>/uploads/
//	scope=staging → <workDir>/drafts/<id>/uploads/   (staged before task creation: the task has no ID yet,
//	                files are first written here, and the frontend writes the returned abs absolute path into the task description)
func (s *Server) chatUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	var sub string
	taskScoped := false
	switch r.URL.Query().Get("scope") {
	case "task":
		sub = "tasks"
		taskScoped = true
	case "session":
		sub = "sessions"
	case "staging":
		sub = "drafts"
	default:
		writeErr(w, 400, errChatUploadScopeInvalid)
		return
	}
	id := r.URL.Query().Get("id")
	if !safeChatID.MatchString(id) {
		writeErr(w, 400, errChatUploadBadID)
		return
	}
	if taskScoped {
		if s.m.ResolveTask(id) == nil {
			writeErr(w, 404, "task not found")
			return
		}
		if !s.engine.beginTaskOperation(id) {
			writeErr(w, http.StatusConflict, errChatUploadTaskDeleting)
			return
		}
		defer s.engine.decInflight(id)
	}
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, errChatUploadMkdir+err.Error())
		return
	}
	defer root.Close()
	dir := filepath.Join(sub, id, "uploads")
	if err := root.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, errChatUploadMkdir+err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, errChatUploadParse+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, errChatUploadNoFile)
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			continue
		}
		src, err := hdr.Open()
		if err != nil {
			writeErr(w, 500, errChatUploadSaveFailed+err.Error())
			return
		}
		file, dest, err := reserveUpload(root, dir, name)
		if err != nil {
			_ = src.Close()
			writeErr(w, 500, errChatUploadSaveFailed+err.Error())
			return
		}
		if err := saveUpload(src, file, hdr.Size); err != nil {
			if removeErr := root.Remove(dest); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
			writeErr(w, 500, errChatUploadSaveFailed+err.Error())
			return
		}
		base := filepath.Base(dest)
		out = append(out, chatAttachment{Name: base, Path: "uploads/" + base, Size: hdr.Size, Abs: filepath.Join(s.m.dir, dest)})
	}
	writeJSON(w, 200, map[string]any{"attachments": out})
}

// reserveUpload atomically allocates a name without following or replacing an existing entry.
func reserveUpload(root *os.Root, dir, name string) (*os.File, string, error) {
	candidate := name
	var stem, ext string
	for index := 0; ; index++ {
		dest := filepath.Join(dir, candidate)
		file, err := root.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		if err == nil {
			return file, dest, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
		if index == 0 {
			ext = filepath.Ext(name)
			stem = strings.TrimSuffix(name, ext)
		}
		candidate = fmt.Sprintf("%s-%d%s", stem, index+1, ext)
	}
}

// composeAgentMessage appends an attachment manifest to the user's message so the agent
// knows which files were uploaded and where to Read them. Attachment paths are
// relative to the agent workspace.
func composeAgentMessage(msg string, atts []chatAttachment) string {
	if len(atts) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	// The manifest below is model-only: the returned string goes to the agent, while the
	// transcript renders attachments separately from the JSON built by userActivityWithAttachments.
	b.WriteString("\n\nUploaded attachments (workspace-relative paths; use Read/Bash as needed):")
	for _, a := range atts {
		fmt.Fprintf(&b, "\n- %s (%s)", a.Path, humanBytes(a.Size))
	}
	return b.String()
}

// userActivityWithAttachments builds the persisted 'user' activity. With attachments,
// Detail holds JSON {text, attachments} so the transcript renders text + attachment
// cards; Summary stays the plain text (the list payload omits Detail, lazy-loaded).
func userActivityWithAttachments(worker, text string, atts []chatAttachment) db.Activity {
	a := db.Activity{Worker: worker, Kind: "user", Summary: text}
	if len(atts) > 0 {
		blob, _ := json.Marshal(map[string]any{"text": text, "attachments": atts})
		a.Detail = string(blob)
	}
	return a
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

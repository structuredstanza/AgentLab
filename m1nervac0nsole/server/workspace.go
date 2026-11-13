package server

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Root-relative
// operations prevent symlink traversal outside that directory. All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// User-facing workspace errors.
const (
	errWsIllegalPath      = "Invalid path"
	errWsPathNotFound     = "The path does not exist"
	errWsNotDir           = "Not a directory"
	errWsFileNotFound     = "The file does not exist"
	errWsIsDir            = "It is a directory, so it cannot be read as a file"
	errWsTargetIsDir      = "The target path is a directory"
	errWsCannotDeleteRoot = "The workspace root directory cannot be deleted"
	errWsUploadDirMissing = "The target directory does not exist"
	errWsUploadParse      = "Failed to parse the upload, or it exceeded the size limit: " // Append err.Error() after it
	errWsNoUploadFile     = "There is no file to upload (form field file)"
)

// workspacePath retains the file manager's rooted path normalization.
func workspacePath(rel string) string {
	name := strings.TrimPrefix(filepath.Clean("/"+strings.TrimSpace(rel)), string(os.PathSeparator))
	if name == "" {
		return "."
	}
	return name
}

func workspaceRel(name string) string {
	if name == "." {
		return ""
	}
	return filepath.ToSlash(name)
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	name := workspacePath(r.URL.Query().Get("path"))
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	dir, err := root.Open(name)
	if err != nil {
		writeErr(w, 404, errWsPathNotFound)
		return
	}
	defer dir.Close()
	fi, err := dir.Stat()
	if err != nil {
		writeErr(w, 404, errWsPathNotFound)
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, errWsNotDir)
		return
	}
	ents, err := dir.ReadDir(-1)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := root.Lstat(filepath.Join(name, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  workspaceRel(filepath.Join(name, e.Name())),
			Dir:   info.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// Place directories first, then sort each group by name.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": workspaceRel(name), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	name := workspacePath(r.URL.Query().Get("path"))
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		writeErr(w, 404, errWsFileNotFound)
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		writeErr(w, 404, errWsFileNotFound)
		return
	}
	if fi.IsDir() {
		writeErr(w, 400, errWsIsDir)
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": workspaceRel(name), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceRead+1))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(data) > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": workspaceRel(name), "size": len(data), "too_large": true, "binary": true})
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": workspaceRel(name), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": workspaceRel(name), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := workspacePath(req.Path)
	if name == "." {
		writeErr(w, 400, errWsIllegalPath)
		return
	}
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	if fi, err := root.Stat(name); err == nil && fi.IsDir() {
		writeErr(w, 400, errWsTargetIsDir)
		return
	}
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := root.WriteFile(name, []byte(req.Content), 0o644); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": workspaceRel(name)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := workspacePath(req.Path)
	if name == "." {
		writeErr(w, 400, errWsIllegalPath)
		return
	}
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	if err := root.MkdirAll(name, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": workspaceRel(name)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	name := workspacePath(r.URL.Query().Get("path"))
	if name == "." {
		writeErr(w, 400, errWsCannotDeleteRoot)
		return
	}
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	if _, err := root.Lstat(name); err != nil {
		writeErr(w, 404, errWsPathNotFound)
		return
	}
	if err := root.RemoveAll(name); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	name := workspacePath(r.URL.Query().Get("path"))
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		writeErr(w, 404, errWsFileNotFound)
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || fi.IsDir() {
		writeErr(w, 404, errWsFileNotFound)
		return
	}
	name = filepath.Base(name)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeContent(w, r, name, fi.ModTime(), file)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	dir := workspacePath(r.URL.Query().Get("path"))
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	if fi, err := root.Stat(dir); err != nil || !fi.IsDir() {
		writeErr(w, 400, errWsUploadDirMissing)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, errWsUploadParse+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, errWsNoUploadFile)
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		src, err := hdr.Open()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		// Stage into a temp name inside the root and rename only on success, so a
		// failed copy cannot destroy the file that is already there.
		dest := filepath.Join(dir, name)
		tmp := filepath.Join(dir, ".upload-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		if err != nil {
			_ = src.Close()
			writeErr(w, 500, err.Error())
			return
		}
		if err := saveUpload(src, out, hdr.Size); err != nil {
			_ = root.Remove(tmp)
			writeErr(w, 500, err.Error())
			return
		}
		if err := root.Rename(tmp, dest); err != nil {
			_ = root.Remove(tmp)
			writeErr(w, 500, err.Error())
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUpload(src io.ReadCloser, out *os.File, size int64) (err error) {
	defer src.Close()
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()
	written, err := io.Copy(out, src)
	if err == nil && written != size {
		return io.ErrUnexpectedEOF
	}
	return err
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}

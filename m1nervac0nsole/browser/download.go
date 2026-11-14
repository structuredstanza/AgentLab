package browser

import (
	"context"
	"encoding/json"
	"path/filepath"
)

// absPath resolves the download directory once, so a reported path is usable
// from any working directory.
func absPath(dir string) string {
	if dir == "" {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
}

// enableDownloads points the browser at the task's download directory and asks
// for progress events. It is a browser-target command, not a page one.
func (d *Driver) enableDownloads(ctx context.Context, c conn) error {
	d.mu.Lock()
	dir := d.downloadDir
	d.mu.Unlock()
	if dir == "" {
		return nil
	}
	_, err := sendBrowser(ctx, c, "Browser.setDownloadBehavior", map[string]any{
		"behavior":      "allow",
		"downloadPath":  dir,
		"eventsEnabled": true,
	})
	return err
}

func (d *Driver) downloadWillBegin(params json.RawMessage) {
	var ev struct {
		GUID              string `json:"guid"`
		SuggestedFilename string `json:"suggestedFilename"`
	}
	if json.Unmarshal(params, &ev) != nil || ev.GUID == "" {
		return
	}
	d.mu.Lock()
	if d.downloadDir != "" {
		if d.downloads == nil {
			d.downloads = map[string]string{}
		}
		d.downloads[ev.GUID] = filepath.Join(d.downloadDir, ev.SuggestedFilename)
	}
	d.mu.Unlock()
}

func (d *Driver) downloadProgress(params json.RawMessage) {
	var ev struct {
		GUID  string `json:"guid"`
		State string `json:"state"`
	}
	if json.Unmarshal(params, &ev) != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	path, known := d.downloads[ev.GUID]
	switch ev.State {
	case "completed":
		delete(d.downloads, ev.GUID)
		if known {
			d.downloaded = append(d.downloaded, path)
		}
	case "canceled":
		delete(d.downloads, ev.GUID)
	}
}

// Downloads returns the completed paths since the previous call and clears
// them, so one tool result reports each file once.
func (d *Driver) Downloads() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.downloaded
	d.downloaded = nil
	return out
}

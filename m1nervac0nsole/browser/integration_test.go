package browser

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestIntegrationRealChromium is the one test that talks to a browser. It is
// opt-in so the unit suite stays hermetic, and it skips when no Chromium is
// installed.
func TestIntegrationRealChromium(t *testing.T) {
	if os.Getenv("M1NERVAC0NSOLE_BROWSER_INTEGRATION") != "1" {
		t.Skip("set M1NERVAC0NSOLE_BROWSER_INTEGRATION=1 to drive a real Chromium")
	}
	// CI installs a browser and names it here; the image's stable link and the
	// guest's own binary are the local fallbacks.
	exe := os.Getenv("M1NERVAC0NSOLE_CHROMIUM")
	if exe == "" {
		exe = "/opt/ms-playwright/current/chrome"
	}
	if _, err := os.Stat(exe); err != nil {
		found, err := exec.LookPath("chromium")
		if err == nil {
			exe = found
		} else if found, err = exec.LookPath("google-chrome"); err == nil {
			exe = found
		} else {
			t.Skip("no Chromium binary")
		}
	}

	page := `<!doctype html><html><head><title>Smoke</title></head><body>
<button onclick="document.getElementById('out').textContent='clicked'">Press</button>
<input aria-label="Name">
<div id="out">waiting</div>
</body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Launch(ctx, Options{Executable: exe, UserDataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer d.Close()

	if _, err := d.Navigate(ctx, server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	snap, err := d.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	button := refFor(t, snap.Tree, `button "Press"`)
	if _, err := d.Click(ctx, button); err != nil {
		t.Fatalf("click: %v", err)
	}
	if err := d.Wait(ctx, "clicked", 5*time.Second); err != nil {
		t.Fatalf("wait after click: %v", err)
	}

	snap, err = d.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot after click: %v", err)
	}
	input := refFor(t, snap.Tree, `textbox "Name"`)
	if _, err := d.Type(ctx, input, "hello"); err != nil {
		t.Fatalf("type: %v", err)
	}
	if err := d.Wait(ctx, "hello", 5*time.Second); err != nil {
		t.Fatalf("wait after type: %v", err)
	}

	png, err := d.Screenshot(ctx, false)
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("screenshot is not a PNG: %d bytes", len(png))
	}
}

func refFor(t *testing.T, tree, needle string) string {
	t.Helper()
	for _, line := range strings.Split(tree, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		start := strings.Index(line, "[ref=")
		end := strings.Index(line, "]")
		if start < 0 || end <= start {
			continue
		}
		return line[start+len("[ref=") : end]
	}
	t.Fatalf("no ref for %q in:\n%s", needle, tree)
	return ""
}

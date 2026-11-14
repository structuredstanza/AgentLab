package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Viewport is an emulated window size. It is restored after a crash so a
// screenshot or a click keeps the geometry the caller set.
type Viewport struct {
	Width  int
	Height int
}

func (v Viewport) params() map[string]any {
	return map[string]any{
		"width":             v.Width,
		"height":            v.Height,
		"deviceScaleFactor": 1,
		"mobile":            false,
	}
}

// SetViewport changes the emulated window size.
func (d *Driver) SetViewport(ctx context.Context, viewport Viewport) error {
	if viewport.Width <= 0 || viewport.Height <= 0 {
		return fmt.Errorf("browser: viewport: width and height must be positive")
	}
	if _, err := d.Send(ctx, "Emulation.setDeviceMetricsOverride", viewport.params()); err != nil {
		return err
	}
	d.mu.Lock()
	d.viewport = &viewport
	d.mu.Unlock()
	return nil
}

// Navigate opens an http or https URL and waits for the load event.
//
// Other schemes are refused: file: and javascript: are not pages a task has
// any reason to open, and scope enforcement lives above this package.
func (d *Driver) Navigate(ctx context.Context, target string) (PageState, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return d.pageState(), fmt.Errorf("browser: navigate: only http and https URLs are allowed")
	}

	d.markAction()
	d.bumpGeneration()
	load := d.expect("Page.loadEventFired")
	raw, err := d.Send(ctx, "Page.navigate", map[string]any{"url": target})
	if err != nil {
		d.dropWaiter("Page.loadEventFired", load)
		return d.pageState(), err
	}

	var result struct {
		ErrorText string `json:"errorText"`
	}
	var navErr error
	if json.Unmarshal(raw, &result) == nil && result.ErrorText != "" {
		navErr = fmt.Errorf("browser: navigate: %s", result.ErrorText)
	}
	d.setURL(target, "")

	select {
	case <-load:
	case <-ctx.Done():
		d.dropWaiter("Page.loadEventFired", load)
		return d.pageState(), fmt.Errorf("browser: navigate: %w", ctx.Err())
	}
	d.refresh(ctx)
	return d.pageState(), navErr
}

// Click presses the centre of a ref's box.
func (d *Driver) Click(ctx context.Context, ref string) (PageState, error) {
	d.markAction()
	if err := d.clickRef(ctx, ref); err != nil {
		return d.pageState(), err
	}
	d.refresh(ctx)
	return d.pageState(), nil
}

// Type focuses a ref and inserts text at the caret. It does not submit.
func (d *Driver) Type(ctx context.Context, ref, text string) (PageState, error) {
	d.markAction()
	if err := d.clickRef(ctx, ref); err != nil {
		return d.pageState(), err
	}
	if _, err := d.Send(ctx, "Input.insertText", map[string]any{"text": text}); err != nil {
		return d.pageState(), err
	}
	d.refresh(ctx)
	return d.pageState(), nil
}

// Press sends one key down and up to the focused element.
func (d *Driver) Press(ctx context.Context, key string) (PageState, error) {
	d.markAction()
	if err := d.pressKey(ctx, key); err != nil {
		return d.pageState(), err
	}
	d.refresh(ctx)
	return d.pageState(), nil
}

// Select chooses options in a select element by value or visible text.
func (d *Driver) Select(ctx context.Context, ref string, values ...string) (PageState, error) {
	d.markAction()
	if len(values) == 0 {
		return d.pageState(), fmt.Errorf("browser: select: no values")
	}
	r, err := d.resolve(ref)
	if err != nil {
		return d.pageState(), err
	}
	raw, err := d.Send(ctx, "DOM.resolveNode", map[string]any{"backendNodeId": r.BackendNodeID})
	if err != nil {
		return d.pageState(), err
	}
	var node struct {
		Object struct {
			ObjectID string `json:"objectId"`
		} `json:"object"`
	}
	if err := json.Unmarshal(raw, &node); err != nil {
		return d.pageState(), fmt.Errorf("browser: select: decode node: %w", err)
	}
	if node.Object.ObjectID == "" {
		return d.pageState(), fmt.Errorf("browser: select: element is not addressable")
	}
	raw, err = d.Send(ctx, "Runtime.callFunctionOn", map[string]any{
		"objectId":            node.Object.ObjectID,
		"functionDeclaration": selectFunction,
		"arguments":           []any{map[string]any{"value": values}},
		"returnByValue":       true,
	})
	if err != nil {
		return d.pageState(), err
	}
	var called struct {
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	if json.Unmarshal(raw, &called) == nil && called.ExceptionDetails != nil {
		return d.pageState(), fmt.Errorf("browser: select: %s", called.ExceptionDetails.Text)
	}
	d.refresh(ctx)
	return d.pageState(), nil
}

// Wait polls the accessibility tree until text appears in a name or value.
// Unlike an action it is an explicit settle, bounded by timeout.
func (d *Driver) Wait(ctx context.Context, text string, timeout time.Duration) error {
	if text == "" {
		return fmt.Errorf("browser: wait: empty text")
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := d.Send(ctx, "Accessibility.getFullAXTree", nil)
		if err == nil {
			var result struct {
				Nodes []axNode `json:"nodes"`
			}
			if json.Unmarshal(raw, &result) == nil {
				for i := range result.Nodes {
					n := &result.Nodes[i]
					if n.Ignored {
						continue
					}
					if strings.Contains(axString(n.Name), text) || strings.Contains(axString(n.Value), text) {
						return nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("browser: wait for %q: %w", text, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Screenshot returns PNG bytes. fullPage captures the whole document, not just
// the viewport.
func (d *Driver) Screenshot(ctx context.Context, fullPage bool) ([]byte, error) {
	params := map[string]any{"format": "png"}
	if fullPage {
		raw, err := d.Send(ctx, "Page.getLayoutMetrics", nil)
		if err != nil {
			return nil, err
		}
		var metrics struct {
			CSSContentSize struct {
				Width  float64 `json:"width"`
				Height float64 `json:"height"`
			} `json:"cssContentSize"`
			ContentSize struct {
				Width  float64 `json:"width"`
				Height float64 `json:"height"`
			} `json:"contentSize"`
		}
		if err := json.Unmarshal(raw, &metrics); err != nil {
			return nil, fmt.Errorf("browser: screenshot: decode layout: %w", err)
		}
		size := metrics.CSSContentSize
		if size.Width <= 0 || size.Height <= 0 {
			size = metrics.ContentSize
		}
		if size.Width <= 0 || size.Height <= 0 {
			return nil, fmt.Errorf("browser: screenshot: page has no size")
		}
		params["clip"] = map[string]any{
			"x": 0, "y": 0, "width": size.Width, "height": size.Height, "scale": 1,
		}
		params["captureBeyondViewport"] = true
	}
	raw, err := d.Send(ctx, "Page.captureScreenshot", params)
	if err != nil {
		return nil, err
	}
	var result struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("browser: screenshot: decode: %w", err)
	}
	png, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		return nil, fmt.Errorf("browser: screenshot: decode: %w", err)
	}
	return png, nil
}

// Upload sets the files of a file input ref.
func (d *Driver) Upload(ctx context.Context, ref string, paths []string) (PageState, error) {
	d.markAction()
	if len(paths) == 0 {
		return d.pageState(), fmt.Errorf("browser: upload: no files")
	}
	r, err := d.resolve(ref)
	if err != nil {
		return d.pageState(), err
	}
	if _, err := d.Send(ctx, "DOM.setFileInputFiles", map[string]any{
		"files": paths, "backendNodeId": r.BackendNodeID,
	}); err != nil {
		return d.pageState(), err
	}
	d.refresh(ctx)
	return d.pageState(), nil
}

// clickRef resolves a ref to the centre of its content box and dispatches a
// left click. The element is scrolled into view first: a ref outside the
// viewport would otherwise click whatever happens to sit at its coordinates.
func (d *Driver) clickRef(ctx context.Context, ref string) error {
	r, err := d.resolve(ref)
	if err != nil {
		return err
	}
	if _, err := d.Send(ctx, "DOM.scrollIntoViewIfNeeded", map[string]any{
		"backendNodeId": r.BackendNodeID,
	}); err != nil {
		return err
	}
	x, y, err := d.boxCentre(ctx, r.BackendNodeID)
	if err != nil {
		return err
	}
	for _, eventType := range []string{"mousePressed", "mouseReleased"} {
		if _, err := d.Send(ctx, "Input.dispatchMouseEvent", map[string]any{
			"type": eventType, "x": x, "y": y, "button": "left", "clickCount": 1,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) boxCentre(ctx context.Context, backendNodeID int64) (float64, float64, error) {
	if backendNodeID == 0 {
		return 0, 0, fmt.Errorf("browser: ref has no DOM node to act on")
	}
	raw, err := d.Send(ctx, "DOM.getBoxModel", map[string]any{"backendNodeId": backendNodeID})
	if err != nil {
		return 0, 0, err
	}
	var model struct {
		Model struct {
			Content []float64 `json:"content"`
		} `json:"model"`
	}
	if err := json.Unmarshal(raw, &model); err != nil {
		return 0, 0, fmt.Errorf("browser: decode box model: %w", err)
	}
	content := model.Model.Content
	if len(content) < 8 {
		return 0, 0, fmt.Errorf("browser: element is not visible")
	}
	x := (content[0] + content[2] + content[4] + content[6]) / 4
	y := (content[1] + content[3] + content[5] + content[7]) / 4
	return x, y, nil
}

type keyDef struct {
	code string
	vk   int
	text string
}

var namedKeys = map[string]keyDef{
	"Enter":      {"Enter", 13, "\r"},
	"Tab":        {"Tab", 9, ""},
	"Escape":     {"Escape", 27, ""},
	"Backspace":  {"Backspace", 8, ""},
	"Delete":     {"Delete", 46, ""},
	"ArrowLeft":  {"ArrowLeft", 37, ""},
	"ArrowUp":    {"ArrowUp", 38, ""},
	"ArrowRight": {"ArrowRight", 39, ""},
	"ArrowDown":  {"ArrowDown", 40, ""},
	"Home":       {"Home", 36, ""},
	"End":        {"End", 35, ""},
	"PageUp":     {"PageUp", 33, ""},
	"PageDown":   {"PageDown", 34, ""},
	"Space":      {"Space", 32, " "},
}

func (d *Driver) pressKey(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("browser: press: empty key")
	}
	down := map[string]any{"type": "keyDown", "key": key}
	up := map[string]any{"type": "keyUp", "key": key}
	if def, ok := namedKeys[key]; ok {
		down["code"] = def.code
		down["windowsVirtualKeyCode"] = def.vk
		down["nativeVirtualKeyCode"] = def.vk
		up["code"] = def.code
		up["windowsVirtualKeyCode"] = def.vk
		up["nativeVirtualKeyCode"] = def.vk
		if def.text != "" {
			down["text"] = def.text
		}
	} else if utf8.RuneCountInString(key) == 1 {
		down["text"] = key
	} else {
		return fmt.Errorf("browser: press: unsupported key %q", key)
	}
	if _, err := d.Send(ctx, "Input.dispatchKeyEvent", down); err != nil {
		return err
	}
	_, err := d.Send(ctx, "Input.dispatchKeyEvent", up)
	return err
}

// selectFunction runs in the page: it sets selectedness from value or visible
// text and fires the events a real choice would.
const selectFunction = `function(values) {
  var el = this;
  if (!el || el.tagName !== 'SELECT') { throw new Error('not a select element'); }
  var wanted = {};
  for (var i = 0; i < values.length; i++) { wanted[values[i]] = true; }
  var changed = false;
  for (var j = 0; j < el.options.length; j++) {
    var option = el.options[j];
    var on = wanted[option.value] === true || wanted[option.text] === true;
    if (option.selected !== on) { option.selected = on; changed = true; }
  }
  if (changed) {
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }
  return true;
}`

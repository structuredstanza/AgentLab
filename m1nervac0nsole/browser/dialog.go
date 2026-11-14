package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// dialogAutoAccept is the window in which a dialog is treated as the direct
// consequence of the agent's own action. Outside it the dialog is probably for
// the operator (MFA, a confirm the model should not answer), so it is parked.
const dialogAutoAccept = 2 * time.Second

// Dialog is a parked JavaScript dialog waiting for the operator.
type Dialog struct {
	Type          string
	Message       string
	DefaultPrompt string
	URL           string
	OpenedAt      time.Time
}

// PendingDialog reports a dialog the agent did not answer, so the tool layer
// can surface it instead of leaving the page silently blocked.
func (d *Driver) PendingDialog() (Dialog, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.parked == nil {
		return Dialog{}, false
	}
	return *d.parked, true
}

// AnswerDialog accepts or dismisses the parked dialog. promptText fills a
// prompt when accepting.
func (d *Driver) AnswerDialog(ctx context.Context, accept bool, promptText string) error {
	d.mu.Lock()
	parked := d.parked
	d.parked = nil
	d.mu.Unlock()
	if parked == nil {
		return fmt.Errorf("browser: no dialog is open")
	}
	params := map[string]any{"accept": accept}
	if promptText != "" {
		params["promptText"] = promptText
	}
	if _, err := d.Send(ctx, "Page.handleJavaScriptDialog", params); err != nil {
		// Keep the dialog visible so the operator can retry.
		d.mu.Lock()
		if d.parked == nil {
			d.parked = parked
		}
		d.mu.Unlock()
		return err
	}
	return nil
}

func (d *Driver) dialogOpening(params json.RawMessage) {
	var ev struct {
		URL           string `json:"url"`
		Message       string `json:"message"`
		Type          string `json:"type"`
		DefaultPrompt string `json:"defaultPrompt"`
	}
	if json.Unmarshal(params, &ev) != nil {
		return
	}

	d.mu.Lock()
	recent := !d.lastAction.IsZero() && time.Since(d.lastAction) <= dialogAutoAccept
	d.mu.Unlock()

	if recent {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := d.Send(ctx, "Page.handleJavaScriptDialog", map[string]any{"accept": true})
		cancel()
		if err == nil {
			return
		}
	}

	d.mu.Lock()
	d.parked = &Dialog{
		Type:          ev.Type,
		Message:       ev.Message,
		DefaultPrompt: ev.DefaultPrompt,
		URL:           ev.URL,
		OpenedAt:      time.Now(),
	}
	d.mu.Unlock()
}

func (d *Driver) dialogClosed() {
	d.mu.Lock()
	d.parked = nil
	d.mu.Unlock()
}

package browser

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// A dialog that follows the agent's own click is the page asking permission
// for what the agent just did; leaving it open would block every later call.
func TestDialogAcceptedWhenAgentJustActed(t *testing.T) {
	f := newFakeConn()
	f.replies["Page.handleJavaScriptDialog"] = map[string]any{}
	d := newTestDriver(t, f, nil)

	d.markAction()
	f.emit("Page.javascriptDialogOpening", map[string]any{
		"type": "alert", "message": "saved", "url": "https://example.test/",
	})

	calls := f.callsOf("Page.handleJavaScriptDialog")
	if len(calls) != 1 {
		t.Fatalf("handle calls = %d, want one auto-accept", len(calls))
	}
	var handled struct {
		Accept bool `json:"accept"`
	}
	if err := json.Unmarshal(calls[0].Params, &handled); err != nil {
		t.Fatalf("decode handle: %v", err)
	}
	if !handled.Accept {
		t.Fatal("dialog was not accepted")
	}
	if _, ok := d.PendingDialog(); ok {
		t.Fatal("auto-accepted dialog was also parked")
	}
}

// A dialog with no recent agent action is for the operator: it is parked and
// visible, never answered silently.
func TestDialogParkedWhenAgentDidNotAct(t *testing.T) {
	f := newFakeConn()
	f.replies["Page.handleJavaScriptDialog"] = map[string]any{}
	d := newTestDriver(t, f, nil)
	d.mu.Lock()
	d.lastAction = time.Now().Add(-3 * time.Second)
	d.mu.Unlock()

	f.emit("Page.javascriptDialogOpening", map[string]any{
		"type": "prompt", "message": "code", "defaultPrompt": "", "url": "https://example.test/mfa",
	})

	if calls := f.callsOf("Page.handleJavaScriptDialog"); len(calls) != 0 {
		t.Fatalf("handle calls = %d, want the dialog parked", len(calls))
	}
	parked, ok := d.PendingDialog()
	if !ok {
		t.Fatal("dialog was neither accepted nor parked")
	}
	if parked.Type != "prompt" || parked.Message != "code" || parked.URL != "https://example.test/mfa" {
		t.Fatalf("parked = %+v", parked)
	}

	if err := d.AnswerDialog(context.Background(), true, "123456"); err != nil {
		t.Fatalf("answer: %v", err)
	}
	calls := f.callsOf("Page.handleJavaScriptDialog")
	if len(calls) != 1 {
		t.Fatalf("handle calls = %d, want the operator answer", len(calls))
	}
	var handled struct {
		Accept     bool   `json:"accept"`
		PromptText string `json:"promptText"`
	}
	if err := json.Unmarshal(calls[0].Params, &handled); err != nil {
		t.Fatalf("decode handle: %v", err)
	}
	if !handled.Accept || handled.PromptText != "123456" {
		t.Fatalf("answer = %+v", handled)
	}
	if _, ok := d.PendingDialog(); ok {
		t.Fatal("answered dialog is still parked")
	}
}

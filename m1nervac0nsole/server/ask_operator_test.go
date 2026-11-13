package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageAskOperatorImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "shot.png")
	if err := os.WriteFile(src, []byte("fakepng"), 0o644); err != nil {
		t.Fatal(err)
	}
	att, err := stageAskOperatorImage(dir, "7", "")
	if err != nil || att != nil {
		t.Fatalf("empty src: att=%v err=%v", att, err)
	}
	att, err = stageAskOperatorImage(dir, "7", src)
	if err != nil || len(att) != 1 {
		t.Fatalf("valid src: att=%v err=%v", att, err)
	}
	if !strings.HasPrefix(att[0].Path, "uploads/ask-operator-") || !strings.HasSuffix(att[0].Path, ".png") {
		t.Fatalf("unexpected attachment path %q", att[0].Path)
	}
	if _, err := os.Stat(filepath.Join(dir, "tasks", "7", "uploads", att[0].Name)); err != nil {
		t.Fatalf("copy missing: %v", err)
	}
	bad := filepath.Join(dir, "payload.exe")
	if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAskOperatorImage(dir, "7", bad); err == nil || !strings.Contains(err.Error(), "png/jpg") {
		t.Fatalf("expected extension rejection, got %v", err)
	}
	if _, err := stageAskOperatorImage(dir, "7", filepath.Join(dir, "nope.png")); err == nil {
		t.Fatal("expected missing-file rejection")
	}
}

func TestAskOperatorActivityShape(t *testing.T) {
	att := []chatAttachment{{Name: "ask-operator-1.png", Path: "uploads/ask-operator-1.png", Size: 7}}
	a := userActivityWithAttachments("worker", "OPERATOR INPUT REQUESTED: solve the captcha", att)
	if a.Kind != "user" || a.Worker != "worker" {
		t.Fatalf("unexpected activity kind/worker: %+v", a)
	}
	var parsed struct {
		Text        string           `json:"text"`
		Attachments []chatAttachment `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(a.Detail), &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(parsed.Text, "OPERATOR INPUT REQUESTED") || len(parsed.Attachments) != 1 || parsed.Attachments[0].Path != att[0].Path {
		t.Fatalf("unexpected detail payload: %+v", parsed)
	}
}

func TestAskOperatorEnvHandoffGuidance(t *testing.T) {
	desc := (&Server{}).toolAskOperator().Description()
	for _, marker := range []string{"copy-pastable", "do not retry or work around"} {
		if !strings.Contains(desc, marker) {
			t.Errorf("ask_operator description missing env-handoff marker %q", marker)
		}
	}
}

// A screenshot must reach the operator without entering the conversation when
// provider credentials are configured: an image cannot be redacted the way the
// question text is, but the human still needs to see the page.
func TestHandoffTextWithholdsTheImageButNamesIt(t *testing.T) {
	att := []chatAttachment{{Name: "ask-operator-1.png", Path: "uploads/ask-operator-1.png", Size: 7}}

	text, kept := handoffText("solve the captcha", att, true)
	if len(kept) != 0 {
		t.Fatalf("the screenshot was attached despite provider credentials: %+v", kept)
	}
	if !strings.Contains(text, "uploads/ask-operator-1.png") {
		t.Fatalf("the withheld screenshot is not named by path: %q", text)
	}
	if !strings.Contains(text, "this intent is pausing") {
		t.Fatalf("the hand-off lost its pause instruction: %q", text)
	}

	text, kept = handoffText("solve the captcha", att, false)
	if len(kept) != 1 {
		t.Fatalf("the screenshot was dropped without provider credentials: %+v", kept)
	}
	if strings.Contains(text, "uploads/") {
		t.Fatalf("an attached screenshot is also named by path: %q", text)
	}
}

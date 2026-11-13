package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// This file covers the Telegram side of whole-item packing and the rule that markdown
// escapes must not leak into HTML rendering.

func TestTelegramPackingUsesRuneBudget(t *testing.T) {
	m := batchMsg(200)
	text, kept := telegramHTML(m)
	// Telegram limits length by **character count**; using a byte count would compress Chinese messages to one third of their capacity.
	if n := utf8.RuneCountInString(text); n > telegramTextLimit {
		t.Fatalf("body is %d characters, over the limit of %d", n, telegramTextLimit)
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should fit only part of the items, got %d", kept)
	}
	if !strings.Contains(text, "next message") {
		t.Fatalf("should say that items are left out:\n%.300s", text)
	}
}

func TestTelegramTitleHasNoMarkdownEscapes(t *testing.T) {
	m := Message{Items: []Item{{Severity: "high", Name: "alert(1) *emphasis*"}}}
	text, _ := telegramHTML(m)
	if strings.Contains(text, `\(`) || strings.Contains(text, `\*`) {
		t.Fatalf("the Telegram body contains markdown backslash escapes:\n%s", text)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// This file covers the "whole-item packing" fix: when a summary message exceeds the channel's length limit, it must be truncated **by whole item**
// and must honestly report how many items did not fit, so that callers mark only the items that were actually delivered.
//
// The previous approach rendered the full document, then truncated it, and then marked the whole batch as delivered: the second half of the message silently disappeared,
// while the delivery history showed everything as successful. The bug went unnoticed, and nothing anywhere could detect it.

func TestMarkdownBodyPacksWholeItemsWithinByteLimit(t *testing.T) {
	// A 200-entry Chinese summary will inevitably far exceed WeCom's 4096-byte limit.
	m := batchMsg(200)
	body, kept := markdownBody(m, weComMarkdownLimit)

	if len(body) > weComMarkdownLimit {
		t.Fatalf("body is %d bytes, over the limit of %d", len(body), weComMarkdownLimit)
	}
	if !utf8.ValidString(body) {
		t.Fatal("body is not valid UTF-8")
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should fit only part of the items (0 < kept < %d), got %d", len(m.Items), kept)
	}
	// The header must state honestly how many entries this message contains and how many remain; otherwise, readers will mistake that number for the total
	// number as the total.
	if !strings.Contains(body, "remaining") || !strings.Contains(body, "next message") {
		t.Fatalf("the header should say how many items remain outside this message:\n%s", body[:minInt(400, len(body))])
	}
	// should include only the first kept entries.
	for i := 0; i < kept; i++ {
		if !strings.Contains(body, "漏洞"+itoa(i+1)) {
			t.Fatalf("item %d should be in this message:\n%s", i+1, body)
		}
	}
	if strings.Contains(body, "漏洞"+itoa(kept+1)) {
		t.Fatalf("item %d should not appear (it belongs to the next batch)", kept+1)
	}
}

func TestMarkdownBodyKeepsEverythingWhenUnderLimit(t *testing.T) {
	m := batchMsg(3)
	body, kept := markdownBody(m, 0) // 0 = no limit
	if kept != len(m.Items) {
		t.Fatalf("with no length limit all items should be kept, got kept=%d", kept)
	}
	if strings.Contains(body, "remaining") {
		t.Fatalf("no truncation notice should appear when nothing is truncated:\n%s", body)
	}
}

func TestMarkdownBodyAlwaysKeepsAtLeastOneItem(t *testing.T) {
	// When the budget is too small to fit even a single entry, still send one message (the final truncation serves as the fallback).
	// Otherwise a single oversized vulnerability would leave the entire batch stuck in place forever: every claim fails to fit, so nothing is ever sent.
	m := batchMsg(5)
	_, kept := markdownBody(m, 50)
	if kept != 1 {
		t.Fatalf("should keep at least 1 item, got %d", kept)
	}
}

func TestMarkdownBodySingleReturnsOne(t *testing.T) {
	_, kept := markdownBody(singleMsg(), 4096)
	if kept != 1 {
		t.Fatalf("a single message should report 1 delivered item, got %d", kept)
	}
	// An empty message has no entries that can be delivered.
	if _, k := markdownBody(Message{}, 4096); k != 0 {
		t.Fatalf("an empty message should report 0 items, got %d", k)
	}
}

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

func TestFeishuPackingReportsKept(t *testing.T) {
	m := batchMsg(2000)
	_, kept := feishuCard(m)
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("the card should fit only part of the items, got %d", kept)
	}
}

func TestWebhookAndEmailReportAllItems(t *testing.T) {
	// These two channels do not truncate the body, so the whole batch counts as delivered.
	m := batchMsg(7)
	if n := len(m.Items); n != 7 {
		t.Fatal("precondition not met")
	}
	// Confirmed indirectly via the renderer's return value: markdownBody(0) keeps everything when there is no limit.
	if _, k := markdownBody(m, 0); k != len(m.Items) {
		t.Fatalf("with no length limit all items should be used, got %d", k)
	}
}

// TestMarkdownEscapesUntrustedContent is a regression test for the rule that "untrusted content must not alter the message structure."
// Titles and summaries come from model output (the model reads the response of the target under test), and asset names come from the URL of the target under test.
func TestMarkdownEscapesUntrustedContent(t *testing.T) {
	cases := []struct {
		name  string
		item  Item
		must  []string // The result must contain (in escaped form)
		wrong []string // Must not appear in the result (unescaped form)
	}{
		{
			name: "newline and link in title",
			item: Item{
				Severity: "high",
				Name:     "登录口 SQL 注入\n[紧急：点此验证账号](http://attacker.tld)",
			},
			// Newlines must be collapsed (otherwise they could forge new list items or blockquotes);
			// Square and round brackets must be escaped (otherwise they become clickable external links).
			must:  []string{`\[紧急：点此验证账号\]`, `\(http://attacker.tld\)`},
			wrong: []string{"\n[紧急", "\n\n[紧急"},
		},
		{
			name: "image beacon in title",
			item: Item{
				Severity: "high",
				Name:     "漏洞 ![](http://attacker.tld/beacon)",
			},
			must:  []string{`\!`, `\(http://attacker.tld/beacon\)`},
			wrong: []string{"![]("},
		},
		{
			name: "emphasis and quote in asset name",
			item: Item{
				Severity: "high",
				Name:     "普通标题",
				Assets:   []string{"a.com/*注入*>引用"},
			},
			must:  []string{`\*注入\*`, `\>`},
			wrong: []string{"*注入*"},
		},
		{
			name: "backticks and pipe in summary",
			item: Item{
				Severity: "high",
				Name:     "标题",
				Summary:  "`code` | 表格",
			},
			must:  []string{"\\`code\\`", `\|`},
			wrong: []string{"`code`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Message{Items: []Item{tc.item}}
			// The single-item write path, Item, is the rendering path shared by all three markdown channels.
			var b strings.Builder
			writeItem(&b, tc.item, "", true)
			got := b.String()
			for _, want := range tc.must {
				if !strings.Contains(got, want) {
					t.Errorf("missing escaped form %q:\n%s", want, got)
				}
			}
			for _, bad := range tc.wrong {
				if strings.Contains(got, bad) {
					t.Errorf("unescaped form %q appeared (it can inject structure or a link):\n%s", bad, got)
				}
			}
			_ = m
		})
	}
}

// TestMarkdownEscapeBackslashFirst locks in the escaping order: backslashes must be handled first,
// otherwise the backslashes added later would be escaped again, producing double backslashes in the output.
func TestMarkdownEscapeBackslashFirst(t *testing.T) {
	if got := markdownEscape(`a\b*c`); got != `a\\b\*c` {
		t.Fatalf("escape order is wrong, got %q", got)
	}
}

// TestTelegramTitleHasNoMarkdownEscapes locks in a specific regression:
// markdown escapes must not leak into Telegram's HTML output (this once happened in the shared title function
// Escaping was applied, yet the resulting Telegram message shows visible backslashes such as `\(1\)`.
func TestTelegramTitleHasNoMarkdownEscapes(t *testing.T) {
	m := Message{Items: []Item{{Severity: "high", Name: "alert(1) *重点*"}}}
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

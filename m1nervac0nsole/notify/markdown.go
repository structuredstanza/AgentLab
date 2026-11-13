package notify

import "fmt"

// This file holds the title line shared by every channel renderer. Body rendering
// lives in each adapter (webhook JSON, Telegram HTML, email HTML).

// maxAssetsShown is the maximum number of assets listed in the message. A single vulnerability may anchor dozens of assets,
// listing all of them would overflow the message and add no value — nobody will look at the 4th domain onward in IM.
const maxAssetsShown = 3

// maxSummaryRunes is how many characters the summary is compressed to. The IM message is "go see the details" prompt,
// not the report body itself; the full content lives on the platform.
const maxSummaryRunes = 120

// markdownTitle returns the message title (the subject line / card title), and the content is the **unescaped original text**.
//
// Escaping is deliberately NOT done here: this title is shared by renderers in three contexts — Telegram's HTML,
// the generic Webhook's JSON and email subjects. Each context's
// escaping rules differ (escapes put into HTML leave visible backslashes, and put into JSON they pollute
// the data), so escaping must be handled by each of their output sides; see telegramEscape.
// Once added escaping in the shared function, but the result in the Telegram message
// showed visible backslashes such as `\(1\)`.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("Vulnerability summary · %d total", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "Vulnerability alert"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

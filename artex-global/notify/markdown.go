package notify

import (
	"fmt"
	"strings"
)

// This file is the message rendering shared by the "Markdown-family" channels (DingTalk, WeCom).
// Feishu card JSON, Telegram HTML, and email HTML are each rendered in their own adapter.

// maxAssetsShown is the maximum number of assets listed in the message. A single vulnerability may anchor dozens of assets,
// listing all of them would overflow the message and add no value — nobody will look at the 4th domain onward in IM.
const maxAssetsShown = 3

// maxSummaryRunes is how many characters the summary is compressed to. The IM message is "go see the details" prompt,
// not the report body itself; the full content lives on the platform.
const maxSummaryRunes = 120

// markdownReservedBytes is reserved for the message header (summary line + severity distribution + possible truncation notice)
// and the footer (platform link). When packing a whole message, this portion is deducted from the budget to guarantee the header and footer are never cut off——
// If the header or footer gets truncated, readers cannot even tell which batch this is or how many entries are not shown.
const markdownReservedBytes = 320

// markdownEscape escapes markdown metacharacters.
//
// Why this is necessary: vulnerability titles, summaries, types, and asset display names all come from **untrusted sources**——
// The title and summary come from model output (the model reads the response from the target under test), while the asset's url comes from the scan
// The resulting full URL (including the target-controllable query string). Without escaping, a vulnerability whose title is
//
//	Login page SQL injection\n[URGENT: click here to verify account](http://attacker.tld)
//
// would be rendered as a **clickable external link** in the security engineer's DingTalk/Feishu; meanwhile
// `![](http://attacker.tld/beacon)` would be fetched by the client at render time, which amounts to reporting that
// "this vulnerability has been viewed" and leaking the reader's IP. Even benign content can have injected bold text or
// block quotes that push the serious vulnerability below the fold.
//
// The escape set covers the characters that alter structure or produce clickable elements, including headings, links, emphasis, lists, blockquotes, and strikethrough.
// `\` must be handled first; otherwise the backslashes added later would be escaped again.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText flattens untrusted text into a single line and escapes it for use in the markdown body.
// Single-line flattening is the other half of escaping: a newline alone can forge a new list item or blockquote,
// But escape characters can't stop it.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns the message title (the title bar / card title on IM platforms), and the content is the **unescaped original text**.
//
// Escaping is deliberately NOT done here: this title is shared by renderers in four contexts — the markdown body, Telegram's
// HTML, the Feishu card's plain_text, and the generic Webhook's JSON and email subjects. Each context's
// escaping rules differ (markdown escapes put into HTML leave visible backslashes, and put into JSON they pollute
// the data), so escaping must be handled by each of their output sides; see writeItem / feishuItemLines /
// telegramEscape. Once added markdown escaping in the shared function, but the result in the Telegram message
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

// markdownBody renders the message body and returns the body together with the **number of entries actually written**.
//
// The return value kept is the number of entries this delivery actually delivered. The caller uses it to mark only the first kept entries as
// delivered. Entries blocked by the channel's length limit must be left for the next batch, not marked
// as successful along with the rest. This is the source of "silent loss": the message was truncated, yet the delivery record shows everything was delivered,
// and nothing anywhere can reveal that the latter part was never sent.
//
// maxBytes<=0 means no limit.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// A single entry is still sent even if it is over-long (the final truncation serves as the fallback). Partial information from one leaky entry
		// is better than sending nothing at all.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[View full on platform](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro renders the opening of the summary message: the time window, the number of entries, and the severity distribution.
// With these, the person receiving the summary can tell whether this batch needs immediate attention without opening the platform.
//
// items is what actually fits in this message, and total is the number of entries this batch should have. When the two differ, it must be stated
// "how many more entries are in the next message"; otherwise readers will assume the number in the message header is the full count,
// while the entries that were never sent simply do not exist in the interface.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**Last %d min: %d new vulnerabilities**", m.WindowMinutes, total)
	} else {
		fmt.Fprintf(&b, "**%d new vulnerabilities**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, "(this message only shows the first %d; the remaining %d will follow in the next message)", len(items), extra)
	}
	// Give the distribution by severity so readers can see at a glance whether there are any serious items. Count only the entries **actually included in this message**
	// so that "Critical 3" matches the entries that can be counted below.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders a single vulnerability entry.
//
// prefix is used for the sequence numbers in the summary list; when single=true, render the full version (including the summary and backlink),
// The summary list renders only one summary line per entry; otherwise 50 entries would turn the summary into a long document.
//
// All content from external sources (title/type/asset/summary) goes through markdownText:
// single-lining + escaping. The backlink is built from the admin-configured public_base_url, not untrusted content,
// and it must be a clickable link, so it is output as-is.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// Summary mode: presented on a single line, with the asset and summary compressed and appended after it.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**Status change**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**Type**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**Asset**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**Summary**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[View details](%s)\n", it.DetailURL)
	}
}

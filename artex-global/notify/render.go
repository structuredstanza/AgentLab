package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes truncates s to no more than max bytes, ensuring the result is valid UTF-8 and does not cut through a character.
//
// Why it must be cut on character boundaries: the WeCom group bot's markdown has a hard limit of 4096 **bytes** (not
// characters), and each Chinese character is 3 bytes. Slicing directly by bytes would split a Chinese character in half, producing invalid
// UTF-8, and the platform would either reject the whole message or display garbled boxes. The approach here is to first step back from the budget position
// to the nearest rune start byte (utf8.RuneStart identifies continuation bytes by 0b10xxxxxx).
//
// max<=0 means no limit. After truncation, an ellipsis is appended unless max is too small to fit the ellipsis.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max is shorter than the ellipsis: drop the ellipsis and truncate plainly, so the result does not end up exceeding max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine flattens multi-line text into a single line: it collapses all whitespace, then truncates by character count.
// Used for the title line of IM messages. Summaries often contain newlines, and putting them directly into a table or title would break the layout.
// max<=0 means no length limit.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes truncates s to no more than max characters (not bytes), appending an ellipsis when truncation occurs.
// max<=0 means no limit.
//
// The difference from TruncateBytes lies in the platform convention: WeCom limits length by bytes, while Telegram limits it by character count.
// Using the wrong unit silently produces no error; the message is just cut far shorter than expected (1 Chinese character = 3 bytes,
// truncating at 4096 bytes leaves only about 1365 characters), so both functions must be kept and chosen per channel.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML truncates an HTML fragment by character count and ensures no half-finished tag is produced.
//
// Truncating HTML directly by characters can cut out broken tags such as `<a href="htt`, and the platform parser will either
// reject the whole message with an error, or swallow the following body text as an attribute value. The approach here is: first truncate by characters,
// then check whether the tail has an unclosed `<`; if so, back up to just before it.
//
// No tag balancing is done (no completing </b> and the like): Telegram's HTML parser automatically closes unclosed tags,
// whereas implementing balancing ourselves would have to handle quotes in attributes, comments, and self-closing tags, so the complexity is not worth the benefit.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the tail is a fragment starting with `<` (there is no `>` after the last `<`), back up to before that `<`.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// If the tail is a truncated HTML entity (e.g. `&amp;` cut down to `&amp`), back up over it as well.
	// A stray entity fragment can cause an entity-strict parser to reject the **entire message**. A summary message exceeding
	// the length limit is already common, so it is not worth dropping the whole notification over it.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount computes how many items can fit **completely** within the budget, so that summary messages are packed by whole items.
//
// Why truncate by whole entries rather than rendering the full document and then truncating: truncation would make the later entries vanish without a trace,
// while their delivery records are still marked as delivered. The message gives no sign of this, and neither does the delivery history, so the bug goes unnoticed.
// With whole-item packing, items that don't fit stay in the database and become the next batch.
// The kept count the caller receives is exactly the number of items this message actually delivered.
//
// Parameters: maxSize<=0 means no limit; reserve is the amount reserved for the message header/footer;
// size does the measuring (platforms count differently: WeCom/DingTalk count bytes, Telegram counts characters——
// using the wrong unit won't raise an error, it will only cause Chinese messages to be packed far below the limit);
// render turns item idx into its actual rendered text—its length varies with content, so it cannot be estimated.
//
// Returns at least 1 (as long as items remain). Even when a single item is extremely long, that item must still be sent, leaving it to the caller's
// final truncation fallback; otherwise one oversized item would permanently stall the entire batch in place.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize are the two measuring units for packItemCount; naming them avoids bare func(s string) int closures at call sites,
// a bare func(s string) int closure appears; otherwise it is hard to tell at a glance which unit is being used.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine renders the asset list as a single line of display text. When there are more than limit items, it omits the rest and notes the total count.
// A single vulnerability may anchor dozens of assets; listing them all would blow up the message.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " and " + itoa(len(assets)) + " total"
}

// itoa is a short alias for strconv.Itoa, used only for building display text, to avoid importing strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

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
// Telegram limits length by character count; the remaining channels either have no hard limit or do their own packing.
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
// size does the measuring (Telegram counts characters; a wrong unit only makes the message pack far below the limit);
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

// runeSize is the measuring unit for packItemCount; naming it avoids a bare func(s string) int closure at the call site.
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

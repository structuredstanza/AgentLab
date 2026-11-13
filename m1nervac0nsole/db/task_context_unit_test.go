package db

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8PreservesValidEncoding(t *testing.T) {
	t.Parallel()
	// 3-byte runes, written as escapes so the source stays ASCII. 1000 is not a multiple of 3,
	// so a byte-oriented cut lands mid-rune; with an ASCII input every offset is valid and the
	// rune-boundary loop in truncateUTF8 was never exercised.
	input := strings.Repeat("\u989d\u5ea6\u4e0d\u8db3", 400)
	got := truncateUTF8(input, 1000)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated value is not valid UTF-8: %q", got[len(got)-8:])
	}
	if len(got) != 999 {
		t.Fatalf("truncated value has %d bytes, want 999 (the last whole rune within 1000)", len(got))
	}
}

func TestTruncateUTF8RepairsInvalidInput(t *testing.T) {
	t.Parallel()
	got := truncateUTF8("bad\xffvalue", 1000)
	if !utf8.ValidString(got) {
		t.Fatalf("repaired value is not valid UTF-8: %q", got)
	}
}

package browser

import (
	"testing"
)

// Console entries arrive in order with a cursor that only moves forward, and
// an uncaught exception is one readable line.
func TestConsoleRecordsOrderAndSeq(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)

	f.emit("Runtime.consoleAPICalled", map[string]any{
		"type": "log",
		"args": []any{
			map[string]any{"type": "string", "value": "hello"},
			map[string]any{"type": "number", "value": 42},
		},
		"stackTrace": map[string]any{"callFrames": []any{
			map[string]any{"url": "https://example.test/app.js", "lineNumber": 6},
		}},
	})
	f.emit("Runtime.consoleAPICalled", map[string]any{
		"type": "error",
		"args": []any{map[string]any{"type": "string", "value": "failed"}},
	})
	f.emit("Runtime.exceptionThrown", map[string]any{
		"exceptionDetails": map[string]any{
			"text":       "Uncaught",
			"url":        "https://example.test/app.js",
			"lineNumber": 9,
			"exception": map[string]any{
				"type":        "object",
				"description": "Error: boom\n    at app.js:10:3",
			},
		},
	})

	entries := d.Console(0, 0)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	if entries[0].Seq != 1 || entries[1].Seq != 2 || entries[2].Seq != 3 {
		t.Fatalf("seq = %d,%d,%d, want 1,2,3", entries[0].Seq, entries[1].Seq, entries[2].Seq)
	}
	if entries[0].Level != "log" || entries[0].Text != "hello 42" {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[0].URL != "https://example.test/app.js" || entries[0].Line != 7 {
		t.Fatalf("first entry location = %s:%d, want app.js:7", entries[0].URL, entries[0].Line)
	}
	if entries[1].Level != "error" || entries[1].Text != "failed" {
		t.Fatalf("second entry = %+v", entries[1])
	}
	if entries[2].Level != "exception" || entries[2].Text != "Uncaught: Error: boom" {
		t.Fatalf("exception entry = %+v", entries[2])
	}
	if entries[2].URL != "https://example.test/app.js" || entries[2].Line != 10 {
		t.Fatalf("exception location = %s:%d, want app.js:10", entries[2].URL, entries[2].Line)
	}
	if got := d.ConsoleSeq(); got != 3 {
		t.Fatalf("ConsoleSeq = %d, want 3", got)
	}
}

// The ring keeps the newest 200 entries and the cursor keeps counting.
func TestConsoleRingCapsAt200(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	for range 250 {
		f.emit("Runtime.consoleAPICalled", map[string]any{
			"type": "log",
			"args": []any{map[string]any{"type": "string", "value": "line"}},
		})
	}

	entries := d.Console(0, consoleRing)
	if len(entries) != consoleRing {
		t.Fatalf("entries = %d, want %d", len(entries), consoleRing)
	}
	if entries[0].Seq != 51 || entries[len(entries)-1].Seq != 250 {
		t.Fatalf("seq range = %d..%d, want 51..250", entries[0].Seq, entries[len(entries)-1].Seq)
	}
	if got := d.ConsoleSeq(); got != 250 {
		t.Fatalf("ConsoleSeq = %d, want 250", got)
	}
}

// since is the cursor from the previous call, and limit is the page size.
func TestConsoleSinceAndLimit(t *testing.T) {
	f := newFakeConn()
	d := newTestDriver(t, f, nil)
	for range 5 {
		f.emit("Runtime.consoleAPICalled", map[string]any{
			"type": "log",
			"args": []any{map[string]any{"type": "string", "value": "line"}},
		})
	}

	entries := d.Console(2, 0)
	if len(entries) != 3 || entries[0].Seq != 3 || entries[2].Seq != 5 {
		t.Fatalf("since=2 entries = %+v, want seq 3..5", entries)
	}
	if entries := d.Console(0, 2); len(entries) != 2 || entries[1].Seq != 2 {
		t.Fatalf("limit=2 entries = %+v, want the first two", entries)
	}
	if entries := d.Console(5, 0); len(entries) != 0 {
		t.Fatalf("since=5 entries = %+v, want none", entries)
	}
}

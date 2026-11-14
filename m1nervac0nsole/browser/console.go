package browser

import (
	"encoding/json"
	"fmt"
	"strings"
)

// consoleRing is how many entries a driver keeps. The caller reads a window
// and advances a cursor, so old entries age out instead of growing forever.
const consoleRing = 200

// ConsoleEntry is one console message or uncaught exception.
type ConsoleEntry struct {
	Seq   int64
	Level string
	Text  string
	URL   string
	Line  int
}

// remoteObject is the part of a CDP RemoteObject a log line needs.
type remoteObject struct {
	Type                string          `json:"type"`
	Value               json.RawMessage `json:"value"`
	Description         string          `json:"description"`
	UnserializableValue string          `json:"unserializableValue"`
}

// consoleAPICalled buffers one console message. The level is the CDP type
// (log, info, warning, error, ...), which is what an operator expects to see.
func (d *Driver) consoleAPICalled(params json.RawMessage) {
	var ev struct {
		Type       string         `json:"type"`
		Args       []remoteObject `json:"args"`
		StackTrace *struct {
			CallFrames []struct {
				URL        string `json:"url"`
				LineNumber int    `json:"lineNumber"`
			} `json:"callFrames"`
		} `json:"stackTrace"`
	}
	if json.Unmarshal(params, &ev) != nil {
		return
	}

	parts := make([]string, 0, len(ev.Args))
	for _, arg := range ev.Args {
		parts = append(parts, remoteText(arg))
	}
	entry := ConsoleEntry{Level: ev.Type, Text: strings.Join(parts, " ")}
	if ev.StackTrace != nil && len(ev.StackTrace.CallFrames) > 0 {
		frame := ev.StackTrace.CallFrames[0]
		entry.URL = frame.URL
		entry.Line = frame.LineNumber + 1
	}
	d.addConsole(entry)
}

// exceptionThrown buffers one uncaught exception. CDP splits the message over
// text and the thrown object's description, so both are joined into the one
// line an operator reads.
func (d *Driver) exceptionThrown(params json.RawMessage) {
	var ev struct {
		ExceptionDetails struct {
			Text       string        `json:"text"`
			URL        string        `json:"url"`
			LineNumber int           `json:"lineNumber"`
			Exception  *remoteObject `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if json.Unmarshal(params, &ev) != nil {
		return
	}

	text := ev.ExceptionDetails.Text
	if ex := ev.ExceptionDetails.Exception; ex != nil && ex.Description != "" {
		description := firstLine(ex.Description)
		switch {
		case text == "":
			text = description
		case !strings.Contains(text, description):
			text += ": " + description
		}
	}
	d.addConsole(ConsoleEntry{
		Level: "exception",
		Text:  text,
		URL:   ev.ExceptionDetails.URL,
		Line:  ev.ExceptionDetails.LineNumber + 1,
	})
}

func (d *Driver) addConsole(entry ConsoleEntry) {
	d.mu.Lock()
	d.consoleSeq++
	entry.Seq = d.consoleSeq
	if len(d.console) == consoleRing {
		copy(d.console, d.console[1:])
		d.console[consoleRing-1] = entry
	} else {
		d.console = append(d.console, entry)
	}
	d.mu.Unlock()
}

// Console returns entries newer than since, oldest first. A limit of zero is
// the default window; the ring itself caps any larger request.
func (d *Driver) Console(since int64, limit int) []ConsoleEntry {
	if limit <= 0 {
		limit = 50
	}
	if limit > consoleRing {
		limit = consoleRing
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]ConsoleEntry, 0, limit)
	for _, entry := range d.console {
		if entry.Seq <= since {
			continue
		}
		out = append(out, entry)
		if len(out) == limit {
			break
		}
	}
	return out
}

// ConsoleSeq is the cursor to pass to the next Console call.
func (d *Driver) ConsoleSeq() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.consoleSeq
}

// remoteText renders one console argument. A string argument is its own text;
// anything else falls back to the shape CDP describes.
func remoteText(obj remoteObject) string {
	if len(obj.Value) > 0 && string(obj.Value) != "null" {
		var value any
		if json.Unmarshal(obj.Value, &value) == nil {
			if text, ok := value.(string); ok {
				return text
			}
			return fmt.Sprint(value)
		}
	}
	if obj.Description != "" {
		return firstLine(obj.Description)
	}
	if obj.UnserializableValue != "" {
		return obj.UnserializableValue
	}
	return obj.Type
}

func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
}

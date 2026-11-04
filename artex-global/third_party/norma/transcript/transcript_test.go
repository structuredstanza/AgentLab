package transcript

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// A message whose content cannot be marshaled is dropped: the write fails, Err is set,
// and nothing drains Err. The log line in write is the only signal, so this pins the
// condition that produces it. Without it a lost message is indistinguishable from one
// that was never recorded, and the transcript silently stops being the full history.
func TestUnserializableMessageIsReportedAndOmitted(t *testing.T) {
	store := NewStore(t.TempDir())
	w := store.NewWriter("s1", "")

	// An invalid RawMessage in a tool call is the real shape of this failure.
	w.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
		Type:  llm.BlockToolUse,
		ID:    "c1",
		Name:  "x",
		Input: json.RawMessage(`{"a":1}{"b":2}`),
	}}}, llm.Usage{})
	if w.Err() == nil {
		t.Fatal("Err is nil, so the loss would be silent")
	}

	// The writer must keep working for subsequent records.
	w.RecordMessage(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
		{Type: llm.BlockText, Text: "hi"},
	}}, llm.Usage{})

	recs, err := store.Load(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want only the valid record on disk, got %d", len(recs))
	}
	if recs[0].Message == nil || recs[0].Message.Content[0].Text != "hi" {
		t.Fatalf("the wrong record survived: %+v", recs[0].Message)
	}
}

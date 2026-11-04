package server

import (
	"context"
	"strings"
	"testing"
)

// list_tools is where an agent looks before running anything, so the engagement's
// rate guidance has to appear there. It is emitted per call rather than stored in
// the tool description, because descriptions are persisted and UI-editable: a
// rebuilt binary would otherwise keep serving the text it seeded on first run.
func TestListToolsStatesTheRateGuidance(t *testing.T) {
	s := &Server{}
	result, err := s.toolListManifests().Call(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := ""
	for _, block := range result.Content {
		out += block.Text
	}
	if !strings.Contains(out, "Choose rates") {
		t.Fatalf("list_tools output carries no rate guidance:\n%s", out)
	}
	if !strings.Contains(out, "requests a minute") {
		t.Fatalf("guidance does not state the request ceiling:\n%s", out)
	}
}

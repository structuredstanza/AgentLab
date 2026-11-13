package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func listToolsText(t *testing.T, in string) string {
	t.Helper()
	res, err := (&Server{}).toolListManifests().Call(context.Background(), json.RawMessage(in), nil)
	if err != nil {
		t.Fatalf("list_tools: %v", err)
	}
	return res.Flatten()
}

// The catalog is long enough that a model asking for one tool should get one
// tool, and an empty result must say so rather than look like a broken catalog.
func TestListToolsFiltersByQuery(t *testing.T) {
	all := listToolsText(t, `{}`)
	if !strings.Contains(all, "nmap") || !strings.Contains(all, "ffuf") {
		t.Fatalf("the unfiltered catalog is missing tools:\n%s", all[:min(len(all), 400)])
	}

	narrowed := listToolsText(t, `{"query":"nmap"}`)
	if !strings.Contains(narrowed, "- nmap") {
		t.Fatalf("query nmap did not return nmap:\n%s", narrowed)
	}
	if strings.Contains(narrowed, "- ffuf") {
		t.Fatalf("query nmap returned unrelated tools:\n%s", narrowed)
	}
	if !strings.Contains(narrowed, "of") || !strings.Contains(narrowed, "match") {
		t.Fatalf("the narrowed header does not report the count:\n%s", narrowed)
	}

	empty := listToolsText(t, `{"query":"zzz-no-such-tool"}`)
	if !strings.Contains(empty, "no tool matches") {
		t.Fatalf("an empty result is not explained:\n%s", empty)
	}
}

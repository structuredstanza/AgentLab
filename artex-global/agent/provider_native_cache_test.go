package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// The native Claude path must send blocks, not a joined string, or the cache
// breakpoint is discarded before it reaches the wire.
func TestNativeSystemBlocksCarriesTheBreakpoint(t *testing.T) {
	req := llm.CompletionRequest{System: []string{"static", "dynamic"}, DynamicBoundary: 1}
	raw, err := json.Marshal(nativeSystemBlocks(req))
	if err != nil {
		t.Fatal(err)
	}
	var blocks []struct {
		Text         string         `json:"text"`
		CacheControl map[string]any `json:"cache_control"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("want 2 blocks, got %d", len(blocks))
	}
	if blocks[0].CacheControl == nil || blocks[0].CacheControl["type"] != "ephemeral" {
		t.Errorf("static block not marked cacheable: %+v", blocks[0])
	}
	if blocks[1].CacheControl != nil {
		t.Errorf("dynamic block marked cacheable: %+v", blocks[1])
	}
}

// An all-static prompt must not be split into an empty tail, and a prompt with no
// declared prefix must not be marked cacheable at all.
func TestNativeSystemBlocksEdgeCases(t *testing.T) {
	allStatic := nativeSystemBlocks(llm.CompletionRequest{System: []string{"a", "b"}, DynamicBoundary: 2})
	if len(allStatic) != 1 || allStatic[0]["cache_control"] == nil {
		t.Fatalf("all-static prompt not cached in one block: %+v", allStatic)
	}

	none := nativeSystemBlocks(llm.CompletionRequest{System: []string{"a"}})
	if len(none) != 1 || none[0]["cache_control"] != nil {
		t.Fatalf("no-boundary prompt should be one unmarked block: %+v", none)
	}

	if got := nativeSystemBlocks(llm.CompletionRequest{}); got != nil {
		t.Fatalf("empty system should yield no blocks, got %+v", got)
	}
}

package llm

import (
	"encoding/json"
	"testing"
)

// The static prefix must carry the breakpoint and the per-turn tail must not: a
// breakpoint on content that changes every turn would never hit.
func TestBuildAnthropicSystemMarksOnlyTheStaticPrefix(t *testing.T) {
	req := CompletionRequest{
		System:          []string{"static rules", "more static", "current time: 12:00"},
		DynamicBoundary: 2,
	}
	blocks := buildAnthropicSystem(req)
	if len(blocks) != 2 {
		t.Fatalf("want 2 blocks, got %d", len(blocks))
	}
	if blocks[0].CacheControl == nil {
		t.Error("static prefix has no cache_control")
	}
	if blocks[0].Text != "static rules\n\nmore static" {
		t.Errorf("static text = %q", blocks[0].Text)
	}
	if blocks[1].CacheControl != nil {
		t.Error("dynamic tail must not be marked cacheable")
	}
	if blocks[1].Text != "current time: 12:00" {
		t.Errorf("dynamic text = %q", blocks[1].Text)
	}
}

// Without a declared boundary there is no known-static prefix, so nothing may be
// marked: a wrong breakpoint costs a cache write that is never read.
func TestBuildAnthropicSystemWithoutBoundaryMarksNothing(t *testing.T) {
	blocks := buildAnthropicSystem(CompletionRequest{System: []string{"a", "b"}})
	if len(blocks) != 1 || blocks[0].CacheControl != nil {
		t.Fatalf("unexpected blocks: %+v", blocks)
	}
}

// An all-static prompt is still cacheable, and must not be split into an empty tail.
func TestBuildAnthropicSystemBoundaryAtEndCachesEverything(t *testing.T) {
	blocks := buildAnthropicSystem(CompletionRequest{System: []string{"a", "b"}, DynamicBoundary: 2})
	if len(blocks) != 1 || blocks[0].CacheControl == nil {
		t.Fatalf("unexpected blocks: %+v", blocks)
	}
}

// The cache key has to stay identical as the conversation grows, or every turn
// routes to a different shard and nothing is ever reused.
func TestPromptCacheKeyIsStableAcrossTurns(t *testing.T) {
	first := CompletionRequest{System: []string{"rules", "now: 12:00"}, DynamicBoundary: 1}
	second := CompletionRequest{System: []string{"rules", "now: 12:05"}, DynamicBoundary: 1}
	if promptCacheKey(first) == "" {
		t.Fatal("no key for a request with a static prefix")
	}
	if promptCacheKey(first) != promptCacheKey(second) {
		t.Error("key changed when only the dynamic tail changed")
	}

	other := CompletionRequest{System: []string{"different rules", "now: 12:00"}, DynamicBoundary: 1}
	if promptCacheKey(first) == promptCacheKey(other) {
		t.Error("a different static prefix produced the same key")
	}
}

// No declared prefix means no safe key; sending an arbitrary one would mix
// unrelated conversations into a single cache shard.
func TestPromptCacheKeyEmptyWithoutBoundary(t *testing.T) {
	if got := promptCacheKey(CompletionRequest{System: []string{"a"}}); got != "" {
		t.Errorf("key without a boundary = %q, want empty", got)
	}
}

// The key must actually reach the wire, not just be computed.
func TestBuildBodySendsThePromptCacheKey(t *testing.T) {
	p := &openaiProvider{cfg: Config{Model: "m"}}
	raw, err := p.buildBody(CompletionRequest{
		System:          []string{"static rules", "dynamic"},
		DynamicBoundary: 1,
		Messages:        []Message{{Role: RoleUser, Content: []ContentBlock{{Type: BlockText, Text: "hi"}}}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["prompt_cache_key"] == nil || body["prompt_cache_key"] == "" {
		t.Fatalf("prompt_cache_key absent from the request body: %s", raw)
	}
}

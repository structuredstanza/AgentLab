package db

import (
	"strconv"
	"testing"
)

// The matcher is compiled once per identifier: promotion and generalisation run
// it over every field of every candidate, so a compile per call was the hot
// path. The cache must not change what the scrubber does.
func TestTargetIdentifierRECaches(t *testing.T) {
	first := targetIdentifierRE("api.example.com")
	second := targetIdentifierRE("api.example.com")
	if first != second {
		t.Fatal("the same identifier compiled twice")
	}
	if other := targetIdentifierRE("other.example"); other == first {
		t.Fatal("two identifiers share one matcher")
	}
	text, n := ScrubTargetIdentifiers("see api.example.com and api.example.com/x", []string{"api.example.com"})
	if n != 2 || text != "see <target> and <target>/x" {
		t.Fatalf("scrub = %q (%d), want two <target>", text, n)
	}
}

// A cache keyed by text an agent can influence must not grow without a bound.
func TestTargetIdentifierREStaysBounded(t *testing.T) {
	for i := 0; i < targetIdentifierRESize+10; i++ {
		targetIdentifierRE("host-" + strconv.Itoa(i))
	}
	n := 0
	targetIdentifierREs.Range(func(any, any) bool { n++; return true })
	if n > targetIdentifierRESize {
		t.Fatalf("cache holds %d entries, want at most %d", n, targetIdentifierRESize)
	}
}

func BenchmarkScrubTargetIdentifiers(b *testing.B) {
	ids := []string{"api.example.com", "10.10.17.49", "acme-internal"}
	text := "the api.example.com host at 10.10.17.49 belongs to acme-internal"
	for b.Loop() {
		_, _ = ScrubTargetIdentifiers(text, ids)
	}
}

package server

import "testing"

// A model writes service:true and timing:4 as JSON scalars; the strict
// map[string]string it replaced rejected the whole call and cost a turn.
func TestParamStringsAcceptsScalars(t *testing.T) {
	got, err := paramStrings(map[string]any{"service": true, "rate": float64(150), "ratio": 1.5, "ports": "1-1000", "skip": nil})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"service": "true", "rate": "150", "ratio": "1.5", "ports": "1-1000"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, err := paramStrings(map[string]any{"nested": map[string]any{"a": 1}}); err == nil {
		t.Error("a nested value must be rejected: no manifest parameter takes one")
	}
}

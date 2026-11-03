package catalog

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/artex/cliproxyhost/internal/contract"
)

func TestArgonThinkingRoutePreservesLogicalProfileAndNativePayload(t *testing.T) {
	for _, tc := range []struct {
		level, wire string
		invalid     bool
	}{
		{"", "gemini-4-argon-low", false},
		{"low", "gemini-4-argon-low", false},
		{"medium", "gemini-4-argon-medium", false},
		{"high", "gemini-4-argon-high", false},
		{"minimal", "", true},
	} {
		t.Run(tc.level, func(t *testing.T) {
			raw := json.RawMessage(`{"generationConfig":{"thinkingConfig":{"thinkingLevel":"` + tc.level + `"}},"contents":[{"role":"user","parts":[{"text":"task"}]}]}`)
			wire, payload, err := Resolve(contract.ProviderAntigravity, "gemini-4-argon", raw)
			if tc.invalid {
				if err == nil {
					t.Fatal("unsupported level admitted")
				}
				return
			}
			if err != nil || wire != tc.wire || string(payload) != string(raw) {
				t.Fatalf("logical route changed native input or selected wrong SKU: wire=%s err=%v", wire, err)
			}
		})
	}
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	models, err := c.Models(contract.ProviderAntigravity)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range models {
		if m.ID == "gemini-4-argon" {
			return
		}
	}
	t.Fatal("configured logical model disappeared from the public catalog")
}

func TestUnknownProviderIsRejected(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Models(contract.Provider("bogus")); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Models(bogus) error = %v, want ErrUnknownProvider", err)
	}
}

func TestReturnedSlicesAreIndependentCopies(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := c.Models(contract.ProviderClaude)
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	want := first[0].ID
	first[0].ID = "mutated"
	if len(first[0].SupportedEfforts) > 0 {
		first[0].SupportedEfforts[0] = "mutated"
	}
	second, err := c.Models(contract.ProviderClaude)
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if second[0].ID != want {
		t.Fatalf("caller mutation leaked into catalog: got %q, want %q", second[0].ID, want)
	}
}

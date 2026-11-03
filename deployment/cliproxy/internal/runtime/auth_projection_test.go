package runtime

import (
	"bytes"
	"testing"

	"github.com/artex/cliproxyhost/internal/contract"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCoreAuthFromRecordEnforcesRuntimeCloakingWithoutPersistingOverrides(t *testing.T) {
	raw := []byte(`{"disabled":true,"proxy_url":"http://untrusted.invalid","base_url":"https://untrusted.invalid","headers":{"X-Client":"untrusted"},"header:X-Client":"untrusted","cloak_mode":"never","cloak_strict_mode":"true","access_token":"fixture-access"}`)
	original := bytes.Clone(raw)

	claude, err := coreAuthFromRecord(contract.ProviderClaude, &contract.Record{CoreAuthID: "fixture-claude-epoch", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if claude.Disabled || claude.Status != coreauth.StatusActive || claude.ProxyURL != "" {
		t.Fatalf("Claude runtime auth admission is not active and local: %#v", claude)
	}
	if claude.Metadata["cloak_mode"] != "always" || claude.Metadata["cloak_strict_mode"] != "false" {
		t.Fatalf("Claude runtime cloaking = (%v, %v), want (always, false)", claude.Metadata["cloak_mode"], claude.Metadata["cloak_strict_mode"])
	}
	for _, key := range []string{"disabled", "proxy_url", "base_url", "headers", "header:X-Client"} {
		if _, exists := claude.Metadata[key]; exists {
			t.Fatalf("Claude runtime metadata propagated override %q", key)
		}
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("runtime projection mutated stored raw grant")
	}

	codex, err := coreAuthFromRecord(contract.ProviderCodex, &contract.Record{CoreAuthID: "fixture-codex-epoch", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if codex.Disabled || codex.Status != coreauth.StatusActive || codex.ProxyURL != "" {
		t.Fatalf("Codex runtime auth admission is not active and local: %#v", codex)
	}
	if codex.Attributes[coreauth.AttributeCodexDisableCloaking] != "false" {
		t.Fatalf("Codex cloak override = %q, want false", codex.Attributes[coreauth.AttributeCodexDisableCloaking])
	}
	for _, key := range []string{"disabled", "proxy_url", "base_url", "headers", "header:X-Client"} {
		if _, exists := codex.Metadata[key]; exists {
			t.Fatalf("Codex runtime metadata propagated override %q", key)
		}
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("runtime projection mutated stored raw grant")
	}
	antigravity, err := coreAuthFromRecord(contract.ProviderAntigravity, &contract.Record{CoreAuthID: "fixture-antigravity-epoch", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if antigravity.Disabled || antigravity.Status != coreauth.StatusActive || antigravity.ProxyURL != "" {
		t.Fatalf("Antigravity runtime auth admission is not active and local: %#v", antigravity)
	}
	for _, key := range []string{"disabled", "proxy_url", "base_url", "headers", "header:X-Client"} {
		if _, exists := antigravity.Metadata[key]; exists {
			t.Fatalf("Antigravity runtime metadata propagated override %q", key)
		}
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("runtime projection mutated stored raw grant")
	}
}

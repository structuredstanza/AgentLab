package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestTaskLLMResolution pins the no-DB reasons returned by resolutionFromProfile for a
// nil profile and for a profile with a blank API key.
func TestTaskLLMResolution(t *testing.T) {
	// 2) Pin the two reasons reachable with no DB. resolutionFromProfile returns
	// before touching providerForProfile for a nil profile and for a profile with
	// a blank API key, so a zero-value Server exercises the real code path.
	s := &Server{}

	missing := s.resolutionFromProfile(nil, "task_chain")
	if missing.Available {
		t.Fatalf("nil profile must be unavailable, got %+v", missing)
	}
	if missing.Reason != reasonLLMProfileMissing {
		t.Fatalf("nil profile reason = %q, want %q", missing.Reason, reasonLLMProfileMissing)
	}

	noKey := s.resolutionFromProfile(&db.LLMProfile{Name: "p", Format: "openai", Model: "m"}, "task_chain")
	if noKey.Available {
		t.Fatalf("blank API key must be unavailable, got %+v", noKey)
	}
	if noKey.Reason != reasonLLMProfileNoAPIKey {
		t.Fatalf("blank-key reason = %q, want %q", noKey.Reason, reasonLLMProfileNoAPIKey)
	}
}

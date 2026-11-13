package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

func mustProfile(t *testing.T, s string) contract.ProfileID {
	t.Helper()
	p, err := contract.ParseProfileID(s)
	if err != nil {
		t.Fatalf("parse profile %q: %v", s, err)
	}
	return p
}

func sampleRecord(core string) *contract.Record {
	return &contract.Record{CoreAuthID: core, Email: "u@example.test", Raw: []byte(`{"refresh_token":"r1"}`)}
}

func TestSaveRejectsStaleGeneration(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "proxy-state"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p := mustProfile(t, "7")

	gen, err := s.Save(ctx, p, contract.ProviderClaude, 0, sampleRecord("core-a"))
	if err != nil || gen != 1 {
		t.Fatalf("first save: gen=%d err=%v", gen, err)
	}
	if _, err := s.Save(ctx, p, contract.ProviderClaude, 0, sampleRecord("core-b")); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale save: want ErrStaleGeneration, got %v", err)
	}
	got, err := s.Load(ctx, p, contract.ProviderClaude)
	if err != nil || got.CoreAuthID != "core-a" {
		t.Fatalf("stale save changed grant: %+v err=%v", got, err)
	}
	if gen, err := s.Save(ctx, p, contract.ProviderClaude, 1, sampleRecord("core-c")); err != nil || gen != 2 {
		t.Fatalf("current save: gen=%d err=%v", gen, err)
	}
}

func TestProfileIsolation(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "proxy-state"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.Save(ctx, mustProfile(t, "1"), contract.ProviderCodex, 0, sampleRecord("core-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, mustProfile(t, "2"), contract.ProviderCodex); !errors.Is(err, ErrNotFound) {
		t.Fatalf("profile 2 saw profile 1 grant: %v", err)
	}
}

func TestRejectsNonCanonicalProfileID(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "proxy-state"))
	if err != nil {
		t.Fatal(err)
	}
	// Built directly because ParseProfileID would reject it before the store sees it.
	bad := contract.ProfileID("../escape")
	if _, err := s.Load(context.Background(), bad, contract.ProviderClaude); err == nil {
		t.Fatal("traversal profile id accepted")
	}
}

func TestModesAndDeleteAll(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proxy-state")
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p := mustProfile(t, "9")
	if _, err := s.Save(ctx, p, contract.ProviderAntigravity, 0, sampleRecord("core-9")); err != nil {
		t.Fatal(err)
	}

	assertMode := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode %o, want %o", path, got, want)
		}
	}
	assertMode(root, 0o700)
	assertMode(filepath.Join(root, "9"), 0o700)
	assertMode(filepath.Join(root, "9", "antigravity.json"), 0o600)
	assertMode(filepath.Join(root, "9", "antigravity.gen"), 0o600)

	if err := s.DeleteAll(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "9")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile dir survived DeleteAll: %v", err)
	}
	if _, err := s.Load(ctx, p, contract.ProviderAntigravity); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grant survived DeleteAll: %v", err)
	}
}

package privacy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/artex/cliproxyhost/internal/contract"
)

func TestReceiptRoundTripAndBinding(t *testing.T) {
	rc, err := NewReceipts(filepath.Join(t.TempDir(), "receipt.key"))
	if err != nil {
		t.Fatal(err)
	}
	b := contract.Binding{Provider: contract.ProviderCodex, Model: "m", Profile: "7", SessionID: "sess", CredentialID: "grant-a"}
	state := []byte("state")
	r, err := rc.Sign(b, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Verify(r, b, state); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	if rc.Verify(r, b, []byte("other")) == nil {
		t.Fatal("receipt verified for different state")
	}
	other := b
	other.CredentialID = "grant-b"
	if rc.Verify(r, other, state) == nil {
		t.Fatal("receipt verified after credential/grant epoch changed")
	}
	tampered := []byte(r)
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	if rc.Verify(string(tampered), b, state) == nil {
		t.Fatal("tampered receipt verified")
	}
}

func TestReceiptKeyPersistsAcrossLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.key")
	first, err := NewReceipts(path)
	if err != nil {
		t.Fatal(err)
	}
	b := contract.Binding{Provider: contract.ProviderClaude, Model: "m", Profile: "1", SessionID: "s", CredentialID: "grant-a"}
	r, err := first.Sign(b, []byte("st"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewReceipts(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Verify(r, b, []byte("st")); err != nil {
		t.Fatalf("reloaded key rejected receipt: %v", err)
	}
}

func TestReceiptKeyCreatedPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.key")
	if _, err := NewReceipts(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestReceiptKeyRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceipts(path); err == nil {
		t.Fatal("group/world-readable key was accepted")
	}
}

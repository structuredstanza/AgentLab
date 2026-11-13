package privacy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

// receiptDomain separates receipt signatures from any other use of the host key.
const receiptDomain = "m1nervac0nsole-cliproxy-replay-receipt-v1\x00"

var errReceipt = errors.New("replay receipt rejected")

type receipts struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewReceipts loads the host Ed25519 seed stored at path. When the file is
// absent it is created exclusively with mode 0600.
func NewReceipts(path string) (contract.Receipts, error) {
	seed, err := loadOrCreateSeed(path)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &receipts{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

func loadOrCreateSeed(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("receipt key %s must be a regular file without group or world permissions", path)
		}
		seed, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, errors.New("receipt key has an invalid size")
		}
		return seed, nil
	case errors.Is(err, os.ErrNotExist):
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(seed); err != nil {
			f.Close()
			os.Remove(path)
			return nil, err
		}
		if err := f.Close(); err != nil {
			os.Remove(path)
			return nil, err
		}
		return seed, nil
	default:
		return nil, err
	}
}

// Sign binds an admitted native assistant state to the exact binding.
func (r *receipts) Sign(b contract.Binding, state []byte) (string, error) {
	if len(state) == 0 || b.SessionID == "" || b.CredentialID == "" {
		return "", errReceipt
	}
	sig := ed25519.Sign(r.priv, signedMessage(b, state))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify returns nil only when the receipt covers exactly this state and binding.
func (r *receipts) Verify(receipt string, b contract.Binding, state []byte) error {
	sig, err := base64.RawURLEncoding.Strict().DecodeString(receipt)
	if err != nil || len(sig) != ed25519.SignatureSize || len(state) == 0 || b.CredentialID == "" {
		return errReceipt
	}
	if !ed25519.Verify(r.pub, signedMessage(b, state), sig) {
		return errReceipt
	}
	return nil
}

// signedMessage frames every binding field with a length prefix so that no two
// distinct bindings produce the same bytes.
func signedMessage(b contract.Binding, state []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(receiptDomain)
	for _, f := range []string{string(b.Provider), b.Model, string(b.Profile), b.SessionID, b.CredentialID} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		buf.Write(n[:])
		buf.WriteString(f)
	}
	sum := sha256.Sum256(state)
	buf.Write(sum[:])
	return buf.Bytes()
}

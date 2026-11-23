package execbox

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultCACert is the recorder's public CA certificate in the guest. The
// backend hands every client this same absolute path (SSL_CERT_FILE and the
// other trust variables), so the supervisor mounts the certificate at it inside
// each session: no caller needs a second, session-only path.
const DefaultCACert = "/state/m1nervac0nsole/traffic/_ca/mitmproxy-ca-cert.pem"

// maxCACertBytes bounds what the supervisor reads from the CA directory, whose
// owner is the backend. A real public certificate is about 1 KiB.
const maxCACertBytes = 64 << 10

// publicCA returns the PEM of the recorder's public CA certificate, re-encoded
// from the certificates alone, and its SHA-256 fingerprint. The CA directory
// also holds the signing key, so anything that is not a plain certificate file
// is refused rather than filtered. A missing file is not an error: the backend
// creates the CA when it starts, after the supervisor, and every session looks
// again. A nil PEM means "no CA yet".
func (s *Supervisor) publicCA() (certPEM []byte, fingerprint string, err error) {
	path := s.cfg.CACert
	if path == "" {
		return nil, "", nil
	}
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("execbox: recorder CA %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxCACertBytes {
		return nil, "", fmt.Errorf("execbox: recorder CA %s is not a small regular file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("execbox: recorder CA %s: %w", path, err)
	}
	// shortcut: a substring check, not a parse, decides "holds a key"; any PEM
	// armour naming a key is refused, upgrade only if a certificate legitimately
	// carries such a word.
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		return nil, "", fmt.Errorf("execbox: recorder CA %s contains a private key; refusing to expose it", path)
	}
	var out []byte
	var first *x509.Certificate
	for rest := raw; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("execbox: recorder CA %s holds a %s block, not only certificates", path, blk.Type)
		}
		c, perr := x509.ParseCertificate(blk.Bytes)
		if perr != nil {
			return nil, "", fmt.Errorf("execbox: recorder CA %s: %w", path, perr)
		}
		if first == nil {
			first = c
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})...)
	}
	if first == nil {
		return nil, "", fmt.Errorf("execbox: recorder CA %s holds no certificate", path)
	}
	if !first.IsCA {
		return nil, "", fmt.Errorf("execbox: recorder CA %s is not a CA certificate", path)
	}
	sum := sha256.Sum256(first.Raw)
	return out, hex.EncodeToString(sum[:]), nil
}

// stageCA copies the current public CA into dir and returns the copy's path,
// or "" when the recorder has no CA yet. The session mounts the copy, not the
// original, so a rotation mid-session cannot change what a running client
// trusts, and the signing key's directory is never a mount source. Creation and
// rotation are logged once, with the fingerprint.
func (s *Supervisor) stageCA(dir string) (string, error) {
	certPEM, fp, err := s.publicCA()
	if err != nil {
		return "", err
	}
	s.caMu.Lock()
	if fp != s.caFP {
		switch {
		case s.caFP == "":
			s.cfg.Logf("[execbox] recorder CA available: sha256=%s", fp)
		case fp == "":
			s.cfg.Logf("[execbox] recorder CA gone (was sha256=%s); sessions start without it", s.caFP)
		default:
			s.cfg.Logf("[execbox] recorder CA rotated: sha256=%s -> sha256=%s", s.caFP, fp)
		}
		s.caFP = fp
	}
	s.caMu.Unlock()
	if certPEM == nil {
		return "", nil
	}
	staged := filepath.Join(dir, "recorder-ca.pem")
	if err := os.WriteFile(staged, certPEM, 0o644); err != nil {
		return "", fmt.Errorf("execbox: stage recorder CA: %w", err)
	}
	return staged, nil
}

package execbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestCA writes what go-mitmproxy leaves in its CA directory: the public
// certificate and a second file that also holds the signing key. It returns the
// directory and the certificate's PEM.
func writeTestCA(t *testing.T, dir string, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "execbox test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mitmproxy-ca-cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mitmproxy-ca.pem"), append(keyPEM, certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

func caSupervisor(t *testing.T, path string) (*Supervisor, *[]string) {
	t.Helper()
	var logs []string
	return &Supervisor{cfg: Config{CACert: path, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}}, &logs
}

// A missing CA is the normal state before the backend starts: no error, no
// mount. A disabled path is the same.
func TestStageCAAbsentIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"", filepath.Join(dir, "none", "mitmproxy-ca-cert.pem")} {
		s, _ := caSupervisor(t, path)
		got, err := s.stageCA(dir)
		if err != nil || got != "" {
			t.Errorf("CACert=%q: staged %q, err %v; want no file and no error", path, got, err)
		}
	}
}

// The staged copy is the certificate alone, in a file the supervisor owns, and
// creation and rotation are each logged once with the fingerprint.
func TestStageCACopiesOnlyTheCertificateAndAccountsRotation(t *testing.T) {
	caDir, stage := filepath.Join(t.TempDir(), "_ca"), t.TempDir()
	want := writeTestCA(t, caDir, true)
	s, logs := caSupervisor(t, filepath.Join(caDir, "mitmproxy-ca-cert.pem"))

	staged, err := s.stageCA(stage)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(staged) != stage {
		t.Fatalf("staged copy %q is outside the session directory", staged)
	}
	got, _ := os.ReadFile(staged)
	if string(got) != string(want) || strings.Contains(string(got), "PRIVATE") {
		t.Fatalf("staged copy is not exactly the public certificate:\n%s", got)
	}
	if _, err := s.stageCA(stage); err != nil {
		t.Fatal(err)
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "available") {
		t.Fatalf("creation must be logged exactly once: %v", *logs)
	}

	rotated := writeTestCA(t, caDir, true)
	staged, err = s.stageCA(stage)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(staged); string(got) != string(rotated) {
		t.Errorf("a new session kept the old CA after rotation")
	}
	if len(*logs) != 2 || !strings.Contains((*logs)[1], "rotated") {
		t.Fatalf("rotation must be logged: %v", *logs)
	}

	if err := os.Remove(filepath.Join(caDir, "mitmproxy-ca-cert.pem")); err != nil {
		t.Fatal(err)
	}
	if staged, err = s.stageCA(stage); err != nil || staged != "" {
		t.Fatalf("a vanished CA gave %q, %v; want no mount and no error", staged, err)
	}
	if len(*logs) != 3 || !strings.Contains((*logs)[2], "gone") {
		t.Fatalf("a vanished CA must be logged: %v", *logs)
	}
}

// Anything but a plain CA certificate file fails the session start by name
// instead of being filtered: the key's file, a non-CA certificate, junk, a
// symlink and an oversized file are all refused.
func TestStageCARefusesAnythingButAPublicCACertificate(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "_ca")
	writeTestCA(t, caDir, true)
	leafDir := filepath.Join(t.TempDir(), "_ca")
	writeTestCA(t, leafDir, false)
	link := filepath.Join(t.TempDir(), "link.pem")
	if err := os.Symlink(filepath.Join(caDir, "mitmproxy-ca.pem"), link); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(t.TempDir(), "big.pem")
	if err := os.WriteFile(big, make([]byte, maxCACertBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"key file":     {filepath.Join(caDir, "mitmproxy-ca.pem"), "private key"},
		"symlink":      {link, "regular file"},
		"not a CA":     {filepath.Join(leafDir, "mitmproxy-ca-cert.pem"), "not a CA"},
		"junk":         {junk, "no certificate"},
		"oversized":    {big, "regular file"},
		"the CA's dir": {caDir, "regular file"},
	} {
		s, _ := caSupervisor(t, tc.path)
		staged, err := s.stageCA(t.TempDir())
		if err == nil || staged != "" || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: staged %q, err %v; want a refusal mentioning %q", name, staged, err, tc.want)
		}
	}
}

// TestKernelRecorderCAIsReadableAndAloneInItsDirectory is the guest-side proof
// for every client: a session reads the certificate at the path the backend
// puts in SSL_CERT_FILE, cannot write it, and sees neither the signing key nor
// anything else of the CA directory.
func TestKernelRecorderCAIsReadableAndAloneInItsDirectory(t *testing.T) {
	requireKernel(t)
	caDir := filepath.Join(t.TempDir(), "traffic", "_ca")
	want := writeTestCA(t, caDir, true)
	cert := filepath.Join(caDir, "mitmproxy-ca-cert.pem")
	env := newKernelEnv(t, "127.0.0.1:1", func(c *Config) { c.CACert = cert })

	script := fmt.Sprintf(`cat %[1]s > /tmp/got && echo read=$(cmp -s /tmp/got %[1]s && echo same || echo differs)
echo listing=$(ls %[2]s | tr '\n' ',')
echo key=$( (cat %[2]s/mitmproxy-ca.pem >/dev/null 2>&1 && echo visible) || echo hidden)
echo write=$( (echo x >> %[1]s) 2>/dev/null && echo allowed || echo refused)
echo parent=$(ls %[3]s | tr '\n' ',')`, cert, caDir, filepath.Dir(caDir))
	res, err := env.client.RunOnce(context.Background(), testSess("ca"), Spec{
		Argv: []string{"bash", "-c", script},
		Dir:  "/tmp",
		Env:  []string{"PATH=/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	t.Logf("session output:\n%s", out)
	if got := field(out, "read"); got != "same" {
		t.Errorf("read = %q, want the recorder certificate readable at its host path", got)
	}
	if got := field(out, "listing"); got != "mitmproxy-ca-cert.pem," {
		t.Errorf("listing = %q, want the certificate alone", got)
	}
	if got := field(out, "key"); got != "hidden" {
		t.Errorf("key = %q, want the signing key invisible", got)
	}
	if got := field(out, "write"); got != "refused" {
		t.Errorf("write = %q, want the certificate read-only", got)
	}
	if got := field(out, "parent"); got != "_ca," {
		t.Errorf("parent = %q, want only the mount point of the certificate directory", got)
	}
	if got, _ := os.ReadFile(cert); string(got) != string(want) {
		t.Error("the session changed the host's certificate")
	}
}

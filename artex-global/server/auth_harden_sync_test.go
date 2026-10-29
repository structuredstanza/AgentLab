package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression guard for upstream a951e4a's port (backlog: auth reads fail-closed + first-time setup made atomic + password upper bound).
// GetSetting differs only in the error return between "key missing" and "read failed" (both return value=""). If the password handler treats the error as "not configured," the entrance opens for initialization during a database failure.
// value=""). If the password handler treats the error as "unset", initialization runs during a database outage
// The two tests below close the connection pool to create a read failure and confirm fail-closed (503).
// verify this behavior.
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d, expected 503 (treating a read failure as uninitialized sends the user to /setup, which overwrites the password); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("on a read failure, initialized must not be reported: %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery","setup_token":"x"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d, expected 503 (letting a read failure through lets an unauthenticated request overwrite the existing password); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("on a read failure, a token must not be issued: %s", w.Body.String())
	}
}

// Verifies that the server enforces the password byte upper bound (bcrypt's 72 bytes). A 73-byte password must be rejected with 400.
// (Previously, bcrypt failed at the hashing stage, causing a 500.)
func TestAuthInitRejectsTooLongPasswordDB(t *testing.T) {
	rig := newAuthTestRig(t)
	tok := rig.s.currentSetupToken()

	code, body := rig.do("POST", "/api/auth/init", "", map[string]any{
		"password":    strings.Repeat("a", 73),
		"setup_token": tok,
	})
	rig.expect(400, code, body)
}

// Token verification and the first-run handling at startup must not fold a read failure into "no password set" either. If they do,
// The empty hash is cached (passHashLoaded=true), and signingKey("") falls back to the raw jwt.key.
func TestVerifyTokenFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m, jwtKey: []byte(strings.Repeat("s", 32))}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if s.verifyToken(tok) {
		t.Fatal("no token may pass while the password state cannot be read")
	}
}

func TestBootstrapAuthSkipsFirstRunWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(adminPasswordEnv, "env-admin-pass-123")

	s := &Server{m: m}
	s.bootstrapAuth()
	s.authMu.Lock()
	loaded := s.passHashLoaded
	s.authMu.Unlock()
	if loaded {
		t.Fatal("a read failure must not be cached as \"no password\"")
	}
}

// The ARTEX_ADMIN_PASSWORD initialization must also be written only once, the first time: a second instance started with a different value
// must not overwrite the existing password.
func TestBootstrapAdminPasswordEnvDoesNotOverwriteDB(t *testing.T) {
	rig := newAuthTestRig(t)
	t.Setenv(adminPasswordEnv, "first-admin-pass-123")
	rig.s.bootstrapAuth()
	first, err := rig.s.reloadPassHash()
	if err != nil || first == "" {
		t.Fatalf("the first instance must initialize the password (err=%v)", err)
	}

	// Second instance: the read at startup is non-empty, so it should return right away, but to simulate a race between the read
	// and the write, check the write path directly.
	inserted, err := rig.s.m.pg.InsertSettingIfAbsent(authPassKey, "second-hash")
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("an insert over an existing password must not succeed")
	}
	t.Setenv(adminPasswordEnv, "second-admin-pass-456")
	s2 := &Server{m: rig.s.m, jwtKey: rig.s.jwtKey}
	s2.bootstrapAuth()
	if got, _ := s2.reloadPassHash(); got != first {
		t.Fatal("the second instance overwrote the existing password")
	}
}

func TestBootstrapAdminPasswordEnvRejectsOverBcryptLimitDB(t *testing.T) {
	rig := newAuthTestRig(t)
	t.Setenv(adminPasswordEnv, strings.Repeat("a", 73))
	rig.s.bootstrapAuth()
	if h, _ := rig.s.reloadPassHash(); h != "" {
		t.Fatal("an environment password longer than 72 bytes must be ignored")
	}
	if rig.s.currentSetupToken() == "" {
		t.Fatal("after being ignored, a setup token must be issued")
	}
}

package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/artex/cliproxyhost/internal/contract"
)

const testToken = "test-capability-token"

// fakeLifecycle counts calls so tests can prove a request never reached it.
type fakeLifecycle struct{ calls int }

func (f *fakeLifecycle) StartLogin(context.Context, contract.ProfileID, contract.Provider) (string, error) {
	f.calls++
	return "sid-1", nil
}
func (f *fakeLifecycle) LoginView(contract.ProfileID, string) (contract.LoginView, error) {
	f.calls++
	return contract.LoginView{Status: contract.LoginPending}, nil
}
func (f *fakeLifecycle) SubmitInput(contract.ProfileID, string, string) error {
	f.calls++
	return nil
}
func (f *fakeLifecycle) CancelLogin(contract.ProfileID, string) error {
	f.calls++
	return nil
}
func (f *fakeLifecycle) Disconnect(context.Context, contract.ProfileID) error {
	f.calls++
	return nil
}

type fakeStore struct{}

func (fakeStore) Load(context.Context, contract.ProfileID, contract.Provider) (*contract.Record, error) {
	return nil, nil
}
func (fakeStore) Save(context.Context, contract.ProfileID, contract.Provider, uint64, *contract.Record) (uint64, error) {
	return 0, nil
}
func (fakeStore) DeleteAll(context.Context, contract.ProfileID) error { return nil }
func (fakeStore) Generation(contract.ProfileID, contract.Provider) (uint64, error) {
	return 0, nil
}

type fakeCatalog struct{}

func (fakeCatalog) Models(contract.Provider) ([]contract.Model, error) {
	return []contract.Model{{ID: "m1", Name: "Model One", ContextWindow: 1000, SupportedEfforts: []string{}}}, nil
}

type fakeUsage struct{}

func (fakeUsage) Usage(context.Context, contract.ProfileID, contract.Provider) (contract.UsageReport, error) {
	return contract.UsageReport{Provider: contract.ProviderClaude, FetchedAt: time.Unix(0, 0).UTC().Format(time.RFC3339), Windows: []contract.Window{}}, nil
}

type fakeInferer struct{ calls int }

func (f *fakeInferer) Infer(context.Context, InferRequest, InferSink) error {
	f.calls++
	return nil
}

func (f *fakeInferer) VerifyReplay(context.Context, InferRequest) error {
	return nil
}

func newTestServer(t *testing.T, lc *fakeLifecycle, inf *fakeInferer) *Server {
	t.Helper()
	s, err := New(Deps{
		Token:     []byte(testToken),
		Lifecycle: lc,
		Store:     fakeStore{},
		Catalog:   fakeCatalog{},
		Usage:     fakeUsage{},
		Inferer:   inf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func do(s *Server, method, path, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestHealthzIsPublic(t *testing.T) {
	s := newTestServer(t, &fakeLifecycle{}, &fakeInferer{})
	if rec := do(s, http.MethodGet, "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
}

func TestMissingBearerIsRejectedBeforeBodyParse(t *testing.T) {
	lc := &fakeLifecycle{}
	s := newTestServer(t, lc, &fakeInferer{})
	rec := do(s, http.MethodPost, "/v1/profiles/1/login/start", "", "not json")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 before body parsing", rec.Code)
	}
	if lc.calls != 0 {
		t.Fatal("unauthenticated request reached the lifecycle")
	}
}

func TestWrongBearerIsRejected(t *testing.T) {
	s := newTestServer(t, &fakeLifecycle{}, &fakeInferer{})
	if rec := do(s, http.MethodGet, "/v1/models?provider=claude", "Bearer wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec := do(s, http.MethodGet, "/v1/models?provider=claude", "Basic "+testToken, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-bearer scheme status = %d, want 401", rec.Code)
	}
}

func TestOversizedControlBodyIsRejected(t *testing.T) {
	lc := &fakeLifecycle{}
	s := newTestServer(t, lc, &fakeInferer{})
	big := `{"value":"` + strings.Repeat("a", 5*1024) + `"}`
	rec := do(s, http.MethodPost, "/v1/profiles/1/login/sid-1/input", "Bearer "+testToken, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if lc.calls != 0 {
		t.Fatal("oversized body reached the lifecycle")
	}
}

func TestNonCanonicalProfileIDsAreRejected(t *testing.T) {
	s := newTestServer(t, &fakeLifecycle{}, &fakeInferer{})
	for _, id := range []string{"01", "abc", "99999999999999999999", "0"} {
		rec := do(s, http.MethodGet, "/v1/profiles/"+id+"/status?provider=claude", "Bearer "+testToken, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("profile %q status = %d, want 400", id, rec.Code)
		}
	}
}

func TestUnknownRouteAndMethodUseFixedCodes(t *testing.T) {
	s := newTestServer(t, &fakeLifecycle{}, &fakeInferer{})
	if rec := do(s, http.MethodGet, "/v1/nope", "Bearer "+testToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", rec.Code)
	}
	if rec := do(s, http.MethodPut, "/v1/models?provider=claude", "Bearer "+testToken, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d, want 405", rec.Code)
	}
}

func TestModelsServeCatalogWithAuth(t *testing.T) {
	s := newTestServer(t, &fakeLifecycle{}, &fakeInferer{})
	rec := do(s, http.MethodGet, "/v1/models?provider=claude", "Bearer "+testToken, "")
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"id":"m1"`)) {
		t.Fatalf("models status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestInferRejectsUnknownBodyFields(t *testing.T) {
	inf := &fakeInferer{}
	s := newTestServer(t, &fakeLifecycle{}, inf)
	body := `{"provider":"claude","model":"m1","session_id":"s","surprise":1}`
	rec := do(s, http.MethodPost, "/v1/profiles/1/infer", "Bearer "+testToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if inf.calls != 0 {
		t.Fatal("inferer ran for a body with unknown fields")
	}
}

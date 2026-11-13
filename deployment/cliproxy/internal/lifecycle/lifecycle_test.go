package lifecycle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/store"
)

// fakeRunner returns whatever run returns; it never performs a real login.
type fakeRunner struct {
	run func(ctx context.Context) (*contract.Record, error)
}

func (f fakeRunner) Run(ctx context.Context, _ contract.ProfileID, _ contract.Provider, _ func(string) error, _ func(string), _ func(string) (string, error)) (*contract.Record, error) {
	return f.run(ctx)
}

type interactivePromptRunner struct{}

func (interactivePromptRunner) Run(
	_ context.Context,
	_ contract.ProfileID,
	_ contract.Provider,
	_ func(string) error,
	_ func(string),
	prompt func(string) (string, error),
) (*contract.Record, error) {
	value, err := prompt("Enter the verification code")
	if err != nil {
		return nil, err
	}
	if value != "123456" {
		return nil, errors.New("unexpected prompt input")
	}
	return &contract.Record{CoreAuthID: "core-prompt", Raw: []byte(`{"access_token":"fixture"}`)}, nil
}

func newFixture(t *testing.T, run func(ctx context.Context) (*contract.Record, error)) (*Lifecycle, *store.Store) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "proxy-state"))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, fakeRunner{run: run}), st
}

func profile(t *testing.T, s string) contract.ProfileID {
	t.Helper()
	p, err := contract.ParseProfileID(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func seed(t *testing.T, st *store.Store, p contract.ProfileID, prov contract.Provider, raw string) {
	t.Helper()
	gen, err := st.Generation(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Save(context.Background(), p, prov, gen, &contract.Record{CoreAuthID: "core-old", Raw: []byte(raw)}); err != nil {
		t.Fatal(err)
	}
}

// waitStatus polls the public view until it leaves pending, or fails the test.
func waitStatus(t *testing.T, l *Lifecycle, p contract.ProfileID, sid string) contract.LoginView {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		v, err := l.LoginView(p, sid)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status != contract.LoginPending {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("login stayed pending")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func TestLoginViewPublishesStructuredPrompt(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "proxy-state"))
	if err != nil {
		t.Fatal(err)
	}
	l := New(st, interactivePromptRunner{})
	p := profile(t, "11")
	sid, err := l.StartLogin(context.Background(), p, contract.ProviderClaude)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.CancelLogin(p, sid) })

	deadline := time.Now().Add(2 * time.Second)
	var view contract.LoginView
	for {
		view, err = l.LoginView(p, sid)
		if err != nil {
			t.Fatal(err)
		}
		if view.Prompt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("login prompt was not exposed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if view.Prompt.Message != "Enter the verification code" {
		t.Fatalf("prompt = %#v", view.Prompt)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Prompt *contract.LoginPrompt `json:"prompt"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Prompt == nil || wire.Prompt.Message != "Enter the verification code" {
		t.Fatalf("wire prompt = %#v; want a structured message", wire.Prompt)
	}

	if err := l.SubmitInput(p, sid, "123456"); err != nil {
		t.Fatal(err)
	}
	view = waitStatus(t, l, p, sid)
	if view.Status != contract.LoginComplete || view.Prompt != nil {
		t.Fatalf("view after input = %+v; want completed and no prompt", view)
	}
}

func TestCancelVsCommitNoLateCommit(t *testing.T) {
	release := make(chan struct{})
	l, st := newFixture(t, func(context.Context) (*contract.Record, error) {
		<-release
		return &contract.Record{CoreAuthID: "core-late", Raw: []byte(`{"refresh_token":"r"}`)}, nil
	})
	p := profile(t, "3")
	sid, err := l.StartLogin(context.Background(), p, contract.ProviderClaude)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.CancelLogin(p, sid); err != nil {
		t.Fatal(err)
	}
	close(release)
	if v := waitStatus(t, l, p, sid); v.Status != contract.LoginCancelled {
		t.Fatalf("status %s after cancel", v.Status)
	}
	if _, err := st.Load(context.Background(), p, contract.ProviderClaude); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("late commit landed after cancel: %v", err)
	}
}

func TestReloginFailureKeepsGrant(t *testing.T) {
	l, st := newFixture(t, func(context.Context) (*contract.Record, error) {
		return nil, errors.New("provider said sk-secret-value")
	})
	p := profile(t, "4")
	seed(t, st, p, contract.ProviderCodex, `{"refresh_token":"keep"}`)
	sid, err := l.StartLogin(context.Background(), p, contract.ProviderCodex)
	if err != nil {
		t.Fatal(err)
	}
	v := waitStatus(t, l, p, sid)
	if v.Status != contract.LoginError || v.Error != "login failed" {
		t.Fatalf("view %+v: want fixed error", v)
	}
	got, err := st.Load(context.Background(), p, contract.ProviderCodex)
	if err != nil || got.CoreAuthID != "core-old" {
		t.Fatalf("old grant lost after failed relogin: %+v %v", got, err)
	}
}

func TestRefreshKeepsRefreshTokenWhenOmitted(t *testing.T) {
	l, st := newFixture(t, nil)
	p := profile(t, "5")
	prov := contract.ProviderAntigravity
	seed(t, st, p, prov, `{"access_token":"a1","refresh_token":"r1"}`)
	gen, _ := st.Generation(p, prov)

	rotated := &contract.Record{CoreAuthID: "core-old", Raw: []byte(`{"access_token":"a2"}`)}
	if err := l.PersistRefresh(context.Background(), p, prov, gen, rotated); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(context.Background(), p, prov)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(got.Raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["access_token"] != "a2" || m["refresh_token"] != "r1" {
		t.Fatalf("merged raw %v", m)
	}
}

func TestRefreshRotatesRefreshToken(t *testing.T) {
	l, st := newFixture(t, nil)
	p := profile(t, "6")
	prov := contract.ProviderClaude
	seed(t, st, p, prov, `{"access_token":"a1","refresh_token":"r1"}`)
	gen, _ := st.Generation(p, prov)

	rotated := &contract.Record{CoreAuthID: "core-old", Raw: []byte(`{"access_token":"a2","refresh_token":"r2"}`)}
	if err := l.PersistRefresh(context.Background(), p, prov, gen, rotated); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Load(context.Background(), p, prov)
	var m map[string]string
	_ = json.Unmarshal(got.Raw, &m)
	if m["refresh_token"] != "r2" {
		t.Fatalf("rotated refresh token not stored: %v", m)
	}
}

func TestRefreshSurvivesCallerCancel(t *testing.T) {
	l, st := newFixture(t, nil)
	p := profile(t, "8")
	prov := contract.ProviderCodex
	seed(t, st, p, prov, `{"refresh_token":"r1"}`)
	gen, _ := st.Generation(p, prov)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rotated := &contract.Record{CoreAuthID: "core-old", Raw: []byte(`{"refresh_token":"r2"}`)}
	if err := l.PersistRefresh(ctx, p, prov, gen, rotated); err != nil {
		t.Fatalf("persist with cancelled caller ctx: %v", err)
	}
	got, _ := st.Load(context.Background(), p, prov)
	var m map[string]string
	_ = json.Unmarshal(got.Raw, &m)
	if m["refresh_token"] != "r2" {
		t.Fatalf("refresh lost after caller cancel: %v", m)
	}
}

func TestDisconnectWaitsForOperation(t *testing.T) {
	l, st := newFixture(t, nil)
	p := profile(t, "10")
	prov := contract.ProviderClaude
	seed(t, st, p, prov, `{"refresh_token":"r1"}`)

	opCtx, release, err := l.AcquireOperation(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan error, 1)
	go func() { done <- l.Disconnect(context.Background(), p) }()

	select {
	case <-opCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not cancel the active operation")
	}
	if _, extraRelease, err := l.AcquireOperation(context.Background(), p); !errors.Is(err, ErrDisconnecting) {
		if extraRelease != nil {
			extraRelease()
		}
		t.Fatalf("new operation admitted during disconnect: %v", err)
	}
	select {
	case <-done:
		t.Fatal("disconnect finished while an operation was held")
	default:
	}
	if _, err := st.Load(context.Background(), p, prov); err != nil {
		t.Fatalf("grant deleted before drain: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(context.Background(), p, prov); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("grant survived disconnect: %v", err)
	}
}

func TestProfileIsolation(t *testing.T) {
	l, st := newFixture(t, nil)
	seed(t, st, profile(t, "11"), contract.ProviderCodex, `{"refresh_token":"r"}`)
	connected, _, _, err := l.Status(profile(t, "12"), contract.ProviderCodex)
	if err != nil || connected {
		t.Fatalf("profile 12 sees profile 11 grant: connected=%v err=%v", connected, err)
	}
}

func TestSessionIDIs128BitsBase64URL(t *testing.T) {
	id, err := newSessionID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != 16 {
		t.Fatalf("session id %q: %d bytes, err=%v", id, len(raw), err)
	}
}

func TestNewLoginSupersedesPendingAttempt(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	cancelled := make(chan struct{})
	l, st := newFixture(t, func(ctx context.Context) (*contract.Record, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		}
		return &contract.Record{CoreAuthID: "new-account", Raw: []byte(`{"refresh_token":"new"}`)}, nil
	})
	p := profile(t, "13")
	first, err := l.StartLogin(context.Background(), p, contract.ProviderClaude)
	if err != nil {
		t.Fatal(err)
	}
	defer l.CancelLogin(p, first)
	<-started
	second, err := l.StartLogin(context.Background(), p, contract.ProviderClaude)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("new login left the old authorization active")
	}
	if v := waitStatus(t, l, p, second); v.Status != contract.LoginComplete {
		t.Fatalf("replacement login failed: %+v", v)
	}
	if v := waitStatus(t, l, p, first); v.Status != contract.LoginCancelled {
		t.Fatalf("superseded login remained usable: %+v", v)
	}
	got, err := st.Load(context.Background(), p, contract.ProviderClaude)
	if err != nil || got.CoreAuthID != "new-account" {
		t.Fatalf("replacement grant was not authoritative: %v", err)
	}
}

func TestDisconnectDrainsAcceptedRefreshBeforeDeleting(t *testing.T) {
	l, st := newFixture(t, nil)
	p := profile(t, "14")
	prov := contract.ProviderCodex
	seed(t, st, p, prov, `{"refresh_token":"old"}`)
	gen, err := st.Generation(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	opCtx, release, err := l.AcquireOperation(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan error, 1)
	go func() { done <- l.Disconnect(context.Background(), p) }()
	select {
	case <-opCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not begin")
	}
	rotated := &contract.Record{CoreAuthID: "core-old", Raw: []byte(`{"refresh_token":"rotated"}`)}
	if err := l.PersistRefresh(opCtx, p, prov, gen, rotated); err != nil {
		t.Fatalf("accepted refresh was lost while draining: %v", err)
	}
	got, err := st.Load(context.Background(), p, prov)
	if err != nil || string(got.Raw) != string(rotated.Raw) {
		t.Fatalf("rotation was not durable before drain: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := l.PersistRefresh(context.Background(), p, prov, gen, rotated); err == nil {
		t.Fatal("late refresh resurrected a deleted grant")
	}
}

func TestRefreshCannotReplaceCredentialEpoch(t *testing.T) {
	l, st := newFixture(t, nil)
	p := profile(t, "15")
	prov := contract.ProviderClaude
	seed(t, st, p, prov, `{"refresh_token":"current"}`)
	gen, err := st.Generation(p, prov)
	if err != nil {
		t.Fatal(err)
	}
	foreign := &contract.Record{CoreAuthID: "superseded-account", Raw: []byte(`{"refresh_token":"foreign"}`)}
	if err := l.PersistRefresh(context.Background(), p, prov, gen, foreign); !errors.Is(err, ErrBadRecord) {
		t.Fatalf("cross-account rotation admitted: %v", err)
	}
	got, err := st.Load(context.Background(), p, prov)
	if err != nil || string(got.Raw) != `{"refresh_token":"current"}` {
		t.Fatalf("current grant overwritten: %v", err)
	}
}

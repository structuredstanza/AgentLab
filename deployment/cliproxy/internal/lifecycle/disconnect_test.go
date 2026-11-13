package lifecycle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/store"
)

type controlledDisconnectStore struct {
	Store
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	failure error
}

func (s *controlledDisconnectStore) DeleteAll(ctx context.Context, p contract.ProfileID) error {
	if s.calls.Add(1) == 1 && s.entered != nil {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.failure != nil {
		return s.failure
	}
	return s.Store.DeleteAll(ctx, p)
}

// Pause a joiner after it has inspected lifecycle state, before its wait starts.
type disconnectJoinContext struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *disconnectJoinContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Done()
}

func TestOverlappingDisconnectCannotDeleteNewLogin(t *testing.T) {
	l, st := newFixture(t, func(context.Context) (*contract.Record, error) {
		return &contract.Record{CoreAuthID: "new-login", Raw: []byte(`{"refresh_token":"new"}`)}, nil
	})
	p, prov := profile(t, "21"), contract.ProviderCodex
	seed(t, st, p, prov, `{"refresh_token":"old"}`)
	storage := &controlledDisconnectStore{Store: st, entered: make(chan struct{}), release: make(chan struct{})}
	l.store = storage
	var releaseOwner, releaseJoiner sync.Once
	t.Cleanup(func() { releaseOwner.Do(func() { close(storage.release) }) })
	owner := make(chan error, 1)
	go func() { owner <- l.Disconnect(context.Background(), p) }()
	<-storage.entered
	joinCtx := &disconnectJoinContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { releaseJoiner.Do(func() { close(joinCtx.release) }) })
	joined := make(chan error, 1)
	go func() { joined <- l.Disconnect(joinCtx, p) }()
	<-joinCtx.entered
	releaseOwner.Do(func() { close(storage.release) })
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	sid, err := l.StartLogin(context.Background(), p, prov)
	if err != nil {
		t.Fatal(err)
	}
	if view := waitStatus(t, l, p, sid); view.Status != contract.LoginComplete {
		t.Fatalf("new login: %+v", view)
	}
	releaseJoiner.Do(func() { close(joinCtx.release) })
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	record, err := st.Load(context.Background(), p, prov)
	if err != nil || record.CoreAuthID != "new-login" {
		t.Fatalf("overlapping disconnect deleted the new grant: record=%+v err=%v", record, err)
	}
	if n := storage.calls.Load(); n != 1 {
		t.Fatalf("one disconnect operation deleted grants %d times", n)
	}
}

func TestDisconnectCancellationCanResumeWithoutReopeningAdmission(t *testing.T) {
	l, st := newFixture(t, nil)
	p, prov := profile(t, "22"), contract.ProviderClaude
	seed(t, st, p, prov, `{"refresh_token":"old"}`)
	opCtx, release, err := l.AcquireOperation(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Disconnect(ctx, p) }()
	<-opCtx.Done()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner cancellation: %v", err)
	}
	if connected, _, _, err := l.Status(p, prov); err != nil || connected {
		t.Fatalf("draining grant reported ready: connected=%v err=%v", connected, err)
	}
	if _, err := l.StartLogin(context.Background(), p, prov); !errors.Is(err, ErrDisconnecting) {
		t.Fatalf("login admitted during drain: %v", err)
	}
	release()
	if err := l.Disconnect(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(context.Background(), p, prov); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("resumed disconnect left grant: %v", err)
	}
	_, releaseAfter, err := l.AcquireOperation(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	releaseAfter()
}

func TestDisconnectStorageFailureKeepsAdmissionClosedUntilRetry(t *testing.T) {
	l, st := newFixture(t, nil)
	p, prov := profile(t, "23"), contract.ProviderCodex
	seed(t, st, p, prov, `{"refresh_token":"old"}`)
	failure := errors.New("storage unavailable")
	storage := &controlledDisconnectStore{Store: st, failure: failure}
	l.store = storage
	if err := l.Disconnect(context.Background(), p); !errors.Is(err, failure) {
		t.Fatalf("storage failure lost: %v", err)
	}
	if connected, _, _, err := l.Status(p, prov); err != nil || connected {
		t.Fatalf("failed disconnect reported ready: connected=%v err=%v", connected, err)
	}
	if _, release, err := l.AcquireOperation(context.Background(), p); !errors.Is(err, ErrDisconnecting) {
		if release != nil {
			release()
		}
		t.Fatalf("operation admitted after failed deletion: %v", err)
	}
	storage.failure = nil
	if err := l.Disconnect(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(context.Background(), p, prov); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retry left grant: %v", err)
	}
}

func TestCanceledDisconnectJoinerDoesNotCancelOwner(t *testing.T) {
	l, st := newFixture(t, nil)
	p, prov := profile(t, "24"), contract.ProviderCodex
	seed(t, st, p, prov, `{"refresh_token":"old"}`)
	storage := &controlledDisconnectStore{Store: st, entered: make(chan struct{}), release: make(chan struct{})}
	l.store = storage
	var releaseOwner sync.Once
	t.Cleanup(func() { releaseOwner.Do(func() { close(storage.release) }) })
	owner := make(chan error, 1)
	go func() { owner <- l.Disconnect(context.Background(), p) }()
	<-storage.entered
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	joinCtx := &disconnectJoinContext{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	close(joinCtx.release)
	joined := make(chan error, 1)
	go func() { joined <- l.Disconnect(joinCtx, p) }()
	<-joinCtx.entered
	cancel()
	if err := <-joined; !errors.Is(err, context.Canceled) {
		t.Fatalf("joiner cancellation: %v", err)
	}
	if n := storage.calls.Load(); n != 1 {
		t.Fatalf("joiner started another deletion: %d", n)
	}
	releaseOwner.Do(func() { close(storage.release) })
	if err := <-owner; err != nil {
		t.Fatalf("joiner canceled owner: %v", err)
	}
	if _, err := st.Load(context.Background(), p, prov); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("owner did not delete the grant: %v", err)
	}
}

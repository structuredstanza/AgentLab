// Package lifecycle serializes per-profile login, cancel, refresh persistence
// and disconnect on top of a private grant store.
//
// Invariants:
//   - A login commits only if its session is still pending, not cancelled and
//     in the profile's current epoch, checked under the profile lock that
//     CancelLogin and Disconnect also take. Save runs under that same lock.
//   - A failed or cancelled login never calls Save, so the old grant survives.
//   - Disconnect marks the profile before draining, so no new operation can
//     start after the drain begins. It deletes grants only after drain.
package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/store"
)

var (
	ErrDisconnecting   = errors.New("profile is disconnecting")
	ErrSessionNotFound = errors.New("login session not found")
	ErrNoPrompt        = errors.New("login session is not waiting for input")
	ErrBadRecord       = errors.New("refresh record is invalid")
	ErrBadAuthURL      = errors.New("authorization url is not an https url")
)

// refreshTokenKey is the top-level key the native auth JSON uses for the refresh token.
const refreshTokenKey = "refresh_token"

// LoginRunner performs one interactive native login for a profile. The
// production implementation is wired by the host to the core sdk/auth
// authenticators; this package defines only the seam.
type LoginRunner interface {
	Run(ctx context.Context, profile contract.ProfileID, provider contract.Provider, authorizationURL func(string) error, progress func(string), prompt func(string) (string, error)) (*contract.Record, error)
}

// Store is the grant store the lifecycle needs: contract.Store plus the
// generation read used to capture expectedGen when a login starts.
type Store interface {
	contract.Store
	Generation(profile contract.ProfileID, provider contract.Provider) (uint64, error)
}

// Drainer hands out operation holds. Inference and refresh acquire one before
// touching a profile's grant and release it when done.
type Drainer interface {
	AcquireOperation(ctx context.Context, profile contract.ProfileID) (operationCtx context.Context, release func(), err error)
}

// Lifecycle implements contract.Lifecycle and Drainer.
type Lifecycle struct {
	store  Store
	runner LoginRunner

	mu       sync.Mutex // guards profiles map only
	profiles map[contract.ProfileID]*profileState
}

var (
	_ contract.Lifecycle = (*Lifecycle)(nil)
	_ Drainer            = (*Lifecycle)(nil)
)

// profileState is guarded by its own mu.
type profileState struct {
	mu            sync.Mutex
	epoch         uint64 // bumped by Disconnect; sessions from older epochs never commit
	disconnecting bool
	disconnect    *disconnectFlight
	operations    map[uint64]context.CancelFunc
	nextOperation uint64
	idle          chan struct{} // closed when operations drain
	sessions      map[string]*session
}

type disconnectFlight struct {
	done chan struct{}
	err  error
}

type session struct {
	id       string
	provider contract.Provider
	epoch    uint64
	cancel   context.CancelFunc

	status    contract.LoginStatus
	cancelled bool
	authURL   string
	progress  string
	prompt    string
	input     chan string // buffered 1; SubmitInput sends here
	email     string
	expiresAt time.Time
	err       string
}

// New returns a Lifecycle over the given store and login runner.
func New(st Store, runner LoginRunner) *Lifecycle {
	return &Lifecycle{store: st, runner: runner, profiles: make(map[contract.ProfileID]*profileState)}
}

func (l *Lifecycle) state(profile contract.ProfileID) *profileState {
	l.mu.Lock()
	defer l.mu.Unlock()
	ps, ok := l.profiles[profile]
	if !ok {
		ps = &profileState{sessions: make(map[string]*session), operations: make(map[uint64]context.CancelFunc)}
		l.profiles[profile] = ps
	}
	return ps
}

func parseProfile(profile contract.ProfileID) (contract.ProfileID, error) {
	return contract.ParseProfileID(string(profile))
}

// StartLogin creates a pending session and runs the login in the background.
// The login outlives ctx; only CancelLogin or Disconnect stop it.
func (l *Lifecycle) StartLogin(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (string, error) {
	if _, ok := contract.ParseProvider(string(provider)); !ok {
		return "", store.ErrUnknownProvider
	}
	p, err := parseProfile(profile)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	ps := l.state(p)

	ps.mu.Lock()
	if ps.disconnecting {
		ps.mu.Unlock()
		return "", ErrDisconnecting
	}
	// A newer login supersedes pending attempts without replacing the saved grant.
	for sid, old := range ps.sessions {
		if old.status == contract.LoginPending {
			old.cancelled = true
			old.status = contract.LoginCancelled
			old.cancel()
		} else {
			delete(ps.sessions, sid)
		}
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s := &session{
		id:       id,
		provider: provider,
		epoch:    ps.epoch,
		cancel:   cancel,
		status:   contract.LoginPending,
		input:    make(chan string, 1),
	}
	ps.sessions[id] = s
	ps.mu.Unlock()

	go l.runLogin(runCtx, ps, s, p)
	return id, nil
}

func (l *Lifecycle) runLogin(ctx context.Context, ps *profileState, s *session, profile contract.ProfileID) {
	authURL := func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return ErrBadAuthURL
		}
		ps.mu.Lock()
		defer ps.mu.Unlock()
		if s.cancelled {
			return context.Canceled
		}
		s.authURL = raw
		return nil
	}
	progress := func(msg string) {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		if !s.cancelled {
			s.progress = msg
		}
	}
	prompt := func(text string) (string, error) {
		ps.mu.Lock()
		if s.cancelled {
			ps.mu.Unlock()
			return "", context.Canceled
		}
		s.prompt = text
		ps.mu.Unlock()
		select {
		case v := <-s.input:
			return v, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	rec, err := l.runner.Run(ctx, profile, s.provider, authURL, progress, prompt)
	l.finishLogin(ps, s, profile, rec, err)
}

// finishLogin is the only commit point. The profile lock is held across Save,
// so CancelLogin and Disconnect either run wholly before it or wholly after it.
func (l *Lifecycle) finishLogin(ps *profileState, s *session, profile contract.ProfileID, rec *contract.Record, runErr error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	s.prompt = ""
	if s.status != contract.LoginPending {
		return
	}
	if s.cancelled || s.epoch != ps.epoch || ps.disconnecting {
		s.status = contract.LoginCancelled
		return
	}
	if runErr != nil || rec == nil {
		// The runner error can echo secrets; the guest sees only a fixed message.
		s.status = contract.LoginError
		s.err = "login failed"
		return
	}
	// Re-read the generation under the profile lock: the login is authoritative
	// for the new grant. The epoch and cancel checks above fence late commits.
	gen, err := l.store.Generation(profile, s.provider)
	if err == nil {
		_, err = l.store.Save(context.Background(), profile, s.provider, gen, rec)
	}
	if err != nil {
		s.status = contract.LoginError
		s.err = "login could not be saved"
		return
	}
	s.status = contract.LoginComplete
	s.email = rec.Email
	s.expiresAt = rec.ExpiresAt
}

// LoginView returns the public state of one session.
func (l *Lifecycle) LoginView(profile contract.ProfileID, sessionID string) (contract.LoginView, error) {
	p, err := parseProfile(profile)
	if err != nil {
		return contract.LoginView{}, err
	}
	ps := l.state(p)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	s, ok := ps.sessions[sessionID]
	if !ok {
		return contract.LoginView{}, ErrSessionNotFound
	}
	v := contract.LoginView{
		Status:           s.status,
		AuthorizationURL: s.authURL,
		Progress:         s.progress,
		Error:            s.err,
	}
	if s.prompt != "" {
		v.Prompt = &contract.LoginPrompt{Message: s.prompt}
	}
	if s.status == contract.LoginComplete {
		v.Email = s.email
		v.ExpiresAt = s.expiresAt.UTC().Format(time.RFC3339)
	}
	return v, nil
}

// SubmitInput delivers the human's answer to a pending prompt. The value is
// never logged.
func (l *Lifecycle) SubmitInput(profile contract.ProfileID, sessionID string, value string) error {
	p, err := parseProfile(profile)
	if err != nil {
		return err
	}
	ps := l.state(p)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	s, ok := ps.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if s.status != contract.LoginPending || s.prompt == "" {
		return ErrNoPrompt
	}
	select {
	case s.input <- value:
		s.prompt = ""
		return nil
	default:
		return ErrNoPrompt
	}
}

// CancelLogin stops a pending session. Once it returns, that session cannot commit.
func (l *Lifecycle) CancelLogin(profile contract.ProfileID, sessionID string) error {
	p, err := parseProfile(profile)
	if err != nil {
		return err
	}
	ps := l.state(p)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	s, ok := ps.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if s.status == contract.LoginPending {
		s.cancelled = true
		s.status = contract.LoginCancelled
		s.prompt = ""
		s.cancel()
	}
	return nil
}

// AcquireOperation holds the profile for one inference or refresh call. It
// fails once a disconnect has started.
func (l *Lifecycle) AcquireOperation(ctx context.Context, profile contract.ProfileID) (context.Context, func(), error) {
	p, err := parseProfile(profile)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	ps := l.state(p)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.disconnecting {
		return nil, nil, ErrDisconnecting
	}
	opCtx, cancel := context.WithCancel(ctx)
	ps.nextOperation++
	id := ps.nextOperation
	ps.operations[id] = cancel
	var once sync.Once
	return opCtx, func() {
		once.Do(func() {
			cancel()
			ps.mu.Lock()
			defer ps.mu.Unlock()
			delete(ps.operations, id)
			if len(ps.operations) == 0 && ps.idle != nil {
				close(ps.idle)
				ps.idle = nil
			}
		})
	}, nil
}

// Disconnect joins one profile-wide cancellation, drain, and deletion operation.
// Failed attempts keep admission closed; a later caller can resume the drain.
func (l *Lifecycle) Disconnect(ctx context.Context, profile contract.ProfileID) error {
	p, err := parseProfile(profile)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ps := l.state(p)
	ps.mu.Lock()
	if flight := ps.disconnect; flight != nil {
		ps.mu.Unlock()
		select {
		case <-flight.done:
			return flight.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	flight := &disconnectFlight{done: make(chan struct{})}
	ps.disconnect = flight
	if !ps.disconnecting {
		ps.disconnecting = true
		ps.epoch++
		for _, s := range ps.sessions {
			if s.status == contract.LoginPending {
				s.cancelled = true
				s.status = contract.LoginCancelled
				s.prompt = ""
				s.cancel()
			}
		}
		for _, cancel := range ps.operations {
			cancel()
		}
	}
	var idle <-chan struct{}
	if len(ps.operations) > 0 {
		if ps.idle == nil {
			ps.idle = make(chan struct{})
		}
		idle = ps.idle
	}
	ps.mu.Unlock()

	if idle != nil {
		select {
		case <-idle:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		if deleteErr := l.store.DeleteAll(ctx, p); deleteErr != nil {
			err = fmt.Errorf("delete grants: %w", deleteErr)
		}
	}
	ps.mu.Lock()
	if err == nil {
		ps.sessions = make(map[string]*session)
		ps.disconnecting = false
	}
	flight.err = err
	ps.disconnect = nil
	close(flight.done)
	ps.mu.Unlock()
	return err
}

// Status reports local grant state only. It never refreshes or contacts a provider.
func (l *Lifecycle) Status(profile contract.ProfileID, provider contract.Provider) (connected bool, email string, expiresAt time.Time, err error) {
	p, err := parseProfile(profile)
	if err != nil {
		return false, "", time.Time{}, err
	}
	ps := l.state(p)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.disconnecting {
		return false, "", time.Time{}, nil
	}
	rec, err := l.store.Load(context.Background(), p, provider)
	if errors.Is(err, store.ErrNotFound) {
		return false, "", time.Time{}, nil
	}
	if err != nil {
		return false, "", time.Time{}, err
	}
	return true, rec.Email, rec.ExpiresAt, nil
}

// PersistRefresh saves a rotated grant. It runs even if ctx is cancelled, so a
// refresh the provider already accepted is not lost. An operation already being
// drained may commit before disconnect deletes the grant. Missing refresh tokens
// are carried forward, but a new login's credential epoch is never overwritten.
func (l *Lifecycle) PersistRefresh(ctx context.Context, profile contract.ProfileID, provider contract.Provider, expectedGen uint64, rotated *contract.Record) error {
	p, err := parseProfile(profile)
	if err != nil {
		return err
	}
	if rotated == nil || rotated.CoreAuthID == "" {
		return ErrBadRecord
	}
	ps := l.state(p)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.disconnecting && len(ps.operations) == 0 {
		return ErrDisconnecting
	}
	wctx := context.WithoutCancel(ctx)
	prev, err := l.store.Load(wctx, p, provider)
	if err != nil {
		return err
	}
	if prev == nil || prev.CoreAuthID != rotated.CoreAuthID {
		return ErrBadRecord
	}
	out := *rotated
	if !hasToken(rotated.Raw) {
		merged, err := carryRefreshToken(rotated.Raw, prev.Raw)
		if err != nil {
			return err
		}
		out.Raw = merged
	}
	_, err = l.store.Save(wctx, p, provider, expectedGen, &out)
	return err
}

// hasToken reports whether raw is a JSON object with a non-empty refresh token.
func hasToken(raw []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	var tok string
	return json.Unmarshal(m[refreshTokenKey], &tok) == nil && tok != ""
}

// carryRefreshToken returns rotated with the refresh token from previous.
// Other fields are kept as the native JSON provided them.
func carryRefreshToken(rotated, previous []byte) ([]byte, error) {
	var next, prev map[string]json.RawMessage
	if err := json.Unmarshal(rotated, &next); err != nil {
		return nil, ErrBadRecord
	}
	if err := json.Unmarshal(previous, &prev); err != nil {
		return nil, ErrBadRecord
	}
	old, ok := prev[refreshTokenKey]
	if !ok {
		return rotated, nil
	}
	next[refreshTokenKey] = old
	return json.Marshal(next)
}

func newSessionID() (string, error) {
	var b [16]byte // 128 bits
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

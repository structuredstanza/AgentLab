package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/artex/cliproxyhost/internal/catalog"
	"github.com/artex/cliproxyhost/internal/contract"
	"github.com/artex/cliproxyhost/internal/infer"
	"github.com/artex/cliproxyhost/internal/lifecycle"
	"github.com/artex/cliproxyhost/internal/privacy"
	"github.com/artex/cliproxyhost/internal/server"
	"github.com/artex/cliproxyhost/internal/store"
	"github.com/artex/cliproxyhost/internal/usage"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/httptransport"
	_ "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator/builtin"
)

type Runtime struct {
	store     *store.Store
	lifecycle *lifecycle.Lifecycle
	catalog   contract.Catalog
	receipts  contract.Receipts
	captures  *captureStore
	usage     *usage.Service
	infer     *infer.Service
	server    *server.Server
	cfg       *sdkconfig.Config
	locksMu   sync.Mutex
	locks     map[contract.ProfileID]chan struct{}
}

func New(dataRoot string, token []byte) (*Runtime, error) {
	if dataRoot == "" || len(token) == 0 {
		return nil, errors.New("native state root and bearer capability are required")
	}
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		return nil, errors.New("could not create native state root")
	}
	if err := os.Chmod(dataRoot, 0o700); err != nil {
		return nil, errors.New("could not restrict native state root")
	}
	st, err := store.New(filepath.Join(dataRoot, "profiles"))
	if err != nil {
		return nil, err
	}
	cat, err := catalog.New()
	if err != nil {
		return nil, err
	}
	receipts, err := privacy.NewReceipts(filepath.Join(dataRoot, "replay.key"))
	if err != nil {
		return nil, err
	}
	captures, err := newCaptureStore(dataRoot)
	if err != nil {
		return nil, errors.New("could not initialize private capture store")
	}
	pol, err := privacy.NewPolicy(privacy.PolicyConfig{
		Identifiers: []string{"ARTEX", "AgentLab", "artex-global"},
		Receipts:    receipts,
		Sink:        captures,
	})
	if err != nil {
		captures.file.Close()
		return nil, err
	}
	if err := httptransport.SetOutboundPolicy(func(next http.RoundTripper) http.RoundTripper { return pol(next) }); err != nil {
		captures.file.Close()
		return nil, err
	}

	cfg := &sdkconfig.Config{}
	cfg.DisableClaudeCloakMode = false
	cfg.ClaudeCode.DisableCloakingModelList = false
	cfg.Codex.DisableCodexCloaking = false
	r := &Runtime{
		store:     st,
		lifecycle: lifecycle.New(st, loginRunner{cfg: cfg}),
		catalog:   cat,
		receipts:  receipts,
		captures:  captures,
		cfg:       cfg,
		locks:     make(map[contract.ProfileID]chan struct{}),
	}
	usageClient, err := usage.New(httptransport.ApplyOutboundPolicy(&http.Client{Timeout: 45 * time.Second}), usageCredential{host: r})
	if err != nil {
		captures.file.Close()
		return nil, err
	}
	r.usage = usageClient
	inference, err := infer.New(infer.Deps{
		Store:    st,
		Catalog:  cat,
		Receipts: receipts,
		Streamer: nativeStreamer{host: r},
		Acquire:  r.acquire,
		Turn:     r.turn,
		Captured: captures.captured,
	})
	if err != nil {
		captures.file.Close()
		return nil, err
	}
	r.infer = inference
	svc, err := server.New(server.Deps{
		Token:     token,
		Lifecycle: r.lifecycle,
		Store:     st,
		Catalog:   cat,
		Usage:     usageAdapter{host: r},
		Inferer:   inferAdapter{service: inference},
	})
	if err != nil {
		captures.file.Close()
		return nil, err
	}
	r.server = svc
	return r, nil
}

func (r *Runtime) HTTPHandler() http.Handler { return r.server }

func (r *Runtime) acquire(ctx context.Context, profile contract.ProfileID) (context.Context, func(), error) {
	opCtx, release, err := r.lifecycle.AcquireOperation(ctx, profile)
	if err != nil {
		return nil, nil, err
	}
	gate := r.profileGate(profile)
	select {
	case gate <- struct{}{}:
		var once sync.Once
		return opCtx, func() {
			once.Do(func() {
				r.captures.clearProfile(profile)
				<-gate
				release()
			})
		}, nil
	case <-opCtx.Done():
		release()
		return nil, nil, opCtx.Err()
	}
}

func (r *Runtime) profileGate(profile contract.ProfileID) chan struct{} {
	r.locksMu.Lock()
	defer r.locksMu.Unlock()
	gate := r.locks[profile]
	if gate == nil {
		gate = make(chan struct{}, 1)
		r.locks[profile] = gate
	}
	return gate
}

func (r *Runtime) turn(ctx context.Context, binding contract.Binding, replay []infer.Replay) context.Context {
	ctx = context.WithValue(ctx, turnKey{}, turnIdentity{binding: binding})
	states := make([]privacy.Replayed, len(replay))
	for i, entry := range replay {
		states[i] = privacy.Replayed{State: entry.State, Receipt: entry.Receipt}
	}
	return privacy.WithTurn(ctx, privacy.Turn{Binding: binding, Replay: states})
}

type inferAdapter struct{ service *infer.Service }

func (a inferAdapter) Infer(ctx context.Context, req server.InferRequest, sink server.InferSink) error {
	return a.service.Run(ctx, nativeInferRequest(req), sink)
}

func (a inferAdapter) VerifyReplay(ctx context.Context, req server.InferRequest) error {
	return a.service.VerifyReplay(ctx, nativeInferRequest(req))
}

func nativeInferRequest(req server.InferRequest) infer.InferRequest {
	replay := make([]infer.Replay, len(req.Replay))
	for i, entry := range req.Replay {
		replay[i] = infer.Replay{State: entry.State, Receipt: entry.Receipt}
	}
	return infer.InferRequest{
		Profile:   req.Profile,
		Provider:  req.Provider,
		Model:     req.Model,
		SessionID: req.SessionID,
		Input:     req.Input,
		Replay:    replay,
	}
}

type usageAdapter struct{ host *Runtime }

func (a usageAdapter) Usage(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (contract.UsageReport, error) {
	opCtx, release, err := a.host.acquire(ctx, profile)
	if err != nil {
		return contract.UsageReport{}, err
	}
	defer release()
	return a.host.usage.Usage(opCtx, profile, provider)
}

type usageCredential struct{ host *Runtime }

func (c usageCredential) Grant(ctx context.Context, profile contract.ProfileID, provider contract.Provider) (usage.Grant, error) {
	rec, err := c.host.store.Load(ctx, profile, provider)
	if err != nil {
		return usage.Grant{}, err
	}
	if rec == nil {
		return usage.Grant{}, store.ErrNotFound
	}
	if shouldRefresh(provider, rec.ExpiresAt, time.Now()) {
		rec, err = c.host.refresh(ctx, profile, provider, rec)
		if err != nil {
			return usage.Grant{}, err
		}
	}
	meta, err := decodeMetadata(rec.Raw)
	if err != nil {
		return usage.Grant{}, errors.New("stored native credential is invalid")
	}
	access, _ := meta["access_token"].(string)
	account, _ := meta["account_id"].(string)
	if account == "" {
		account, _ = meta["account_uuid"].(string)
	}
	project, _ := meta["project_id"].(string)
	if access == "" {
		return usage.Grant{}, errors.New("stored native credential is invalid")
	}
	return usage.Grant{Access: access, AccountID: account, ProjectID: project}, nil
}

func shouldRefresh(provider contract.Provider, expiry, now time.Time) bool {
	if expiry.IsZero() {
		return false
	}
	var lead time.Duration
	switch provider {
	case contract.ProviderClaude:
		lead = 4 * time.Hour
	case contract.ProviderCodex:
		lead = coreauth.CodexOuterRefreshLead
	case contract.ProviderAntigravity:
		lead = 30 * time.Minute
	}
	return !expiry.After(now.Add(lead))
}

func decodeMetadata(raw []byte) (map[string]any, error) {
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil || meta == nil {
		return nil, errors.New("invalid metadata")
	}
	return meta, nil
}

type nativeStreamer struct{ host *Runtime }

func (s nativeStreamer) ExecuteStream(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	turn, ok := ctx.Value(turnKey{}).(turnIdentity)
	if !ok || len(providers) != 1 || providers[0] != string(turn.binding.Provider) || req.Model != turn.binding.Model {
		return nil, errors.New("native request binding mismatch")
	}
	pinned, _ := opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey].(string)
	if pinned == "" || pinned != turn.binding.CredentialID {
		return nil, errors.New("native credential binding mismatch")
	}
	rec, err := s.host.store.Load(ctx, turn.binding.Profile, turn.binding.Provider)
	if err != nil || rec == nil || rec.CoreAuthID != pinned {
		return nil, errors.New("native credential unavailable")
	}
	if shouldRefresh(turn.binding.Provider, rec.ExpiresAt, time.Now()) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rec, err = s.host.refresh(ctx, turn.binding.Profile, turn.binding.Provider, rec)
		if err != nil {
			return nil, err
		}
	}
	manager, cleanup, err := s.host.nativeManager(ctx, turn.binding.Profile, turn.binding.Provider, rec)
	if err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	result, err := manager.ExecuteStream(streamCtx, providers, req, opts)
	if err != nil {
		cancel()
		cleanup()
		return nil, err
	}
	if result == nil || result.Chunks == nil {
		cancel()
		cleanup()
		return nil, errors.New("native executor returned no stream")
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	wrapped := &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: out}
	go func() {
		defer close(out)
		defer cleanup()
		defer cancel()
		for chunk := range result.Chunks {
			select {
			case out <- chunk:
			case <-ctx.Done():
				cancel()
				return
			}
		}
	}()
	return wrapped, nil
}

func (r *Runtime) nativeManager(ctx context.Context, profile contract.ProfileID, provider contract.Provider, rec *contract.Record) (*coreauth.Manager, func(), error) {
	if err := core.RegisterNativeAuthModels(rec.CoreAuthID, string(provider)); err != nil {
		return nil, nil, err
	}
	manager := coreauth.NewManager(refreshStore{host: r, profile: profile, provider: provider, coreAuthID: rec.CoreAuthID}, nil, nil)
	cleanup := func() {
		manager.Remove(context.Background(), rec.CoreAuthID)
		core.UnregisterNativeAuthModels(rec.CoreAuthID)
	}
	if err := core.RegisterNativeHTTPExecutors(manager, r.cfg); err != nil {
		cleanup()
		return nil, nil, err
	}
	auth, err := coreAuthFromRecord(provider, rec)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		cleanup()
		return nil, nil, err
	}
	return manager, cleanup, nil
}

func coreAuthFromRecord(provider contract.Provider, rec *contract.Record) (*coreauth.Auth, error) {
	meta, err := decodeMetadata(rec.Raw)
	if err != nil || rec.CoreAuthID == "" {
		return nil, errors.New("stored native credential is invalid")
	}
	for key := range meta {
		if runtimeOverrideMetadataKey(key) {
			delete(meta, key)
		}
	}
	attributes := map[string]string(nil)
	switch provider {
	case contract.ProviderClaude:
		meta["cloak_mode"] = "always"
		meta["cloak_strict_mode"] = "false"
	case contract.ProviderCodex:
		attributes = map[string]string{coreauth.AttributeCodexDisableCloaking: "false"}
	}
	return &coreauth.Auth{
		ID: rec.CoreAuthID, Provider: string(provider), Attributes: attributes,
		Metadata: meta, Disabled: false, Status: coreauth.StatusActive, Label: rec.Email,
	}, nil
}

func runtimeOverrideMetadataKey(key string) bool {
	switch normalized := strings.ToLower(key); normalized {
	case "disabled", "proxy", "proxy_url", "proxy-url", "base_url", "base-url", "baseurl",
		"headers", "custom_headers", "custom-headers", "cloak_mode", "cloak_strict_mode":
		return true
	default:
		return strings.HasPrefix(normalized, "header:")
	}
}

type refreshStore struct {
	host       *Runtime
	profile    contract.ProfileID
	provider   contract.Provider
	coreAuthID string
}

func (s refreshStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (s refreshStore) Delete(context.Context, string) error           { return nil }
func (s refreshStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil || auth.ID != s.coreAuthID || auth.Provider != string(s.provider) {
		return "", errors.New("native auth persistence rejected")
	}
	persistCtx := context.WithoutCancel(ctx)
	gen, err := s.host.store.Generation(s.profile, s.provider)
	if err != nil {
		return "", errors.New("native auth persistence rejected")
	}
	current, err := s.host.store.Load(persistCtx, s.profile, s.provider)
	if err != nil || current == nil || current.CoreAuthID != s.coreAuthID {
		return "", errors.New("native auth persistence rejected")
	}
	before, err := decodeMetadata(current.Raw)
	if err != nil {
		return "", errors.New("native auth persistence rejected")
	}
	persisted := make(map[string]any, len(auth.Metadata))
	for key, value := range auth.Metadata {
		if !runtimeOverrideMetadataKey(key) {
			persisted[key] = value
		}
	}
	for key, value := range before {
		if runtimeOverrideMetadataKey(key) {
			persisted[key] = value
		}
	}
	if reflect.DeepEqual(before, persisted) {
		return auth.ID, nil
	}
	raw, err := json.Marshal(persisted)
	if err != nil {
		return "", errors.New("native auth persistence rejected")
	}
	rec := *current
	rec.Raw = raw
	if email, ok := auth.Metadata["email"].(string); ok {
		rec.Email = email
	}
	if expiry, ok := auth.Metadata["expired"].(string); ok {
		rec.ExpiresAt, _ = time.Parse(time.RFC3339, expiry)
	}
	if err := s.host.lifecycle.PersistRefresh(persistCtx, s.profile, s.provider, gen, &rec); err != nil {
		return "", errors.New("native auth persistence rejected")
	}
	return auth.ID, nil
}

func (r *Runtime) refresh(ctx context.Context, profile contract.ProfileID, provider contract.Provider, prior *contract.Record) (*contract.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := r.store.Load(ctx, profile, provider)
	if err != nil || current == nil || current.CoreAuthID != prior.CoreAuthID {
		return nil, errors.New("native credential changed")
	}
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	manager, cleanup, err := r.nativeManager(refreshCtx, profile, provider, current)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if _, err := manager.ForceRefreshAuth(refreshCtx, current.CoreAuthID); err != nil {
		return nil, errors.New("native credential refresh failed")
	}
	refreshed, err := r.store.Load(refreshCtx, profile, provider)
	if err != nil || refreshed == nil || refreshed.CoreAuthID != current.CoreAuthID {
		return nil, errors.New("native credential refresh was not persisted")
	}
	return refreshed, nil
}

var _ contract.Usage = usageAdapter{}
var _ usage.Credential = usageCredential{}
var _ infer.Streamer = nativeStreamer{}
var _ server.Inferer = inferAdapter{}

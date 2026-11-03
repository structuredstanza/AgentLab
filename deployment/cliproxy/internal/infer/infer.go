// Package infer runs one native inference turn through the pinned core's
// native executors. Replay provenance is verified before any upstream call.
package infer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/nativepolicy"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"

	"github.com/artex/cliproxyhost/internal/catalog"
	"github.com/artex/cliproxyhost/internal/contract"
	"github.com/artex/cliproxyhost/internal/store"
)

// Stop reasons reported on the done record.
const (
	StopEnd     = "end"
	StopTool    = "tool"
	StopRefusal = "refusal"
	StopLength  = "length"
	StopError   = "error"
)

// Bounded error codes. Messages never echo provider or payload text.
const (
	CodeInvalid        = "invalid_request"
	CodeNotConnected   = "not_connected"
	CodeUnavailable    = "unavailable"
	CodeTruncated      = "truncated"
	CodeCanceled       = "canceled"
	CodeQuotaExhausted = "quota_exhausted"
	CodeUnauthorized   = "upstream_unauthorized"
	CodeForbidden      = "upstream_forbidden"
)

var messages = map[string]string{
	CodeInvalid:        "invalid inference request",
	CodeNotConnected:   "profile is not connected",
	CodeUnavailable:    "upstream unavailable",
	CodeTruncated:      "upstream stream truncated",
	CodeCanceled:       "inference canceled",
	CodeQuotaExhausted: "upstream quota exhausted",
	CodeUnauthorized:   "upstream authentication failed",
	CodeForbidden:      "upstream authorization denied",
}

// Error is a bounded inference failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// ErrorStatus reports the HTTP status code and bounded code string for server responses.
func (e *Error) ErrorStatus() (int, string) {
	if e == nil {
		return http.StatusInternalServerError, "internal_error"
	}
	switch e.Code {
	case CodeInvalid:
		return http.StatusBadRequest, e.Code
	case CodeNotConnected:
		return http.StatusUnauthorized, e.Code
	case CodeUnavailable:
		return http.StatusServiceUnavailable, e.Code
	case CodeTruncated:
		return http.StatusBadGateway, e.Code
	case CodeCanceled:
		return http.StatusRequestTimeout, e.Code
	case CodeQuotaExhausted:
		return http.StatusTooManyRequests, e.Code
	case CodeUnauthorized:
		return http.StatusUnauthorized, e.Code
	case CodeForbidden:
		return http.StatusForbidden, e.Code
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func fail(code string) error { return &Error{Code: code, Message: messages[code]} }

// Replay is one previously admitted assistant state and its host receipt.
type Replay struct {
	State   []byte
	Receipt string
}

// InferRequest is the validated wire shape for one inference turn.
type InferRequest struct {
	Profile   contract.ProfileID
	Provider  contract.Provider
	Model     string
	SessionID string
	Input     json.RawMessage
	Replay    []Replay
}

// Sink receives NDJSON records in order. A returned error aborts the turn.
type Sink interface {
	Send(record any) error
}

// Usage is the normalized token accounting reported on done.
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_tokens"`
	CacheWriteTokens int `json:"cache_write_tokens"`
	ReasoningTokens  int `json:"reasoning_tokens"`
}

// WireRequest is the redacted provider request record.
type WireRequest struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// WireSSE is one redacted provider SSE data frame.
type WireSSE struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// Done is the terminal record of a completed native turn.
type Done struct {
	Type     string          `json:"type"`
	Response json.RawMessage `json:"response"`
	State    json.RawMessage `json:"state"`
	Receipt  string          `json:"receipt"`
	Usage    Usage           `json:"usage"`
	Stop     string          `json:"stop"`
}

// Streamer is the subset of the core manager used for native streams.
type Streamer interface {
	ExecuteStream(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
}

// Deps are the host seams. Acquire, Turn, and Captured are wired by the parent.
type Deps struct {
	Store    contract.Store
	Catalog  contract.Catalog
	Receipts contract.Receipts
	Streamer Streamer
	// Acquire blocks profile disconnect until release is called.
	Acquire func(ctx context.Context, profile contract.ProfileID) (operationCtx context.Context, release func(), err error)
	// Turn attaches the privacy capture turn; called after receipt verification.
	Turn func(ctx context.Context, b contract.Binding, replay []Replay) context.Context
	// Captured returns the final provider request captured for the turn.
	Captured func(ctx context.Context) ([]byte, bool)
}

// Service runs native inference turns.
type Service struct {
	d Deps
}

// New validates the dependencies.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Catalog == nil || d.Receipts == nil || d.Streamer == nil ||
		d.Acquire == nil || d.Turn == nil || d.Captured == nil {
		return nil, errors.New("infer: incomplete dependencies")
	}
	return &Service{d: d}, nil
}

type admittedTurn struct {
	ctx     context.Context
	release func()
	binding contract.Binding
	input   json.RawMessage
	replay  []Replay
}

// Run executes one turn and streams wire and done records to sink.
func (s *Service) Run(ctx context.Context, req InferRequest, sink Sink) error {
	turn, err := s.admit(ctx, req)
	if err != nil {
		return err
	}
	defer turn.release()
	ctx = nativepolicy.WithStrictReplay(turn.ctx)
	ctx = s.d.Turn(ctx, turn.binding, turn.replay)
	return s.stream(ctx, turn.binding, turn.input, turn.binding.CredentialID, sink)
}

// VerifyReplay admits existing receipts offline, without inference or refresh.
func (s *Service) VerifyReplay(ctx context.Context, req InferRequest) error {
	if len(req.Replay) == 0 {
		return fail(CodeInvalid)
	}
	if len(req.Input) == 0 {
		req.Input = json.RawMessage(`{}`)
	}
	turn, err := s.admit(ctx, req)
	if err != nil {
		return err
	}
	turn.release()
	return nil
}

func (s *Service) admit(ctx context.Context, req InferRequest) (admittedTurn, error) {
	provider := req.Provider
	if _, ok := contract.ParseProvider(string(provider)); !ok {
		return admittedTurn{}, fail(CodeInvalid)
	}
	profile, err := contract.ParseProfileID(string(req.Profile))
	if err != nil || req.SessionID == "" || len(req.SessionID) > maxSessionBytes {
		return admittedTurn{}, fail(CodeInvalid)
	}
	models, err := s.d.Catalog.Models(provider)
	if err != nil {
		return admittedTurn{}, fail(CodeUnavailable)
	}
	model, ok := findModel(models, req.Model)
	if !ok {
		return admittedTurn{}, fail(CodeInvalid)
	}
	doc, err := parseInput(req.Input, req.Model)
	if err != nil {
		return admittedTurn{}, err
	}
	if effort := effortOf(provider, doc); effort != "" && !slices.Contains(model.SupportedEfforts, effort) {
		return admittedTurn{}, fail(CodeInvalid)
	}
	wireModel, resolvedInput, err := catalog.Resolve(provider, req.Model, req.Input)
	if err != nil {
		return admittedTurn{}, fail(CodeInvalid)
	}
	ctx, release, err := s.d.Acquire(ctx, profile)
	if err != nil {
		return admittedTurn{}, fail(CodeUnavailable)
	}
	admitted := false
	defer func() {
		if !admitted {
			release()
		}
	}()
	rec, err := s.d.Store.Load(ctx, profile, provider)
	if errors.Is(err, store.ErrNotFound) || (err == nil && rec == nil) {
		return admittedTurn{}, fail(CodeNotConnected)
	}
	if err != nil {
		return admittedTurn{}, fail(CodeUnavailable)
	}
	binding := contract.Binding{Provider: provider, Model: wireModel, Profile: profile, SessionID: req.SessionID, CredentialID: rec.CoreAuthID}
	if err := verifyReplay(s.d.Receipts, binding, req.Replay, doc); err != nil {
		return admittedTurn{}, err
	}
	replays := make([]Replay, len(req.Replay))
	for i, replay := range req.Replay {
		state, err := canonicalJSON(replay.State)
		if err != nil {
			return admittedTurn{}, contract.ErrDenied
		}
		replays[i] = Replay{State: state, Receipt: replay.Receipt}
	}
	admitted = true
	return admittedTurn{ctx: ctx, release: release, binding: binding, input: resolvedInput, replay: replays}, nil
}

func (s *Service) stream(ctx context.Context, b contract.Binding, input json.RawMessage, coreAuthID string, sink Sink) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	format := formatOf(b.Provider)
	sourceFormat := format
	if b.Provider == contract.ProviderCodex {
		// Normalize Responses-shaped requests while retaining native Codex output.
		sourceFormat = sdktranslator.FormatOpenAIResponse
	}
	res, err := s.d.Streamer.ExecuteStream(ctx, []string{string(b.Provider)},
		cliproxyexecutor.Request{Model: b.Model, Payload: input, Format: sourceFormat},
		cliproxyexecutor.Options{
			Stream:         true,
			SourceFormat:   sourceFormat,
			ResponseFormat: format,
			Metadata:       map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: coreAuthID},
		})
	if err != nil {
		return streamErr(ctx, err)
	}
	defer func() {
		cancel()
		for range res.Chunks {
		}
	}()
	totalBytes := 0
	acc := newAccumulator(b.Provider)
	for chunk := range res.Chunks {
		totalBytes += len(chunk.Payload)
		if totalBytes > maxInputBytes {
			return fail(CodeUnavailable)
		}
		if chunk.Err != nil {
			return streamErr(ctx, chunk.Err)
		}
		if err := consume(chunk.Payload, acc, sink); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return fail(CodeCanceled)
	}
	out, ok, err := acc.result()
	if err != nil {
		return fail(CodeUnavailable)
	}
	if !ok {
		return fail(CodeTruncated)
	}
	if raw, ok := s.d.Captured(ctx); ok {
		safe, err := redactJSON(raw)
		if err != nil {
			return fail(CodeUnavailable)
		}
		if err := sink.Send(WireRequest{Type: "wire_request", Payload: safe}); err != nil {
			return err
		}
	}
	receipt, err := s.d.Receipts.Sign(b, out.state)
	if err != nil {
		return fail(CodeUnavailable)
	}
	return sink.Send(Done{
		Type:     "done",
		Response: out.response,
		State:    out.state,
		Receipt:  receipt,
		Usage:    out.usage,
		Stop:     out.stop,
	})
}

var dataPrefix = []byte("data:")

var doneMarker = []byte("[DONE]")

func isDoneMarker(b []byte) bool {
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, dataPrefix) {
		b = bytes.TrimSpace(b[len(dataPrefix):])
	}
	return bytes.Equal(b, doneMarker)
}

func consume(payload []byte, acc accumulator, sink Sink) error {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || isDoneMarker(trimmed) {
		return nil
	}

	// If the entire payload is a single valid JSON object, process it directly.
	if bytes.HasPrefix(trimmed, []byte("{")) && bytes.HasSuffix(trimmed, []byte("}")) && json.Valid(trimmed) {
		return processFrame(trimmed, acc, sink)
	}

	// Otherwise, process line-by-line (for SSE frames, NDJSON, or multi-line chunks).
	for _, line := range bytes.Split(payload, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || isDoneMarker(line) {
			continue
		}
		if bytes.HasPrefix(line, []byte(":")) {
			// SSE comment
			continue
		}
		if bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte("id:")) || bytes.HasPrefix(line, []byte("retry:")) {
			// SSE header field
			continue
		}
		isData := bytes.HasPrefix(line, dataPrefix)
		if isData {
			line = bytes.TrimSpace(line[len(dataPrefix):])
			if len(line) == 0 || isDoneMarker(line) {
				continue
			}
		}
		if isData || bytes.HasPrefix(line, []byte("{")) {
			if err := processFrame(line, acc, sink); err != nil {
				return err
			}
		}
	}
	return nil
}

func processFrame(data []byte, acc accumulator, sink Sink) error {
	ev, err := decodeObject(data)
	if err != nil {
		return fail(CodeUnavailable)
	}
	if err := acc.feed(ev); err != nil {
		return err
	}
	safe, err := redactJSON(data)
	if err != nil {
		return fail(CodeUnavailable)
	}
	return sink.Send(WireSSE{Type: "wire_sse", Data: string(safe)})
}

func streamErr(ctx context.Context, err error) error {
	var trunc cliproxyexecutor.StreamTruncatedError
	switch {
	case ctx.Err() != nil:
		return fail(CodeCanceled)
	case errors.Is(err, contract.ErrDenied):
		return contract.ErrDenied
	case errors.As(err, &trunc) && trunc.IsStreamTruncated():
		return fail(CodeTruncated)
	}
	var statusErr interface{ StatusCode() int }
	if errors.As(err, &statusErr) && statusErr != nil {
		switch statusErr.StatusCode() {
		case http.StatusTooManyRequests:
			return fail(CodeQuotaExhausted)
		case http.StatusUnauthorized:
			return fail(CodeUnauthorized)
		case http.StatusForbidden:
			return fail(CodeForbidden)
		}
	}
	return fail(CodeUnavailable)
}

func formatOf(p contract.Provider) sdktranslator.Format {
	switch p {
	case contract.ProviderClaude:
		return sdktranslator.FormatClaude
	case contract.ProviderCodex:
		return sdktranslator.FormatCodex
	default:
		return sdktranslator.FormatAntigravity
	}
}

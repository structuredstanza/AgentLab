package infer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/store"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestRedactJSONKeepsMaxTokensAndMasksAuthorization(t *testing.T) {
	got, err := redactJSON([]byte(`{"max_tokens":128,"authorization":"Bearer secret","input":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["max_tokens"] != float64(128) || doc["authorization"] != "[redacted]" || doc["input"] != "safe" {
		t.Fatalf("unexpected redaction result: %s", got)
	}
}

type fixtureReceipts struct{ denied bool }

func (r fixtureReceipts) Sign(contract.Binding, []byte) (string, error) {
	return "receipt", nil
}
func (r fixtureReceipts) Verify(_ string, _ contract.Binding, _ []byte) error {
	if r.denied {
		return contract.ErrDenied
	}
	return nil
}

func TestReplayRejectsForeignOpaqueAndSubstrings(t *testing.T) {
	b := contract.Binding{Provider: contract.ProviderClaude, Model: "model", Profile: "1", SessionID: "session"}
	replay := []Replay{{State: []byte(`{"signature":"signed-original"}`), Receipt: "receipt"}}
	for _, signature := range []string{"foreign", "original"} {
		if err := verifyReplay(fixtureReceipts{}, b, replay, map[string]any{"signature": signature}); !errors.Is(err, contract.ErrDenied) {
			t.Fatal("unadmitted opaque value accepted")
		}
	}
	if err := verifyReplay(fixtureReceipts{denied: true}, b, replay, map[string]any{"signature": "signed-original"}); !errors.Is(err, contract.ErrDenied) {
		t.Fatal("bad receipt accepted")
	}
}

type fixtureStreamer struct{}

func (fixtureStreamer) ExecuteStream(context.Context, []string, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	ch := make(chan coreexecutor.StreamChunk)
	close(ch)
	return &coreexecutor.StreamResult{Chunks: ch}, nil
}

type fixtureSink struct{ records []any }

func (s *fixtureSink) Send(record any) error {
	s.records = append(s.records, record)
	return nil
}

func TestTruncatedStreamNeverEmitsDone(t *testing.T) {
	service := &Service{d: Deps{Streamer: fixtureStreamer{}}}
	sink := &fixtureSink{}
	err := service.stream(context.Background(), contract.Binding{Provider: contract.ProviderClaude, Model: "model"}, []byte(`{}`), "opaque-auth", sink)
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != CodeTruncated {
		t.Fatalf("got %v, want truncated", err)
	}
	if len(sink.records) != 0 {
		t.Fatal("truncated stream emitted records")
	}
}

func TestNativeRefusalStopsRemainDistinct(t *testing.T) {
	if claudeStop("refusal") != StopRefusal {
		t.Fatal("Claude refusal lost")
	}
	if codexStop("response.incomplete", map[string]any{"incomplete_details": map[string]any{"reason": "content_filter"}}, nil) != StopRefusal {
		t.Fatal("Codex refusal lost")
	}
}

func TestAntigravityTextWithoutFinishIsTruncated(t *testing.T) {
	acc := newAccumulator(contract.ProviderAntigravity)
	err := acc.feed(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": "partial"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, complete, err := acc.result(); err != nil || complete {
		t.Fatal("unterminated text accepted as complete")
	}
}

type boundReceiptFixture struct {
	fixtureReceipts
	binding contract.Binding
}

func (r *boundReceiptFixture) Verify(_ string, binding contract.Binding, _ []byte) error {
	r.binding = binding
	return contract.ErrDenied
}

type loadedStoreFixture struct {
	contract.Store
	loads int
}

func (s *loadedStoreFixture) Load(context.Context, contract.ProfileID, contract.Provider) (*contract.Record, error) {
	s.loads++
	return &contract.Record{CoreAuthID: "current-credential"}, nil
}

type catalogFixture struct{}

func (catalogFixture) Models(contract.Provider) ([]contract.Model, error) {
	return []contract.Model{{ID: "model"}}, nil
}

type forbiddenStreamerFixture struct{ t *testing.T }

func (s forbiddenStreamerFixture) ExecuteStream(context.Context, []string, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	s.t.Fatal("provider called before receipt admission")
	return nil, errors.New("unexpected provider call")
}

func TestReplayBoundToLoadedCredentialBeforeProviderCall(t *testing.T) {
	store := &loadedStoreFixture{}
	receipts := &boundReceiptFixture{}
	released := false
	service := &Service{d: Deps{
		Store: store, Catalog: catalogFixture{}, Receipts: receipts,
		Streamer: forbiddenStreamerFixture{t},
		Acquire: func(ctx context.Context, _ contract.ProfileID) (context.Context, func(), error) {
			return ctx, func() { released = true }, nil
		},
	}}
	err := service.Run(context.Background(), InferRequest{
		Profile: "1", Provider: contract.ProviderClaude, Model: "model", SessionID: "session",
		Input:  []byte(`{"model":"model"}`),
		Replay: []Replay{{State: []byte(`{"content":[]}`), Receipt: "old-receipt"}},
	}, &fixtureSink{})
	if !errors.Is(err, contract.ErrDenied) || receipts.binding.CredentialID != "current-credential" || store.loads != 1 || !released {
		t.Fatalf("credential admission failed: err=%v binding=%+v loads=%d released=%v", err, receipts.binding, store.loads, released)
	}
}

type argonCatalogFixture struct{}

func (argonCatalogFixture) Models(contract.Provider) ([]contract.Model, error) {
	return []contract.Model{{ID: "gemini-4-argon", SupportedEfforts: []string{"low", "medium", "high"}}}, nil
}

type requestStreamerFixture struct {
	req coreexecutor.Request
}

func (s *requestStreamerFixture) ExecuteStream(_ context.Context, _ []string, req coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	s.req = req
	ch := make(chan coreexecutor.StreamChunk)
	close(ch)
	return &coreexecutor.StreamResult{Chunks: ch}, nil
}

func TestArgonWireSKUAndOperationContext(t *testing.T) {
	type contextKey struct{}
	for _, level := range []string{"", "medium", "high"} {
		t.Run(level, func(t *testing.T) {
			input := json.RawMessage(`{"model":"gemini-4-argon","generationConfig":{"thinkingConfig":{"thinkingLevel":"` + level + `"}}}`)
			wireModel := "gemini-4-argon-" + level
			if level == "" {
				wireModel = "gemini-4-argon-low"
			}
			streamer := &requestStreamerFixture{}
			var binding contract.Binding
			service := &Service{d: Deps{
				Store: &loadedStoreFixture{}, Catalog: argonCatalogFixture{}, Receipts: fixtureReceipts{},
				Streamer: streamer,
				Acquire: func(ctx context.Context, _ contract.ProfileID) (context.Context, func(), error) {
					return context.WithValue(ctx, contextKey{}, true), func() {}, nil
				},
				Turn: func(ctx context.Context, b contract.Binding, _ []Replay) context.Context {
					if ctx.Value(contextKey{}) != true {
						t.Fatal("lifecycle operation context discarded")
					}
					binding = b
					return ctx
				},
			}}
			err := service.Run(context.Background(), InferRequest{
				Profile: "1", Provider: contract.ProviderAntigravity, Model: "gemini-4-argon",
				SessionID: "session", Input: input,
			}, &fixtureSink{})
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != CodeTruncated {
				t.Fatalf("unexpected terminal error: %v", err)
			}
			if binding.Model != wireModel || streamer.req.Model != wireModel || string(streamer.req.Payload) != string(input) {
				t.Fatal("logical model did not resolve to a receipt-bound native SKU")
			}
		})
	}
}

func TestArgonReplayVerificationUsesNativeSKU(t *testing.T) {
	receipts := &boundReceiptFixture{}
	service := &Service{d: Deps{
		Store: &loadedStoreFixture{}, Catalog: argonCatalogFixture{}, Receipts: receipts,
		Streamer: forbiddenStreamerFixture{t},
		Acquire: func(ctx context.Context, _ contract.ProfileID) (context.Context, func(), error) {
			return ctx, func() {}, nil
		},
	}}
	err := service.Run(context.Background(), InferRequest{
		Profile: "1", Provider: contract.ProviderAntigravity, Model: "gemini-4-argon", SessionID: "session",
		Input:  []byte(`{"generationConfig":{"thinkingConfig":{"thinkingLevel":"high"}}}`),
		Replay: []Replay{{State: []byte(`{"candidates":[]}`), Receipt: "low-sku-receipt"}},
	}, &fixtureSink{})
	if !errors.Is(err, contract.ErrDenied) || receipts.binding.Model != "gemini-4-argon-high" {
		t.Fatal("replay verification was not native SKU-bound")
	}
}

func TestNativeUsageKeepsCacheReadWriteAndReasoning(t *testing.T) {
	cases := []struct {
		provider contract.Provider
		events   []string
		want     Usage
	}{
		{
			provider: contract.ProviderClaude,
			events: []string{
				`{"type":"message_start","message":{"role":"assistant","usage":{"input_tokens":11,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}}`,
				`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
				`{"type":"message_stop"}`,
			},
			want: Usage{InputTokens: 11, OutputTokens: 7, CacheReadTokens: 3, CacheWriteTokens: 2},
		},
		{
			provider: contract.ProviderCodex,
			events:   []string{`{"type":"response.completed","response":{"output":[],"usage":{"input_tokens":11,"output_tokens":7,"input_tokens_details":{"cached_tokens":3},"output_tokens_details":{"reasoning_tokens":5}}}}`},
			want:     Usage{InputTokens: 11, OutputTokens: 7, CacheReadTokens: 3, ReasoningTokens: 5},
		},
		{
			provider: contract.ProviderAntigravity,
			events:   []string{`{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"answer"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":7,"cachedContentTokenCount":3,"thoughtsTokenCount":5}}}`},
			want:     Usage{InputTokens: 11, OutputTokens: 7, CacheReadTokens: 3, ReasoningTokens: 5},
		},
	}
	for _, tt := range cases {
		t.Run(string(tt.provider), func(t *testing.T) {
			acc := newAccumulator(tt.provider)
			for _, raw := range tt.events {
				event, err := decodeObject([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				if err := acc.feed(event); err != nil {
					t.Fatal(err)
				}
			}
			result, complete, err := acc.result()
			if err != nil || !complete || result.usage != tt.want {
				t.Fatalf("usage=%+v want=%+v complete=%v err=%v", result.usage, tt.want, complete, err)
			}
			wire, err := json.Marshal(result.usage)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]int
			if err := json.Unmarshal(wire, &fields); err != nil {
				t.Fatal(err)
			}
			if _, exists := fields["cached_tokens"]; exists {
				t.Fatal("obsolete cached_tokens alias emitted")
			}
			if len(fields) != 5 || fields["cache_read_tokens"] != tt.want.CacheReadTokens || fields["cache_write_tokens"] != tt.want.CacheWriteTokens {
				t.Fatalf("unexpected canonical usage: %s", wire)
			}
		})
	}
}

func TestErrorStatusMappings(t *testing.T) {
	cases := []struct {
		err        *Error
		wantStatus int
		wantCode   string
	}{
		{fail(CodeInvalid).(*Error), http.StatusBadRequest, "invalid_request"},
		{fail(CodeNotConnected).(*Error), http.StatusUnauthorized, "not_connected"},
		{fail(CodeUnavailable).(*Error), http.StatusServiceUnavailable, "unavailable"},
		{fail(CodeTruncated).(*Error), http.StatusBadGateway, "truncated"},
		{fail(CodeCanceled).(*Error), http.StatusRequestTimeout, "canceled"},
		{fail(CodeQuotaExhausted).(*Error), http.StatusTooManyRequests, CodeQuotaExhausted},
		{fail(CodeUnauthorized).(*Error), http.StatusUnauthorized, CodeUnauthorized},
		{fail(CodeForbidden).(*Error), http.StatusForbidden, CodeForbidden},
		{&Error{Code: "unknown_future_code"}, http.StatusInternalServerError, "internal_error"},
		{nil, http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range cases {
		status, code := tt.err.ErrorStatus()
		if status != tt.wantStatus || code != tt.wantCode {
			t.Fatalf("ErrorStatus(%v) = (%d, %q), want (%d, %q)", tt.err, status, code, tt.wantStatus, tt.wantCode)
		}
	}
}

type fixtureUpstreamStatusError int

func (e fixtureUpstreamStatusError) Error() string   { return "untrusted upstream error detail" }
func (e fixtureUpstreamStatusError) StatusCode() int { return int(e) }

type fixtureTruncatedStatusError int

func (e fixtureTruncatedStatusError) Error() string         { return "truncated upstream" }
func (e fixtureTruncatedStatusError) StatusCode() int       { return int(e) }
func (fixtureTruncatedStatusError) IsStreamTruncated() bool { return true }

func TestStreamErrPreservesSafeNativeStatusesAndPrecedence(t *testing.T) {
	for _, tc := range []struct {
		status     int
		wantStatus int
		wantCode   string
	}{
		{http.StatusTooManyRequests, http.StatusTooManyRequests, CodeQuotaExhausted},
		{http.StatusUnauthorized, http.StatusUnauthorized, CodeUnauthorized},
		{http.StatusForbidden, http.StatusForbidden, CodeForbidden},
		{http.StatusBadGateway, http.StatusServiceUnavailable, CodeUnavailable},
	} {
		var failure *Error
		err := streamErr(context.Background(), fixtureUpstreamStatusError(tc.status))
		if !errors.As(err, &failure) {
			t.Fatalf("streamErr(%d) = %T, want bounded inference error", tc.status, err)
		}
		gotStatus, gotCode := failure.ErrorStatus()
		if gotStatus != tc.wantStatus || gotCode != tc.wantCode || failure.Error() == "untrusted upstream error detail" {
			t.Fatalf("streamErr(%d) = (%d, %q), want (%d, %q) without upstream detail", tc.status, gotStatus, gotCode, tc.wantStatus, tc.wantCode)
		}
	}

	var truncated *Error
	if err := streamErr(context.Background(), fixtureTruncatedStatusError(http.StatusTooManyRequests)); !errors.As(err, &truncated) || truncated.Code != CodeTruncated {
		t.Fatalf("truncation lost precedence over upstream status: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var canceled *Error
	if err := streamErr(ctx, fixtureUpstreamStatusError(http.StatusTooManyRequests)); !errors.As(err, &canceled) || canceled.Code != CodeCanceled {
		t.Fatalf("cancellation lost precedence over upstream status: %v", err)
	}
}

func TestStreamErrPreservesPrivacyDenial(t *testing.T) {
	for _, err := range []error{contract.ErrDenied, errors.Join(errors.New("transport failed"), contract.ErrDenied)} {
		if got := streamErr(context.Background(), err); !errors.Is(got, contract.ErrDenied) {
			t.Fatalf("privacy denial became %T instead of the denial sentinel", got)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var failure *Error
		if got := streamErr(ctx, err); !errors.As(got, &failure) || failure.Code != CodeCanceled {
			t.Fatalf("cancellation lost precedence over privacy denial: %T", got)
		}
	}
}

type errStoreFixture struct {
	contract.Store
	err error
}

func (s *errStoreFixture) Load(context.Context, contract.ProfileID, contract.Provider) (*contract.Record, error) {
	return nil, s.err
}

func TestStoreErrNotFoundYieldsNotConnected(t *testing.T) {
	service := &Service{d: Deps{
		Store:    &errStoreFixture{err: store.ErrNotFound},
		Catalog:  catalogFixture{},
		Receipts: fixtureReceipts{},
		Streamer: forbiddenStreamerFixture{t},
		Acquire: func(ctx context.Context, _ contract.ProfileID) (context.Context, func(), error) {
			return ctx, func() {}, nil
		},
	}}
	err := service.Run(context.Background(), InferRequest{
		Profile: "1", Provider: contract.ProviderClaude, Model: "model", SessionID: "session",
		Input: []byte(`{"model":"model"}`),
	}, &fixtureSink{})
	var inferErr *Error
	if !errors.As(err, &inferErr) || inferErr.Code != CodeNotConnected {
		t.Fatalf("Run with ErrNotFound returned %v, want CodeNotConnected", err)
	}
	status, code := inferErr.ErrorStatus()
	if status != http.StatusUnauthorized || code != "not_connected" {
		t.Fatalf("ErrorStatus() = (%d, %q), want (401, not_connected)", status, code)
	}

	// Genuine unexpected storage error returns unavailable (503).
	service.d.Store = &errStoreFixture{err: errors.New("underlying disk I/O error")}
	errIO := service.Run(context.Background(), InferRequest{
		Profile: "1", Provider: contract.ProviderClaude, Model: "model", SessionID: "session",
		Input: []byte(`{"model":"model"}`),
	}, &fixtureSink{})
	if !errors.As(errIO, &inferErr) || inferErr.Code != CodeUnavailable {
		t.Fatalf("Run with I/O error returned %v, want CodeUnavailable", errIO)
	}
	statusIO, codeIO := inferErr.ErrorStatus()
	if statusIO != http.StatusServiceUnavailable || codeIO != "unavailable" {
		t.Fatalf("ErrorStatus() = (%d, %q), want (503, unavailable)", statusIO, codeIO)
	}
}

func TestConsumeRawNativeAntigravityAndDone(t *testing.T) {
	acc := newAccumulator(contract.ProviderAntigravity)
	sink := &fixtureSink{}

	// Chunk 1: Raw native JSON with thoughtSignature and functionCall without SSE data: prefix
	rawChunk := []byte(`{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"investigating","thoughtSignature":"ts-antigravity-xyz"},{"functionCall":{"name":"execute","args":{"step":1}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":42,"candidatesTokenCount":18,"thoughtsTokenCount":9}}}`)
	if err := consume(rawChunk, acc, sink); err != nil {
		t.Fatalf("consume raw chunk: %v", err)
	}
	if len(sink.records) != 1 {
		t.Fatalf("sink received %d records, want 1 wire_sse", len(sink.records))
	}
	wire, ok := sink.records[0].(WireSSE)
	if !ok || wire.Type != "wire_sse" {
		t.Fatalf("unexpected record: %#v", sink.records[0])
	}
	if !strings.Contains(wire.Data, "ts-antigravity-xyz") {
		t.Fatalf("wire_sse masked thoughtSignature: %s", wire.Data)
	}

	// Chunk 2: Literal [DONE] without SSE prefix
	if err := consume([]byte("[DONE]"), acc, sink); err != nil {
		t.Fatalf("consume [DONE]: %v", err)
	}
	// No new record emitted for [DONE]
	if len(sink.records) != 1 {
		t.Fatalf("sink received extra record on [DONE]: %d", len(sink.records))
	}

	res, complete, err := acc.result()
	if err != nil || !complete {
		t.Fatalf("acc.result() = complete:%v err:%v, want complete true", complete, err)
	}
	if res.stop != StopTool {
		t.Fatalf("stop = %q, want %q for functionCall", res.stop, StopTool)
	}
	if res.usage.InputTokens != 42 || res.usage.OutputTokens != 18 || res.usage.ReasoningTokens != 9 {
		t.Fatalf("unexpected usage: %+v", res.usage)
	}
	if !strings.Contains(string(res.state), "ts-antigravity-xyz") || !strings.Contains(string(res.state), "functionCall") {
		t.Fatalf("state omitted native parts: %s", string(res.state))
	}
}

func TestConsumeMixedSSEAndRawFrames(t *testing.T) {
	acc := newAccumulator(contract.ProviderClaude)
	sink := &fixtureSink{}

	// Chunk with SSE event, comment, data, and [DONE]
	mixed := []byte(": keepalive comment\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"usage\":{\"input_tokens\":5}}}\n\n")
	if err := consume(mixed, acc, sink); err != nil {
		t.Fatalf("consume mixed SSE: %v", err)
	}
	if len(sink.records) != 1 {
		t.Fatalf("sink received %d records, want 1", len(sink.records))
	}

	delta := []byte("data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\ndata: [DONE]\n")
	if err := consume(delta, acc, sink); err != nil {
		t.Fatalf("consume delta: %v", err)
	}
	if len(sink.records) != 2 {
		t.Fatalf("sink received %d records, want 2", len(sink.records))
	}

	stop := []byte("data: {\"type\":\"message_stop\"}\n")
	if err := consume(stop, acc, sink); err != nil {
		t.Fatalf("consume stop: %v", err)
	}

	res, complete, err := acc.result()
	if err != nil || !complete {
		t.Fatalf("acc.result() = complete:%v err:%v", complete, err)
	}
	if res.stop != StopEnd {
		t.Fatalf("stop = %q, want %q", res.stop, StopEnd)
	}
	if res.usage.InputTokens != 5 || res.usage.OutputTokens != 3 {
		t.Fatalf("usage = %+v, want input:5 output:3", res.usage)
	}
}

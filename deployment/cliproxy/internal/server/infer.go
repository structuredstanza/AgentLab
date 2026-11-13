package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
)

// Inferer runs one inference turn. The infer slice implements it; this package never
// imports that slice.
type Inferer interface {
	Infer(ctx context.Context, req InferRequest, w InferSink) error
	VerifyReplay(ctx context.Context, req InferRequest) error
}

// InferRequest is the validated inference request. Input is the native payload,
// passed through unchanged.
type InferRequest struct {
	Profile   contract.ProfileID
	Provider  contract.Provider
	Model     string
	SessionID string
	Input     json.RawMessage
	Replay    []Replay
}

// Replay is one previously issued opaque state with its signed receipt.
type Replay struct {
	State   json.RawMessage `json:"state"`
	Receipt string          `json:"receipt"`
}

// InferSink receives NDJSON records. Send writes one JSON object per line and flushes.
type InferSink interface {
	Send(record any) error
}

// inferBody is the wire form. The profile comes from the path, not the body.
type inferBody struct {
	Provider  string          `json:"provider"`
	Model     string          `json:"model"`
	SessionID string          `json:"session_id"`
	Input     json.RawMessage `json:"input"`
	Replay    []Replay        `json:"replay"`
}

// streamError is the bounded terminal record sent after the stream has started.
type streamError struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// lazySink commits the NDJSON response on the first record, so failures before any
// output still get a proper HTTP status.
type lazySink struct {
	w       http.ResponseWriter
	enc     *json.Encoder
	flusher http.Flusher
}

func (l *lazySink) Send(record any) error {
	if l.enc == nil {
		l.w.Header().Set("Content-Type", "application/x-ndjson")
		l.w.Header().Set("Cache-Control", "no-store")
		l.w.WriteHeader(http.StatusOK)
		l.enc = json.NewEncoder(l.w)
		l.flusher, _ = l.w.(http.Flusher)
	}
	if err := l.enc.Encode(record); err != nil {
		return err
	}
	if l.flusher != nil {
		l.flusher.Flush()
	}
	return nil
}

func (s *Server) infer(w http.ResponseWriter, r *http.Request, profile contract.ProfileID) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body inferBody
	if !decodeBody(w, r, inferBodyLimit, &body) {
		return
	}
	prov, ok := contract.ParseProvider(body.Provider)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_provider")
		return
	}
	if body.Model == "" || !validSessionID(body.SessionID) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	req := InferRequest{
		Profile:   profile,
		Provider:  prov,
		Model:     body.Model,
		SessionID: body.SessionID,
		Input:     body.Input,
		Replay:    body.Replay,
	}

	sink := &lazySink{w: w}
	err := s.d.Inferer.Infer(r.Context(), req, sink)
	if sink.enc == nil {
		if err != nil {
			writeFailure(w, err)
		}
		return
	}
	if err != nil {
		code := errorCode(err)
		_ = sink.Send(streamError{Type: "error", Code: code, Message: safeMessage(code)})
	}
}

// errorCode returns the bounded public code for err without exposing its text.
func errorCode(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "upstream_error"
	}
	_, code := classify(err)
	return code
}

func (s *Server) verifyReplay(w http.ResponseWriter, r *http.Request, profile contract.ProfileID) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body inferBody
	if !decodeBody(w, r, inferBodyLimit, &body) {
		return
	}
	provider, ok := contract.ParseProvider(body.Provider)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_provider")
		return
	}
	if body.Model == "" || !validSessionID(body.SessionID) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := s.d.Inferer.VerifyReplay(r.Context(), InferRequest{Profile: profile, Provider: provider, Model: body.Model, SessionID: body.SessionID, Input: body.Input, Replay: body.Replay}); err != nil {
		writeFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

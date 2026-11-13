package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/structuredstanza/cliproxyhost/internal/contract"
	"github.com/structuredstanza/cliproxyhost/internal/store"
)

const maxSessionIDLen = 128

var errTrailingData = errors.New("trailing data after JSON value")

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type modelsResponse struct {
	Models []contract.Model `json:"models"`
}

type statusResponse struct {
	Connected bool    `json:"connected"`
	Email     *string `json:"email,omitempty"`
	// ExpiresAt is RFC 3339 when the record has an expiry; null otherwise.
	ExpiresAt *string `json:"expires_at"`
}

// safeMessage returns the only messages a client ever sees for a given code.
func safeMessage(code string) string {
	switch code {
	case "bad_request":
		return "request is invalid"
	case "invalid_profile":
		return "profile id must be a canonical positive integer"
	case "invalid_provider":
		return "provider must be claude, codex, or antigravity"
	case "invalid_body":
		return "request body must be a single JSON object"
	case "request_too_large":
		return "request body exceeds the limit"
	case "unauthorized":
		return "bearer authentication required"
	case "not_found":
		return "route not found"
	case "method_not_allowed":
		return "method not allowed"
	case "denied":
		return "request denied"
	case "rate_limited":
		return "upstream rate limit reached"
	case "upstream_error":
		return "upstream request failed"
	case "upstream_network_error":
		return "upstream network request failed"
	case "response_too_large":
		return "upstream response exceeds the limit"
	case "invalid_json":
		return "upstream response was not valid JSON"
	case "unsupported_provider":
		return "provider is not supported"
	case "internal_error":
		return "internal error"
	}
	return "request failed"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: safeMessage(code)}})
}

// decodeBody caps the body at limit, rejects unknown fields, and requires exactly
// one JSON value. On failure it writes the error response and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := decodeStrict(r.Body, v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_body")
		return false
	}
	return true
}

func decodeStrict(rd io.Reader, v any) error {
	dec := json.NewDecoder(rd)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errTrailingData
		}
		return err
	}
	return nil
}

func providerQuery(w http.ResponseWriter, r *http.Request) (contract.Provider, bool) {
	p, ok := contract.ParseProvider(r.URL.Query().Get("provider"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_provider")
		return "", false
	}
	return p, true
}

func validSessionID(sid string) bool {
	return sid != "" && len(sid) <= maxSessionIDLen
}

// models serves the embedded catalog. It touches no network and needs no login.
func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	prov, ok := providerQuery(w, r)
	if !ok {
		return
	}
	models, err := s.d.Catalog.Models(prov)
	if err != nil {
		writeFailure(w, err)
		return
	}
	if models == nil {
		models = []contract.Model{}
	}
	writeJSON(w, http.StatusOK, modelsResponse{Models: models})
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, profile contract.ProfileID) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if !decodeBody(w, r, controlBodyLimit, &body) {
		return
	}
	prov, ok := contract.ParseProvider(body.Provider)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_provider")
		return
	}
	sid, err := s.d.Lifecycle.StartLogin(r.Context(), profile, prov)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"session_id": sid,
		"status":     string(contract.LoginPending),
	})
}

func (s *Server) loginSession(w http.ResponseWriter, r *http.Request, profile contract.ProfileID, sid string) {
	if !validSessionID(sid) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		view, err := s.d.Lifecycle.LoginView(profile, sid)
		if err != nil {
			writeFailure(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case http.MethodDelete:
		if err := s.d.Lifecycle.CancelLogin(profile, sid); err != nil {
			writeFailure(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *Server) loginInput(w http.ResponseWriter, r *http.Request, profile contract.ProfileID, sid string) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !validSessionID(sid) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if !decodeBody(w, r, controlBodyLimit, &body) {
		return
	}
	if err := s.d.Lifecycle.SubmitInput(profile, sid, body.Value); err != nil {
		writeFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request, profile contract.ProfileID) {
	if !requireMethod(w, r, http.MethodDelete) {
		return
	}
	if err := s.d.Lifecycle.Disconnect(r.Context(), profile); err != nil {
		writeFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// status reports local presence only. It never refreshes and never calls upstream.
func (s *Server) status(w http.ResponseWriter, r *http.Request, profile contract.ProfileID) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	prov, ok := providerQuery(w, r)
	if !ok {
		return
	}
	rec, err := s.d.Store.Load(r.Context(), profile, prov)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeFailure(w, err)
		return
	}
	var resp statusResponse
	if rec != nil {
		resp.Connected = true
		if rec.Email != "" {
			email := rec.Email
			resp.Email = &email
		}
		if !rec.ExpiresAt.IsZero() {
			exp := rec.ExpiresAt.UTC().Format(time.RFC3339)
			resp.ExpiresAt = &exp
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) usage(w http.ResponseWriter, r *http.Request, profile contract.ProfileID) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	prov, ok := providerQuery(w, r)
	if !ok {
		return
	}
	report, err := s.d.Usage.Usage(r.Context(), profile, prov)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

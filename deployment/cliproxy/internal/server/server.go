// Package server exposes the host control API. Every route except /healthz requires
// the bearer capability, checked before any body is read. Request bodies are capped:
// 4 KiB for control routes and 8 MiB for inference. Error responses use fixed codes
// and messages and never echo request or upstream data.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/artex/cliproxyhost/internal/contract"
)

const (
	controlBodyLimit = 4 * 1024
	inferBodyLimit   = 8 * 1024 * 1024
	bearerPrefix     = "Bearer "
)

// Deps are the collaborators the server routes to. Each is implemented by another slice.
type Deps struct {
	Token     []byte
	Lifecycle contract.Lifecycle
	Store     contract.Store
	Catalog   contract.Catalog
	Usage     contract.Usage
	Inferer   Inferer
}

// Server routes host control requests. It keeps only a digest of the bearer token.
type Server struct {
	digest [sha256.Size]byte
	d      Deps
}

// New validates the dependencies and retains only a digest of the bearer token.
func New(d Deps) (*Server, error) {
	if len(d.Token) == 0 {
		return nil, errors.New("server: bearer token is required")
	}
	if d.Lifecycle == nil || d.Store == nil || d.Catalog == nil || d.Usage == nil || d.Inferer == nil {
		return nil, errors.New("server: all collaborators are required")
	}
	s := &Server{digest: sha256.Sum256(d.Token)}
	d.Token = nil
	s.d = d
	return s, nil
}

// HTTPServer wraps the handler with timeouts. WriteTimeout is deliberately unset so
// NDJSON inference streams are not cut off mid-turn.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "healthz" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="cliproxyhost"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.route(w, r, strings.Split(path, "/"))
}

// authorized compares SHA-256 digests in constant time, so token length is not leaked.
func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, bearerPrefix) {
		return false
	}
	presented := sha256.Sum256([]byte(h[len(bearerPrefix):]))
	return subtle.ConstantTimeCompare(presented[:], s.digest[:]) == 1
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 2 && parts[0] == "v1" && parts[1] == "models" {
		s.models(w, r)
		return
	}
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "profiles" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	profile, err := contract.ParseProfileID(parts[2])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_profile")
		return
	}
	rest := parts[3:]
	switch {
	case len(rest) == 2 && rest[0] == "login" && rest[1] == "start":
		s.startLogin(w, r, profile)
	case len(rest) == 2 && rest[0] == "login":
		s.loginSession(w, r, profile, rest[1])
	case len(rest) == 3 && rest[0] == "login" && rest[2] == "input":
		s.loginInput(w, r, profile, rest[1])
	case len(rest) == 1 && rest[0] == "grant":
		s.disconnect(w, r, profile)
	case len(rest) == 1 && rest[0] == "status":
		s.status(w, r, profile)
	case len(rest) == 1 && rest[0] == "usage":
		s.usage(w, r, profile)
	case len(rest) == 1 && rest[0] == "infer":
		s.infer(w, r, profile)
	case len(rest) == 2 && rest[0] == "replay" && rest[1] == "verify":
		s.verifyReplay(w, r, profile)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

// requireMethod writes 405 and returns false when r uses another method.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return false
	}
	return true
}

// classify maps an error to a public status and fixed code. Unknown errors are not
// exposed; their text may contain upstream or credential material.
func classify(err error) (int, string) {
	var c coded
	switch {
	case errors.As(err, &c):
		return c.ErrorStatus()
	case errors.Is(err, contract.ErrDenied):
		return http.StatusForbidden, "denied"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

// coded is implemented by slice errors that carry a fixed public status and code.
type coded interface {
	ErrorStatus() (int, string)
}

func writeFailure(w http.ResponseWriter, err error) {
	status, code := classify(err)
	writeError(w, status, code)
}

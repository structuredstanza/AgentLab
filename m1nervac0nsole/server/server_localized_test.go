package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Server responses reach clients as status codes and error strings. These tests check
// those on the paths that need no DB, engine, or asset store.

// TestServerHandlersResponses drives handlers that return before touching the DB and
// checks the real HTTP status and error body. Paths that need the DB, engine, or asset
// store are not covered here.
func TestServerHandlersResponses(t *testing.T) {
	// Server with a deletion barrier in place: beginTaskOperation / IsDeleting judges it as "being deleted".
	deletingServer := func() *Server {
		s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
		s.engine.deleting.Store("t1", true)
		return s
	}
	// Server without a barrier: proceeds to input validation.
	liveServer := func() *Server {
		return &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
	}

	cases := []struct {
		name    string
		req     func() *http.Request
		handler func(*Server) http.HandlerFunc
		server  func() *Server
		code    int
	}{
		{
			name: "controlIntent/task-deleting",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/5/control", strings.NewReader(`{"action":"pause"}`))
				r.SetPathValue("id", "t1")
				r.SetPathValue("iid", "5")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.controlIntent },
			server:  deletingServer,
			code:    http.StatusConflict,
		},
		{
			name: "rerunIntent/task-deleting",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/5/rerun", nil)
				r.SetPathValue("id", "t1")
				r.SetPathValue("iid", "5")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.rerunIntent },
			server:  deletingServer,
			code:    http.StatusConflict,
		},
		{
			name: "rerunBlocked/task-deleting",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/rerun-blocked", nil)
				r.SetPathValue("id", "t1")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.rerunBlocked },
			server:  deletingServer,
			code:    http.StatusConflict,
		},
		{
			name: "createTask/source-limit",
			req: func() *http.Request {
				// MaxTaskSourceCount=8 → 9 items exceeds the limit (returns before the loop).
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					"{\"goal\":\"\ubaa9\ud45c\",\"source_task_ids\":[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\"]}"))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
		},
		{
			name: "createTask/source-invalid",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					"{\"goal\":\"\ubaa9\ud45c\",\"source_task_ids\":[\"abc\"]}"))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
		},
		{
			name: "createTask/source-not-found",
			req: func() *http.Request {
				// 999 is not in the tasks map → not found (no DB access, map lookup).
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					"{\"goal\":\"\ubaa9\ud45c\",\"source_task_ids\":[\"999\"]}"))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
		},
		{
			name: "createTask/company-limit",
			req: func() *http.Request {
				// MaxTaskCompanyCount=32 → 33 items produce an error in NormalizeTaskCompanyIDs (pure function).
				ids := make([]string, 33)
				for i := range ids {
					ids[i] = fmt.Sprintf("%d", i+1)
				}
				body := "{\"goal\":\"\ubaa9\ud45c\",\"company_ids\":[" + strings.Join(ids, ",") + "]}"
				return httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(body))
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
		},
		{
			name: "createTask/llm-profile-invalid",
			req: func() *http.Request {
				// llm_profile_ids:[0] → validateTaskProfileIDs returns before loadProfileConfig (DB).
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					"{\"goal\":\"\ubaa9\ud45c\",\"llm_profile_ids\":[0]}"))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
		},
		{
			name: "taskCoverageGraph/asset-store-disabled",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/api/tasks/t1/coverage-graph", nil)
				r.SetPathValue("id", "t1")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.taskCoverageGraph },
			server:  liveServer, // Manager.assets==nil → Assets()==nil → 503
			code:    http.StatusServiceUnavailable,
		},
		{
			name: "taskAssetRefs/asset-id-required",
			req: func() *http.Request {
				// No asset_id query → ParseInt("")=0 → <=0 → 400 (before Assets() is called).
				r := httptest.NewRequest(http.MethodGet, "/api/tasks/t1/asset-refs", nil)
				r.SetPathValue("id", "t1")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.taskAssetRefs },
			server:  liveServer,
			code:    http.StatusBadRequest,
		},
		{
			// F34(b): If profile_id is left empty (no DB lookup) and api_key is also empty, TestConnection
			// returns writeJSON{ok:false,error} beforehand (status 200). liveServer
			// has llmCfg.APIKey as "" too, so there is no global fallback key either.
			name: "testLLM/no-api-key",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(`{}`))
			},
			handler: func(s *Server) http.HandlerFunc { return s.testLLM },
			server:  liveServer,
			code:    http.StatusOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.server()
			rec := httptest.NewRecorder()
			c.handler(s)(rec, c.req())
			if rec.Code != c.code {
				t.Fatalf("status code = %d, want = %d (body %q)", rec.Code, c.code, rec.Body.String())
			}
		})
	}
}

// TestFallbackCommandParsing checks that all command prefixes are recognized and
// stripped without changing the arguments, while non-commands remain intact.
// The parser needs no database.
func TestFallbackCommandParsing(t *testing.T) {
	cases := []struct {
		name, in, cmd, text string
	}{
		{"intent-alias-1", "\uc758\ub3c4 SQLi \uc8fc\uc785\uc810 \uba3c\uc800 \ud655\uc778", "intent", "SQLi \uc8fc\uc785\uc810 \uba3c\uc800 \ud655\uc778"},
		{"hint-alias-1", "\ud78c\ud2b8 \ub85c\uadf8\uc778 \ud3fc\ubd80\ud130 \ubcf4\ub77c", "hint", "\ub85c\uadf8\uc778 \ud3fc\ubd80\ud130 \ubcf4\ub77c"},
		{"intent-alias-2", "\u610f\u56fe \u626b\u63cf\u7aef\u53e3", "intent", "\u626b\u63cf\u7aef\u53e3"},
		{"hint-alias-2", "\u63d0\u793a \u770b\u767b\u5f55", "hint", "\u770b\u767b\u5f55"},
		{"english-intent", "intent scan ports", "intent", "scan ports"},
		{"english-hint", "hint try admin:admin", "hint", "try admin:admin"},
		{"status-unrecognized-prefix", "\uc9c0\uae08 \uc0c1\ud669 \uc54c\ub824\uc918", "", "\uc9c0\uae08 \uc0c1\ud669 \uc54c\ub824\uc918"},
		{"status-empty", "   ", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, text := fallbackCommand(c.in)
			if cmd != c.cmd || text != c.text {
				t.Fatalf("fallbackCommand(%q) = (%q, %q), want = (%q, %q)", c.in, cmd, text, c.cmd, c.text)
			}
		})
	}
}

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
					`{"goal":"목표","source_task_ids":["1","2","3","4","5","6","7","8","9"]}`))
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
					`{"goal":"목표","source_task_ids":["abc"]}`))
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
					`{"goal":"목표","source_task_ids":["999"]}`))
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
				body := `{"goal":"목표","company_ids":[` + strings.Join(ids, ",") + `]}`
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
					`{"goal":"목표","llm_profile_ids":[0]}`))
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

// TestFallbackCommandParsing verifies that the trigger keyword parsing of rule-mode chat (fallbackCommand) recognizes Korean
// While still recognizing aliases (intent/hints), accept the existing Chinese and English triggers as-is, and strip out only the keyword
// Verifies that the arguments are returned. This is pure input parsing that does not touch the Store or DB, so it runs without a DB.
// If the Korean alias is removed, the korean-* cases break; if the Chinese or English ones are removed, their cases break (non-vacuousness).
func TestFallbackCommandParsing(t *testing.T) {
	cases := []struct {
		name, in, cmd, text string
	}{
		{"korean-intent", "의도 SQLi 주입점 먼저 확인", "intent", "SQLi 주입점 먼저 확인"},
		{"korean-hint", "힌트 로그인 폼부터 보라", "hint", "로그인 폼부터 보라"},
		{"chinese-intent", "意图 扫描端口", "intent", "扫描端口"}, // Preserve for backward compatibility
		{"chinese-hint", "提示 看登录", "hint", "看登录"},       // Preserve for backward compatibility
		{"english-intent", "intent scan ports", "intent", "scan ports"},
		{"english-hint", "hint try admin:admin", "hint", "try admin:admin"},
		{"status-korean", "지금 상황 알려줘", "", "지금 상황 알려줘"},
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

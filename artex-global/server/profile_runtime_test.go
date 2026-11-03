package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/nativeproxy"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func runtimeProfile(t *testing.T, s *Server, p *db.LLMProfile) *db.LLMProfile {
	t.Helper()
	id, err := s.m.pg.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	return p
}

func TestProfileActivationAndOAuthRuntime(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	previous, err := s.m.pg.ActiveProfile()
	if err != nil {
		t.Fatal(err)
	}
	var connected atomic.Bool
	var apiCalls, nativeCalls, disconnects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/status"):
			json.NewEncoder(w).Encode(nativeproxy.ProfileStatus{Connected: connected.Load()})
		case strings.HasSuffix(r.URL.Path, "/login/fixture-login"):
			connected.Store(true)
			json.NewEncoder(w).Encode(nativeproxy.LoginSession{SessionID: "fixture-login", Status: "complete"})
		case strings.HasSuffix(r.URL.Path, "/grant") && r.Method == http.MethodDelete:
			disconnects.Add(1)
			connected.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/infer"):
			nativeCalls.Add(1)
			state := json.RawMessage(`{"id":"native-answer","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"account B"}]}]}`)
			json.NewEncoder(w).Encode(map[string]any{"type": "done", "response": state, "state": state, "receipt": "fixture-receipt", "stop": "end"})
		case r.URL.Path == "/apikey/chat/completions":
			apiCalls.Add(1)
			fmt.Fprintln(w, `{"id":"api-answer","choices":[{"message":{"role":"assistant","content":"account A"},"finish_reason":"stop"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(proxy.Close)
	s.nativeProxy, err = nativeproxy.New(proxy.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	a := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-A", Format: "openai", AuthMethod: "api_key", Model: "api-model", APIKey: "fixture-key", BaseURL: proxy.URL + "/apikey"})
	b := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-B", Format: "openai-responses", AuthMethod: "codex", Model: "native-model", RatePerMinute: 1})
	t.Cleanup(func() {
		if previous != nil {
			s.m.pg.SetActiveProfile(previous.ID)
		}
	})
	activate := func(p *db.LLMProfile) *httptest.ResponseRecorder {
		return req("POST", "/api/llm/profiles/active", fmt.Sprintf(`{"id":%d}`, p.ID))
	}
	if w := activate(a); w.Code != 200 {
		t.Fatalf("activate A: %d %s", w.Code, w.Body.String())
	}
	if w := activate(b); w.Code != 400 {
		t.Fatalf("unavailable B activation: %d %s", w.Code, w.Body.String())
	}
	if active, err := s.m.pg.ActiveProfile(); err != nil || active == nil || active.ID != a.ID {
		t.Fatalf("rejected activation changed selected account: %+v %v", active, err)
	}
	p, _, ok := s.globalProvider()
	if !ok {
		t.Fatal("rejected activation disabled the working account")
	}
	message, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("account probe")}})
	if err != nil || len(message.Content) == 0 || message.Content[0].Text != "account A" {
		t.Fatalf("account A completion: %+v %v", message, err)
	}
	if err := s.m.pg.SetActiveProfile(b.ID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "unrelated-environment-account")
	if err := s.reapplyActiveProfile(); !errors.Is(err, errLLMProfileUnavailable) {
		t.Fatalf("selected unavailable profile: %v", err)
	}
	if _, _, ok := s.globalProvider(); ok {
		t.Fatal("unavailable selected account retained another account's provider")
	}
	w := req("GET", "/api/llm", "")
	var status struct {
		Configured bool   `json:"configured"`
		Model      string `json:"model"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Configured || status.Model != b.Model {
		t.Fatalf("unavailable selected identity: %s %v", w.Body.String(), err)
	}
	poll := func() *httptest.ResponseRecorder {
		return req("POST", fmt.Sprintf("/api/llm/profiles/%d/oauth/poll", b.ID), `{"session_id":"fixture-login"}`)
	}
	if w := poll(); w.Code != 200 {
		t.Fatalf("OAuth completion: %d %s", w.Code, w.Body.String())
	}
	p, _, ok = s.globalProvider()
	if !ok {
		t.Fatal("completed login did not enable the selected runtime")
	}
	ctx := transcript.WithSessionID(context.Background(), "runtime-fixture")
	message, _, _, err = p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("account probe")}})
	if err != nil || len(message.Content) == 0 || message.Content[0].Text != "account B" {
		t.Fatalf("account B completion: %+v %v", message, err)
	}
	if w := poll(); w.Code != 200 {
		t.Fatalf("repeat completed poll: %d %s", w.Code, w.Body.String())
	}
	p, _, _ = s.globalProvider()
	limitedCtx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancel()
	_, _, _, err = p.Complete(limitedCtx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("rate-limit probe")}})
	if err == nil || nativeCalls.Load() != 1 {
		t.Fatalf("repeated OAuth poll reset the shared account limit: calls=%d err=%v", nativeCalls.Load(), err)
	}
	w = req("DELETE", fmt.Sprintf("/api/llm/profiles/%d/oauth", b.ID), "")
	if w.Code != 200 || disconnects.Load() != 1 {
		t.Fatalf("OAuth disconnect: %d %s calls=%d", w.Code, w.Body.String(), disconnects.Load())
	}
	if _, _, ok := s.globalProvider(); ok || s.engine.Ready() {
		t.Fatal("disconnected account remained ready")
	}
	if apiCalls.Load() != 1 || nativeCalls.Load() != 1 {
		t.Fatalf("unexpected account usage: API=%d native=%d", apiCalls.Load(), nativeCalls.Load())
	}
	// The legacy editor must keep an OAuth grant bound to the same profile ID.
	connected.Store(true)
	w = req("POST", "/api/llm", `{"provider":"openai-responses","model":"updated-native-model","auth_method":"codex"}`)
	if w.Code != 200 {
		t.Fatalf("legacy OAuth edit: %d %s", w.Code, w.Body.String())
	}
	if active, err := s.m.pg.ActiveProfile(); err != nil || active == nil || active.ID != b.ID || active.Model != "updated-native-model" {
		t.Fatalf("legacy editor moved the subscription binding: %+v %v", active, err)
	}
}

func TestRejectedProfileMutationsPreserveGrant(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	previous, err := s.m.pg.ActiveProfile()
	if err != nil {
		t.Fatal(err)
	}
	var connected, failDelete atomic.Bool
	var deletes atomic.Int32
	connected.Store(true)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/status"):
			json.NewEncoder(w).Encode(nativeproxy.ProfileStatus{Connected: connected.Load()})
		case strings.HasSuffix(r.URL.Path, "/grant") && r.Method == http.MethodDelete:
			deletes.Add(1)
			connected.Store(false)
			if failDelete.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintln(w, `{"code":"fixture_delete_failed"}`)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(proxy.Close)
	s.nativeProxy, err = nativeproxy.New(proxy.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	a := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-api", Format: "openai", AuthMethod: "api_key", APIKey: "fixture-key", Model: "api-model", BaseURL: "http://127.0.0.1:1"})
	b := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-native", Format: "openai-responses", AuthMethod: "codex", Model: "native-model"})
	t.Cleanup(func() {
		if previous != nil {
			s.m.pg.SetActiveProfile(previous.ID)
		}
	})
	activate := func(p *db.LLMProfile) {
		t.Helper()
		w := req("POST", "/api/llm/profiles/active", fmt.Sprintf(`{"id":%d}`, p.ID))
		if w.Code != 200 {
			t.Fatalf("activate: %d %s", w.Code, w.Body.String())
		}
	}
	activate(b)
	path := fmt.Sprintf("/api/llm/profiles/%d", b.ID)
	if w := req("DELETE", path, ""); w.Code != 409 || deletes.Load() != 0 || !connected.Load() {
		t.Fatalf("rejected active deletion changed grant: status=%d deletes=%d connected=%v", w.Code, deletes.Load(), connected.Load())
	}
	body := fmt.Sprintf(`{"id":%d,"name":%q,"format":"openai","auth_method":"api_key","model":"updated","api_key":"fixture-key"}`, b.ID, a.Name)
	if w := req("POST", "/api/llm/profiles", body); w.Code != 500 || deletes.Load() != 0 || !connected.Load() {
		t.Fatalf("invalid auth edit changed grant: status=%d deletes=%d connected=%v", w.Code, deletes.Load(), connected.Load())
	}
	if _, err := s.m.pg.Exec(`ALTER TABLE llm_profiles ADD CONSTRAINT profile_cleanup_price_fixture CHECK (price_input_per_m <> 12345) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`ALTER TABLE llm_profiles DROP CONSTRAINT profile_cleanup_price_fixture`) })
	body = fmt.Sprintf(`{"id":%d,"name":%q,"format":"openai","auth_method":"api_key","model":"updated","api_key":"fixture-key","price_input_per_m":12345}`, b.ID, b.Name)
	if w := req("POST", "/api/llm/profiles", body); w.Code != 500 || deletes.Load() != 0 || !connected.Load() {
		t.Fatalf("late SQL failure changed grant: status=%d deletes=%d connected=%v", w.Code, deletes.Load(), connected.Load())
	}
	if saved, err := s.m.pg.ProfileByID(b.ID); err != nil || saved == nil || saved.AuthMethod != "codex" || saved.Model != "native-model" {
		t.Fatalf("failed save partially changed the profile: %+v %v", saved, err)
	}
	activate(a)
	failDelete.Store(true)
	if w := req("DELETE", path, ""); w.Code != 503 {
		t.Fatalf("failed grant deletion: %d %s", w.Code, w.Body.String())
	}
	if saved, err := s.m.pg.ProfileByID(b.ID); err != nil || saved == nil {
		t.Fatalf("grant deletion failure removed the profile: %+v %v", saved, err)
	}
	failDelete.Store(false)
	if w := req("DELETE", path, ""); w.Code != 200 {
		t.Fatalf("retry grant deletion: %d %s", w.Code, w.Body.String())
	}
	if saved, err := s.m.pg.ProfileByID(b.ID); err != nil || saved != nil || connected.Load() || deletes.Load() != 2 {
		t.Fatalf("successful deletion: row=%+v err=%v connected=%v deletes=%d", saved, err, connected.Load(), deletes.Load())
	}

	// A deferred failure proves the unavoidable post-cleanup commit boundary.
	c := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-commit", Format: "openai-responses", AuthMethod: "codex", Model: "native-model"})
	if _, err := s.m.pg.Exec(`CREATE FUNCTION profile_cleanup_commit_failure_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DROP FUNCTION profile_cleanup_commit_failure_fixture() CASCADE`) })
	if _, err := s.m.pg.Exec(fmt.Sprintf(`CREATE CONSTRAINT TRIGGER profile_cleanup_commit_failure_fixture AFTER DELETE ON llm_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.id = %d) EXECUTE FUNCTION profile_cleanup_commit_failure_fixture()`, c.ID)); err != nil {
		t.Fatal(err)
	}
	connected.Store(true)
	if w := req("DELETE", fmt.Sprintf("/api/llm/profiles/%d", c.ID), ""); w.Code != 500 {
		t.Fatalf("post-cleanup commit failure: %d %s", w.Code, w.Body.String())
	}
	if saved, err := s.m.pg.ProfileByID(c.ID); err != nil || saved == nil || connected.Load() || deletes.Load() != 3 {
		t.Fatalf("post-cleanup state was not retained honestly: row=%+v err=%v connected=%v deletes=%d", saved, err, connected.Load(), deletes.Load())
	}
}

func TestProfileActivationAndDeletionSerialize(t *testing.T) {
	for _, first := range []string{"activation", "deletion"} {
		t.Run(first, func(t *testing.T) {
			s, _, req := trafficEvidenceServer(t)
			previous, err := s.m.pg.ActiveProfile()
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var block, connected atomic.Bool
			var deletes atomic.Int32
			connected.Store(true)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				isDelete := r.Method == http.MethodDelete
				if (first == "deletion") == isDelete && block.CompareAndSwap(true, false) {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				if isDelete {
					deletes.Add(1)
					connected.Store(false)
					w.WriteHeader(http.StatusNoContent)
				} else {
					json.NewEncoder(w).Encode(nativeproxy.ProfileStatus{Connected: connected.Load()})
				}
			}))
			t.Cleanup(proxy.Close)
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			s.nativeProxy, err = nativeproxy.New(proxy.URL, "fixture-token")
			if err != nil {
				t.Fatal(err)
			}
			a := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-A", Format: "openai", AuthMethod: "api_key", APIKey: "fixture", Model: "a"})
			b := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-B", Format: "openai-responses", AuthMethod: "codex", Model: "b"})
			t.Cleanup(func() {
				if previous != nil {
					s.m.pg.SetActiveProfile(previous.ID)
				}
			})
			if w := req("POST", "/api/llm/profiles/active", fmt.Sprintf(`{"id":%d}`, a.ID)); w.Code != 200 {
				t.Fatalf("activate A: %d %s", w.Code, w.Body.String())
			}
			activation, deletion := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
			activate := func() { activation <- req("POST", "/api/llm/profiles/active", fmt.Sprintf(`{"id":%d}`, b.ID)) }
			remove := func() { deletion <- req("DELETE", fmt.Sprintf("/api/llm/profiles/%d", b.ID), "") }
			block.Store(true)
			if first == "activation" {
				go activate()
				<-entered
				go remove()
			} else {
				go remove()
				<-entered
				go activate()
			}
			close(release)
			aw, dw := <-activation, <-deletion
			active, err := s.m.pg.ActiveProfile()
			if err != nil || active == nil {
				t.Fatalf("selected profile lost: %+v %v", active, err)
			}
			if first == "activation" {
				if aw.Code != 200 || dw.Code != 409 || active.ID != b.ID || deletes.Load() != 0 || !connected.Load() {
					t.Fatalf("activation-first: activate=%d delete=%d selected=%d grant=%v deletes=%d", aw.Code, dw.Code, active.ID, connected.Load(), deletes.Load())
				}
			} else if aw.Code != 404 || dw.Code != 200 || active.ID != a.ID || deletes.Load() != 1 || connected.Load() {
				t.Fatalf("deletion-first: activate=%d delete=%d selected=%d grant=%v deletes=%d", aw.Code, dw.Code, active.ID, connected.Load(), deletes.Load())
			}
		})
	}
}

func TestProfileChatInvalidationRejectsInFlightOldBuild(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pool, bound := s.m.LLMPoolEnabled(), s.m.LLMPoolBindFallback()
	t.Cleanup(func() { s.m.SetLLMPoolEnabled(pool); s.m.SetLLMPoolBindFallback(bound) })
	if err := s.m.SetLLMPoolEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := s.m.SetLLMPoolBindFallback(true); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var block atomic.Bool
	block.Store(true)
	var observed atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("completion request: %v", err)
			w.WriteHeader(400)
			return
		}
		observed.Store(request.Model)
		fmt.Fprintln(w, `{"id":"answer","choices":[{"message":{"role":"assistant","content":"current model answer"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(upstream.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block.CompareAndSwap(true, false) {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"connected":false}`)
	}))
	t.Cleanup(proxy.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	var err error
	s.nativeProxy, err = nativeproxy.New(proxy.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	head := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-head", Format: "openai", AuthMethod: "api_key", APIKey: "fixture", Model: "old-model", BaseURL: upstream.URL})
	runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-fallback", Format: "openai-responses", AuthMethod: "codex", Model: "fallback-model"})
	if _, _, ok := s.providerForProfile(head.ID); !ok {
		t.Fatal("head provider unavailable")
	}
	built := make(chan *agent.ChatAgent, 1)
	go func() { built <- s.chatAgentForProfile(head.ID) }()
	<-entered
	head.Model = "new-model"
	if _, err := s.m.pg.SaveProfile(head); err != nil {
		t.Fatal(err)
	}
	s.invalidateProfileAgents()
	close(release)
	ca := <-built
	if ca == nil {
		t.Fatal("current profile chat unavailable")
	}
	if _, err := ca.Chat(t.Context(), "cache-fixture", "profile-cache-fixture", "Reply briefly", 1, 0, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := observed.Load(); got != "new-model" {
		t.Fatalf("in-flight old chat build survived invalidation: model=%v", got)
	}
}

func TestProfileRuntimeBuildFailureClearsOldAccount(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	previous, err := s.m.pg.ActiveProfile()
	if err != nil {
		t.Fatal(err)
	}
	var localCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/status") {
			fmt.Fprintln(w, `{"connected":true}`)
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected provider operation: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		localCalls.Add(1)
		fmt.Fprintln(w, `{"id":"local-answer","choices":[{"message":{"role":"assistant","content":"local answer"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(upstream.Close)
	s.nativeProxy = nil
	local := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-local", Format: "ollama", AuthMethod: "api_key", Model: "local-model", BaseURL: upstream.URL})
	broken := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-broken", Format: "openai-responses", AuthMethod: "codex", Model: "native-model", BaseURL: upstream.URL})
	t.Cleanup(func() {
		if previous != nil {
			s.m.pg.SetActiveProfile(previous.ID)
		}
	})
	w := req("POST", "/api/llm/profiles/active", fmt.Sprintf(`{"id":%d}`, local.ID))
	if w.Code != 200 {
		t.Fatalf("Ollama without native proxy: %d %s", w.Code, w.Body.String())
	}
	p, _, ok := s.globalProvider()
	if !ok {
		t.Fatal("Ollama required a subscription proxy")
	}
	message, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("local probe")}})
	if err != nil || len(message.Content) == 0 || message.Content[0].Text != "local answer" {
		t.Fatalf("Ollama completion: %+v %v", message, err)
	}
	s.nativeProxy, err = nativeproxy.New(upstream.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	w = req("POST", "/api/llm/profiles/active", fmt.Sprintf(`{"id":%d}`, broken.ID))
	if w.Code != 400 {
		t.Fatalf("invalid connected profile activation: %d %s", w.Code, w.Body.String())
	}
	if active, err := s.m.pg.ActiveProfile(); err != nil || active == nil || active.ID != local.ID {
		t.Fatalf("failed provider build changed selection: %+v %v", active, err)
	}
	if err := s.m.pg.SetActiveProfile(broken.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.reapplyActiveProfile(); !errors.Is(err, errLLMProfileUnavailable) {
		t.Fatalf("persisted broken provider build: %v", err)
	}
	if _, _, ok := s.globalProvider(); ok || s.engine.Ready() || localCalls.Load() != 1 {
		t.Fatal("broken selected profile retained or called the old account")
	}
}

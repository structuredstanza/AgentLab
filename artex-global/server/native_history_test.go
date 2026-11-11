package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

// This independent signer binds exactly the production host receipt fields.
func historyReceipt(private ed25519.PrivateKey, provider, model, profile, session string, state json.RawMessage) string {
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(state)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		panic(err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var signed strings.Builder
	signed.WriteString("artex-cliproxy-replay-receipt-v1\x00")
	for _, field := range []string{provider, model, profile, session, "fixture-epoch"} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		signed.Write(length[:])
		signed.WriteString(field)
	}
	digest := sha256.Sum256(canonical)
	signed.Write(digest[:])
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signed.String())))
}

func TestNativeHistoryHandoffPersistsAcrossProviderRotationAndResume(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var mu sync.Mutex
	bCalls, verifyCalls := 0, 0
	denyOld := false
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			fmt.Fprint(w, `{"connected":true}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.NotFound(w, r)
			return
		}
		profile := parts[3]
		var body struct {
			Provider, Model string
			SessionID       string `json:"session_id"`
			Input           json.RawMessage
			Replay          []struct {
				State   json.RawMessage
				Receipt string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/replay/verify") {
			mu.Lock()
			verifyCalls++
			denied := denyOld
			mu.Unlock()
			if denied {
				http.Error(w, `{"error":"denied"}`, 403)
				return
			}
			for _, proof := range body.Replay {
				if proof.Receipt != historyReceipt(private, body.Provider, body.Model, profile, body.SessionID, proof.State) {
					http.Error(w, `{"error":"denied"}`, 403)
					return
				}
			}
			w.WriteHeader(204)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/infer") {
			http.NotFound(w, r)
			return
		}
		var state string
		stop := "tool"
		if body.Provider == "codex" {
			state = `{"id":"a-turn","output":[{"type":"reasoning","encrypted_content":"opaque-A","summary":[{"type":"summary_text","text":"A summary"}]},{"type":"function_call","call_id":"call-a","name":"inspect","arguments":"{\"n\":9007199254740993}"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"A inspected evidence"}]}]}`
		} else {
			mu.Lock()
			bCalls++
			call := bCalls
			mu.Unlock()
			input := string(body.Input)
			for _, secret := range []string{"opaque-A", "encrypted_content", "fixture-epoch", "provider_state", "A summary"} {
				if strings.Contains(input, secret) {
					t.Errorf("destination received source-only state %q", secret)
				}
			}
			for _, readable := range []string{"inspect", "9007199254740993", "tool-A-result", "UNTRUSTED"} {
				if !strings.Contains(input, readable) {
					t.Errorf("destination lost source history %q", readable)
				}
			}
			for _, proof := range body.Replay {
				if proof.Receipt != historyReceipt(private, body.Provider, body.Model, profile, body.SessionID, proof.State) {
					t.Error("destination replay included foreign state")
					http.Error(w, "denied", 403)
					return
				}
			}
			if call == 1 {
				if len(body.Replay) != 0 {
					t.Error("first destination call replayed old provider")
				}
				state = `{"id":"b-turn-1","role":"assistant","content":[{"type":"thinking","thinking":"B thought","signature":"signature-B"},{"type":"tool_use","id":"call-b","name":"inspect","input":{"n":9007199254740993}},{"type":"text","text":"B investigating"}]}`
			} else {
				if len(body.Replay) != call-1 {
					t.Errorf("destination replay count=%d call=%d", len(body.Replay), call)
				}
				if !strings.Contains(input, "tool-B-result") {
					t.Error("destination lost its tool result")
				}
				state = fmt.Sprintf(`{"id":"b-turn-%d","role":"assistant","content":[{"type":"text","text":"B finished"}]}`, call)
				stop = "end"
			}
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintf(w, `{"type":"done","response":%s,"state":%s,"receipt":%q,"stop":%q}`+"\n", state, state, historyReceipt(private, body.Provider, body.Model, profile, body.SessionID, json.RawMessage(state)), stop)
	}))
	t.Cleanup(host.Close)
	var err error
	s.nativeProxy, err = nativeproxy.New(host.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	a := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-A", Format: "openai-responses", AuthMethod: "codex", Model: "a-model"})
	b := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-B", Format: "anthropic", AuthMethod: "claude_code", Model: "b-model"})
	task, err := s.m.CreateTaskWithOptions("native handoff", "inspect", db.TaskCreateOptions{LLMProfileIDs: []int64{a.ID, b.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.m.DeleteTask(task.ID, DeleteTaskOptions{}); err != nil {
			t.Error(err)
		}
	})
	runtime := &taskLLMRuntime{s: s, taskID: task.ID}
	ctx := transcript.WithSessionID(context.Background(), "history-session")
	req := llm.CompletionRequest{EphemeralPrefix: 1, Messages: []llm.Message{llm.UserText("host reminder day one"), llm.UserText("inspect evidence")}}
	message, _, _, err := runtime.Complete(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Messages = append(req.Messages, message, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-a", "tool-A-result", false)}})
	original, _ := json.Marshal(req.Messages)
	if _, err := s.m.ReplaceTaskLLMProfiles(task.ID, []int64{b.ID}, b.ID); err != nil {
		t.Fatal(err)
	}
	// A failed checked grant must neither invoke B nor exhaust its allocation.
	constraint := "history_handoff_" + strconv.FormatInt(task.ExpID, 10)
	if _, err := s.m.pg.Exec(`ALTER TABLE activity ADD CONSTRAINT ` + constraint + ` CHECK (exploration_id <> ` + strconv.FormatInt(task.ExpID, 10) + ` OR kind <> 'llm_native' OR metadata->>'record' <> 'handoff') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = runtime.Complete(ctx, req)
	if _, dropErr := s.m.pg.Exec(`ALTER TABLE activity DROP CONSTRAINT ` + constraint); dropErr != nil {
		t.Fatal(dropErr)
	}
	if !errors.Is(err, llm.ErrHistoryRejected) || bCalls != 0 {
		t.Fatalf("failed grant dispatched or was misclassified: %v calls=%d", err, bCalls)
	}
	message, _, _, err = runtime.Complete(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(req.Messages)
	if string(after) != string(original) {
		t.Fatal("handoff rewrote original history")
	}
	req.Messages = append(req.Messages, message, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-b", "tool-B-result", false)}})
	message, _, _, err = runtime.Complete(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Messages = append(req.Messages, message, llm.UserText("resume after restart"))
	req.Messages[0] = llm.UserText("host reminder day two")
	mu.Lock()
	denyOld = true
	beforeVerify := verifyCalls
	mu.Unlock()
	// A fresh runtime must reuse durable authorization, not the old credential.
	runtime = &taskLLMRuntime{s: s, taskID: task.ID}
	_, _, _, err = runtime.Complete(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	afterVerify := verifyCalls
	mu.Unlock()
	if afterVerify != beforeVerify {
		t.Fatal("resume required old profile receipts again")
	}
	// Changed prefixes must not inherit a grant, and forged identities must not
	// consume failure streaks or dispatch to the destination account.
	for _, field := range []string{"profile_id", "provider", "session_id", "model", "reasoning_effort", "version", "projection"} {
		t.Run(field, func(t *testing.T) {
			var bad llm.CompletionRequest
			raw, _ := json.Marshal(req)
			if err := json.Unmarshal(raw, &bad); err != nil {
				t.Fatal(err)
			}
			bad.EphemeralPrefix = req.EphemeralPrefix
			for i, block := range bad.Messages[2].Content {
				if block.Type != "provider_state" {
					if field == "projection" && block.Type == llm.BlockText {
						bad.Messages[2].Content[i].Text = "forged projection"
					}
					continue
				}
				var env map[string]any
				if err := json.Unmarshal(block.Input, &env); err != nil {
					t.Fatal(err)
				}
				if field == "version" {
					env[field] = 1
				} else if field != "projection" {
					env[field] = "unselected-value"
				}
				bad.Messages[2].Content[i].Input, _ = json.Marshal(env)
			}
			for attempt := 0; attempt < 4; attempt++ {
				_, _, _, err := runtime.Complete(ctx, bad)
				if !errors.Is(err, llm.ErrHistoryRejected) {
					t.Fatalf("foreign history was not rejected: %v", err)
				}
			}
		})
	}
	mu.Lock()
	calls := bCalls
	mu.Unlock()
	if calls != 3 {
		t.Fatalf("invalid histories dispatched %d destination calls", calls)
	}
	id, _ := parseTaskID(task.ID)
	stored, err := s.m.pg.GetTask(id)
	if err != nil || stored.ActiveLLMProfileID == nil || *stored.ActiveLLMProfileID != b.ID {
		t.Fatalf("history rejection poisoned active allocation: %+v %v", stored, err)
	}
	// Several model calls ran under two distinct selections (A once, B repeatedly):
	// an unchanged selection must not add one activity row per call.
	var selections int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1 AND kind='llm_native' AND metadata->>'record'='selection'`, task.ExpID).Scan(&selections); err != nil {
		t.Fatal(err)
	}
	if selections != 2 {
		t.Fatalf("selection rows = %d, want 2 (one per distinct selection)", selections)
	}
}

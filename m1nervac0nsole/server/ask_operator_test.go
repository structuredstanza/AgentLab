package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
)

func TestStageAskOperatorImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "shot.png")
	if err := os.WriteFile(src, []byte("fakepng"), 0o644); err != nil {
		t.Fatal(err)
	}
	att, err := stageAskOperatorImage(dir, "7", "")
	if err != nil || att != nil {
		t.Fatalf("empty src: att=%v err=%v", att, err)
	}
	att, err = stageAskOperatorImage(dir, "7", src)
	if err != nil || len(att) != 1 {
		t.Fatalf("valid src: att=%v err=%v", att, err)
	}
	if !strings.HasPrefix(att[0].Path, "uploads/ask-operator-") || !strings.HasSuffix(att[0].Path, ".png") {
		t.Fatalf("unexpected attachment path %q", att[0].Path)
	}
	if _, err := os.Stat(filepath.Join(dir, "tasks", "7", "uploads", att[0].Name)); err != nil {
		t.Fatalf("copy missing: %v", err)
	}
	bad := filepath.Join(dir, "payload.exe")
	if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAskOperatorImage(dir, "7", bad); err == nil || !strings.Contains(err.Error(), "png/jpg") {
		t.Fatalf("expected extension rejection, got %v", err)
	}
	if _, err := stageAskOperatorImage(dir, "7", filepath.Join(dir, "nope.png")); err == nil {
		t.Fatal("expected missing-file rejection")
	}
}

func TestAskOperatorActivityShape(t *testing.T) {
	att := []chatAttachment{{Name: "ask-operator-1.png", Path: "uploads/ask-operator-1.png", Size: 7}}
	a := userActivityWithAttachments("worker", "OPERATOR INPUT REQUESTED: solve the captcha", att)
	if a.Kind != "user" || a.Worker != "worker" {
		t.Fatalf("unexpected activity kind/worker: %+v", a)
	}
	var parsed struct {
		Text        string           `json:"text"`
		Attachments []chatAttachment `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(a.Detail), &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(parsed.Text, "OPERATOR INPUT REQUESTED") || len(parsed.Attachments) != 1 || parsed.Attachments[0].Path != att[0].Path {
		t.Fatalf("unexpected detail payload: %+v", parsed)
	}
}

// A screenshot must reach the operator without entering the conversation when
// provider credentials are configured: an image cannot be redacted the way the
// question text is, but the human still needs to see the page.
func TestHandoffTextWithholdsTheImageButNamesIt(t *testing.T) {
	att := []chatAttachment{{Name: "ask-operator-1.png", Path: "uploads/ask-operator-1.png", Size: 7}}

	text, kept := handoffText("solve the captcha", att, true)
	if len(kept) != 0 {
		t.Fatalf("the screenshot was attached despite provider credentials: %+v", kept)
	}
	if !strings.Contains(text, "uploads/ask-operator-1.png") {
		t.Fatalf("the withheld screenshot is not named by path: %q", text)
	}
	if !strings.Contains(text, "the ask stays open") {
		t.Fatalf("the hand-off lost its open-ask instruction: %q", text)
	}

	text, kept = handoffText("solve the captcha", att, false)
	if len(kept) != 1 {
		t.Fatalf("the screenshot was dropped without provider credentials: %+v", kept)
	}
	if strings.Contains(text, "uploads/") {
		t.Fatalf("an attached screenshot is also named by path: %q", text)
	}
}

// askTestTask creates a task with running intents; the ask protocol only needs
// the task and the run attribution, not a live worker.
func askTestTask(t *testing.T, m *Manager, name string, intents int) (*Task, []int64) {
	t.Helper()
	task, err := m.CreateTask(name, "captcha on the login page", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	ids := make([]int64, 0, intents)
	for i := range intents {
		id, err := task.Store.AddIntent(map[string]any{"summary": fmt.Sprintf("intent %d", i+1)}, 1, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := transitionIntentState(task.Store, id, "open", "running"); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return task, ids
}

func waitAsk(t *testing.T, s *Server, taskID string) *pendingAsk {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ask := s.asks.pending(taskID); ask != nil {
			return ask
		}
		if time.Now().After(deadline) {
			t.Fatal("ask was not registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitAskWaiters(t *testing.T, s *Server, taskID string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.asks.mu.Lock()
		ask := s.asks.byTask[taskID]
		got := 0
		if ask != nil {
			got = ask.waiters
		}
		s.asks.mu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ask waiters = %d, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type askCallResult struct {
	text string
	err  error
}

func askCall(s *Server, taskID int64, intentID int64, question string, timeout int) chan askCallResult {
	ch := make(chan askCallResult, 1)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID, IntentID: intentID})
	input, _ := json.Marshal(map[string]any{"question": question, "timeout_seconds": timeout})
	go func() {
		res, err := s.toolAskOperator().Call(ctx, input, nil)
		ch <- askCallResult{res.Flatten(), err}
	}()
	return ch
}

// A second ask while one is open for the task must join it: same id, one
// notification, and both callers receive the one answer.
func TestAskOperatorJoinsPendingAsk(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task, ids := askTestTask(t, m, "ask join", 2)
	tid := mustTaskID(t, task.ID)

	first := askCall(s, tid, ids[0], "solve the captcha", 10)
	ask := waitAsk(t, s, task.ID)
	second := askCall(s, tid, ids[1], "which button do I press", 10)
	waitAskWaiters(t, s, task.ID, 2)
	if got := s.asks.pending(task.ID); got != ask {
		t.Fatalf("second call replaced the pending ask: %v", got)
	}
	if askID, ok := s.asks.answer(task.ID, ids[0], "abc123"); !ok || askID != ask.id {
		t.Fatalf("answer resolved ask %q, want %q", askID, ask.id)
	}
	for i, ch := range []chan askCallResult{first, second} {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("call %d: %v", i, r.err)
			}
			var out struct {
				Answered bool   `json:"answered"`
				AskID    string `json:"ask_id"`
				Answer   string `json:"answer"`
			}
			if err := json.Unmarshal([]byte(r.text), &out); err != nil {
				t.Fatalf("call %d result is not JSON (%v): %s", i, err, r.text)
			}
			if !out.Answered || out.AskID != ask.id || out.Answer != "abc123" {
				t.Fatalf("call %d result = %+v", i, out)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("call %d did not return", i)
		}
	}
	feed, _, err := task.Store.ActivityList(nil, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	notified := 0
	for _, a := range feed {
		if strings.Contains(a.Summary, "OPERATOR INPUT REQUESTED") {
			notified++
		}
	}
	if notified != 1 {
		t.Fatalf("operator notified %d times, want 1", notified)
	}
}

// A timed-out wait leaves the ask open and returns its id. An answer that
// arrives afterwards is kept, and a retry of the same question collects it
// without waiting again.
func TestAskOperatorTimeoutLeavesAskOpenAndCollectsLateAnswer(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task, ids := askTestTask(t, m, "ask timeout", 1)
	tid := mustTaskID(t, task.ID)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: tid, IntentID: ids[0]})

	start := time.Now()
	res, err := s.toolAskOperator().Call(ctx, json.RawMessage(`{"question":"what is the OTP","timeout_seconds":1}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("wait = %v, want about 1s", elapsed)
	}
	var pending struct {
		Pending bool   `json:"pending"`
		AskID   string `json:"ask_id"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &pending); err != nil {
		t.Fatalf("timeout result is not JSON (%v): %s", err, res.Flatten())
	}
	if !pending.Pending || pending.AskID == "" {
		t.Fatalf("timeout result = %+v", pending)
	}
	if s.asks.pending(task.ID) == nil {
		t.Fatal("the ask was dropped on timeout")
	}

	// The human answers after the agent stopped waiting: the answer is kept.
	if askID, ok := s.asks.answer(task.ID, ids[0], "654321"); !ok || askID != pending.AskID {
		t.Fatalf("late answer resolved ask %q, want %q", askID, pending.AskID)
	}

	start = time.Now()
	res, err = s.toolAskOperator().Call(ctx, json.RawMessage(`{"question":"what is the OTP","timeout_seconds":30}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the retry waited instead of collecting the late answer")
	}
	var answer struct {
		Answered bool   `json:"answered"`
		AskID    string `json:"ask_id"`
		Answer   string `json:"answer"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &answer); err != nil {
		t.Fatalf("retry result is not JSON (%v): %s", err, res.Flatten())
	}
	if !answer.Answered || answer.AskID != pending.AskID || answer.Answer != "654321" {
		t.Fatalf("retry result = %+v", answer)
	}
	if _, _, ok := s.asks.takeLate(task.ID, ids[0], "what is the OTP"); ok {
		t.Fatal("the late answer was not consumed by the retry")
	}
}

// A parked answer is only usable for 30 minutes; older replies must not answer
// a question the human has long moved on from.
func TestAskLateAnswerExpires(t *testing.T) {
	var a askState
	_, _ = a.join("7", 1, "what is the OTP")
	if _, ok := a.answer("7", 1, "654321"); !ok {
		t.Fatal("answer did not resolve the ask")
	}
	key := lateAnswerKey("7", 1, "what is the OTP")
	a.mu.Lock()
	entry := a.late[key]
	entry.at = time.Now().Add(-askLateAnswerTTL - time.Minute)
	a.late[key] = entry
	a.mu.Unlock()
	if _, _, ok := a.takeLate("7", 1, "what is the OTP"); ok {
		t.Fatal("an expired late answer was collected")
	}
}

// A reply to a still-running intent answers its open ask instead of being
// rejected as "only a paused Worker can be messaged".
func TestSendWorkerMessageAnswersPendingAsk(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task, ids := askTestTask(t, m, "ask reply", 1)
	if err := m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	ask, _ := s.asks.join(task.ID, ids[0], "what is the OTP")
	wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	answerCh := make(chan string, 1)
	go func() {
		answer, _ := s.asks.wait(wctx, ask)
		answerCh <- answer
	}()
	waitAskWaiters(t, s, task.ID, 1)

	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	iid := strconv.FormatInt(ids[0], 10)
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+task.ID+"/intents/"+iid+"/messages",
		strings.NewReader(`{"message":"654321","request_id":"ask-reply"}`))
	req.SetPathValue("id", task.ID)
	req.SetPathValue("iid", iid)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.sendWorkerMessage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["answered"] != true || out["ask_id"] != ask.id {
		t.Fatalf("response = %v", out)
	}
	select {
	case got := <-answerCh:
		if got != "654321" {
			t.Fatalf("waiter got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter was not woken")
	}
}

// A reply addressed to a different intent must not be consumed as the open
// ask's answer: the operator meant it for that worker, and the asking worker
// would otherwise proceed on a fabricated answer.
func TestSendWorkerMessageDoesNotAnswerAnotherIntentsAsk(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := newFixtureServer(t, m)
	task, ids := askTestTask(t, m, "ask other intent", 2)
	if err := m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	ask, _ := s.asks.join(task.ID, ids[0], "what is the OTP")

	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	iid := strconv.FormatInt(ids[1], 10)
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+task.ID+"/intents/"+iid+"/messages",
		strings.NewReader(`{"message":"steer the other worker","request_id":"ask-other"}`))
	req.SetPathValue("id", task.ID)
	req.SetPathValue("iid", iid)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.sendWorkerMessage(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if s.asks.pending(task.ID) != ask {
		t.Fatal("the open ask was resolved by a message addressed to another intent")
	}
	if _, ok := s.asks.answer(task.ID, ids[0], "654321"); !ok {
		t.Fatal("the asking intent could no longer answer its own ask")
	}
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/artex-global/db"
	"github.com/structuredstanza/AgentLab/artex-global/nativeproxy"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

func TestTaskLLMPreparesLiveModeAndKeepsInflightSelection(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"connected":true}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/infer") {
			w.Header().Set("Content-Type", "application/x-ndjson")
			state := `{"id":"mode-native","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"native account"}]}]}`
			fmt.Fprintf(w, `{"type":"done","response":%s,"state":%s,"receipt":"mode-receipt","stop":"end"}`+"\n", state, state)
			return
		}
		if r.URL.Path != "/api/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Stream bool `json:"stream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, `data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"API account"},"finish_reason":null}]}`+"\n\n")
			fmt.Fprint(w, `data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\ndata: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"choices":[{"message":{"role":"assistant","content":"API account"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(host.Close)
	var err error
	s.nativeProxy, err = nativeproxy.New(host.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	a := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-API", Format: "openai", AuthMethod: "api_key", Model: "api-model", APIKey: "fixture-key", BaseURL: host.URL + "/api", Streaming: true})
	b := runtimeProfile(t, s, &db.LLMProfile{Name: t.Name() + "-native", Format: "openai-responses", AuthMethod: "codex", Model: "native-model"})
	task, err := s.m.CreateTaskWithOptions("mode boundary", "inspect evidence", db.TaskCreateOptions{LLMProfileIDs: []int64{a.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.m.DeleteTask(task.ID, DeleteTaskOptions{}); err != nil {
			t.Error(err)
		}
	})
	taskID, err := parseTaskID(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &taskLLMRuntime{s: s, taskID: task.ID}
	ctx := transcript.WithSessionID(context.Background(), "task-mode-session")
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("identify the selected account")}}
	prepared, nonStreaming, err := runtime.PrepareModelCall(ctx, req, false)
	if err != nil || nonStreaming {
		t.Fatalf("API-only route should stream: mode=%v err=%v", nonStreaming, err)
	}
	if err := s.m.pg.ReplaceTaskLLMProfiles(taskID, []int64{b.ID}, b.ID); err != nil {
		t.Fatal(err)
	}
	events, err := collectTaskLLMStream(runtime.Stream(prepared, req))
	var visible strings.Builder
	for _, event := range events {
		if event.Type == llm.SETextDelta {
			visible.WriteString(event.Text)
		}
	}
	if err != nil || visible.String() != "API account" {
		t.Fatalf("live edit changed the already-prepared call: %q %v", visible.String(), err)
	}
	prepared, nonStreaming, err = runtime.PrepareModelCall(ctx, req, false)
	if err != nil || !nonStreaming {
		t.Fatalf("next boundary did not select native Complete: %v %v", nonStreaming, err)
	}
	message, _, _, err := runtime.Complete(prepared, req)
	if err != nil || message.Text() != "native account" {
		t.Fatalf("native boundary: %+v %v", message, err)
	}
	if err := s.m.pg.ReplaceTaskLLMProfiles(taskID, []int64{a.ID, b.ID}, a.ID); err != nil {
		t.Fatal(err)
	}
	prepared, nonStreaming, err = runtime.PrepareModelCall(ctx, req, false)
	if err != nil || !nonStreaming {
		t.Fatalf("API head hid a native fallback: %v %v", nonStreaming, err)
	}
	message, _, _, err = runtime.Complete(prepared, req)
	if err != nil || message.Text() != "API account" {
		t.Fatalf("mixed chain did not retain the API head: %+v %v", message, err)
	}
}

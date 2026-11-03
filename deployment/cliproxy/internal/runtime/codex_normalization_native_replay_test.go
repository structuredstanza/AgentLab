package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/artex/cliproxyhost/internal/contract"
	"github.com/artex/cliproxyhost/internal/privacy"
)

const codexReplayChildEnv = "CLIPROXY_CODEX_NATIVE_REPLAY_CHILD"

func TestCodexNormalizationNativeReplayRoundTrip(t *testing.T) {
	if os.Getenv(codexReplayChildEnv) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestCodexNormalizationNativeReplayRoundTrip$")
		cmd.Env = append(os.Environ(), codexReplayChildEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated native replay fixture: %v\n%s", err, out)
		}
		return
	}

	const (
		capability = "synthetic-codex-fixture-capability"
		profile    = "7"
		model      = "gpt-6.1-sol"
		session    = "codex-native-replay-session"
	)
	stateToken := fixtureCodexEncryptedContent(11)
	firstSSE := []byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"id\":\"rs-native-fixture\",\"summary\":[],\"encrypted_content\":\"" + stateToken + "\",\"native_reasoning_extra\":\"kept\"}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-native-fixture\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-6.1-sol\",\"output\":[{\"type\":\"reasoning\",\"id\":\"rs-native-fixture\",\"summary\":[],\"encrypted_content\":\"" + stateToken + "\",\"native_reasoning_extra\":\"kept\"},{\"type\":\"message\",\"id\":\"msg-native-fixture\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"first native answer\",\"annotations\":[]}]}],\"usage\":{\"input_tokens\":4,\"output_tokens\":3},\"native_response_extra\":{\"fixture\":true}}}\n\n")
	secondSSE := []byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-native-fixture-2\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-6.1-sol\",\"output\":[{\"type\":\"message\",\"id\":\"msg-native-fixture-2\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"second native answer\",\"annotations\":[]}]}],\"usage\":{\"input_tokens\":6,\"output_tokens\":2},\"native_response_extra\":{\"fixture\":true}}}\n\n")
	terminal := &codexReplayTerminal{responses: [][]byte{firstSSE, secondSSE}}
	root := t.TempDir()
	rt, err := New(root, []byte(capability))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.captures.file.Close() })
	lastRefresh := time.Now().UTC().Format(time.RFC3339)
	grant := &contract.Record{
		CoreAuthID: "synthetic-codex-grant",
		Email:      "codex@example.invalid",
		ExpiresAt:  time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
		Raw:        []byte(`{"type":"codex","access_token":"synthetic-access","refresh_token":"synthetic-refresh","id_token":"` + fixtureCodexIDToken() + `","last_refresh":"` + lastRefresh + `","expired":"2099-12-31T23:59:59Z","account_id":"codex-account","plan_type":"pro"}`),
	}
	if _, err := rt.store.Save(context.Background(), profile, contract.ProviderCodex, 0, grant); err != nil {
		t.Fatal(err)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), "cliproxy.roundtripper", terminal)
		rt.HTTPHandler().ServeHTTP(w, req.WithContext(ctx))
	}))
	t.Cleanup(api.Close)

	status, modelBody := fixtureRequest(t, api.Client(), http.MethodGet, api.URL+"/v1/models?provider=codex", capability, nil)
	var catalog struct {
		Models []contract.Model `json:"models"`
	}
	if status != http.StatusOK || json.Unmarshal(modelBody, &catalog) != nil {
		t.Fatalf("load synthetic host Codex catalog: status=%d body=%s", status, modelBody)
	}
	found := false
	for _, entry := range catalog.Models {
		found = found || entry.ID == model
	}
	if !found {
		t.Fatalf("host Codex catalog does not expose %q", model)
	}

	firstInput := []byte(`{"model":"gpt-6.1-sol","max_output_tokens":1024,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"keep this user content"}]}]}`)
	status, firstEvents := codexHostInference(t, api.Client(), api.URL, capability, profile, model, session, firstInput, nil)
	if status != http.StatusOK {
		t.Fatalf("first Codex turn status=%d events=%+v", status, firstEvents)
	}
	firstDone := codexHostDone(t, firstEvents)
	if firstDone.Stop != "end" || firstDone.Receipt == "" || len(firstDone.State) == 0 ||
		!bytes.Contains(firstDone.State, []byte(stateToken)) || !bytes.Contains(firstDone.Response, []byte("first native answer")) ||
		!bytes.Contains(firstDone.Response, []byte("native_response_extra")) || !bytes.Contains(firstDone.Response, []byte("msg-native-fixture")) {
		t.Fatalf("first native terminal did not retain completed response and opaque state: %+v", firstDone)
	}
	firstWire := codexWireRequest(t, firstEvents)
	assertCodexNormalizedBody(t, firstWire, model, "keep this user content")

	var prior struct {
		Output []json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(firstDone.State, &prior); err != nil || len(prior.Output) == 0 {
		t.Fatalf("decode returned assistant state %s: %v", firstDone.State, err)
	}
	replayInputItems := append(prior.Output, json.RawMessage(`{"type":"message","role":"user","content":[{"type":"input_text","text":"continue with the signed state"}]}`))
	secondInput, err := json.Marshal(map[string]any{
		"model": model, "input": replayInputItems, "store": true, "stream": false,
		"include": []string{"reasoning.summary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	replay := []map[string]any{{"state": json.RawMessage(firstDone.State), "receipt": firstDone.Receipt}}
	status, secondEvents := codexHostInference(t, api.Client(), api.URL, capability, profile, model, session, secondInput, replay)
	if status != http.StatusOK || codexHostDone(t, secondEvents).Stop != "end" {
		t.Fatalf("replayed Codex turn status=%d events=%+v", status, secondEvents)
	}
	secondWire := codexWireRequest(t, secondEvents)
	assertCodexNormalizedBody(t, secondWire, model, "continue with the signed state")
	assertCodexReplayItemUnchanged(t, secondWire, prior.Output[0])

	alteredInput := bytes.Replace(secondInput, []byte(stateToken), []byte(stateToken+"x"), 1)
	before := terminal.count()
	deniedStatus, deniedEvents := codexHostInference(t, api.Client(), api.URL, capability, profile, model, session, alteredInput, replay)
	if deniedStatus != http.StatusForbidden || terminal.count() != before || codexHasDone(deniedEvents) {
		t.Fatalf("tampered state was not denied before terminal transport: status=%d calls=%d->%d events=%+v", deniedStatus, before, terminal.count(), deniedEvents)
	}

	captured := readCodexRequestCaptures(t, filepath.Join(root, "captures", "native-sse.ndjson"), session)
	if len(captured) != 2 || !bytes.Equal(captured[0], terminal.body(0)) || !bytes.Equal(captured[1], terminal.body(1)) {
		t.Fatalf("privacy-captured outbound bodies differ from terminal bodies: captures=%d terminal=%d", len(captured), terminal.count())
	}
}

type codexReplayTerminal struct {
	mu        sync.Mutex
	responses [][]byte
	requests  [][]byte
}

func (t *codexReplayTerminal) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	index := len(t.requests)
	t.requests = append(t.requests, bytes.Clone(body))
	if index >= len(t.responses) {
		return nil, io.ErrUnexpectedEOF
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(bytes.NewReader(t.responses[index])),
		Request:    req,
	}, nil
}

func (t *codexReplayTerminal) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

func (t *codexReplayTerminal) body(index int) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.requests[index])
}

type codexReplayEvent struct {
	Type     string          `json:"type"`
	Stop     string          `json:"stop"`
	State    json.RawMessage `json:"state"`
	Receipt  string          `json:"receipt"`
	Response json.RawMessage `json:"response"`
	Payload  json.RawMessage `json:"payload"`
}

func codexHostInference(t *testing.T, client *http.Client, host, token, profile, model, session string, input []byte, replay []map[string]any) (int, []codexReplayEvent) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider": contract.ProviderCodex, "model": model, "session_id": session,
		"input": json.RawMessage(input), "replay": replay,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, stream := fixtureRequest(t, client, http.MethodPost, host+"/v1/profiles/"+profile+"/infer", token, body)
	var events []codexReplayEvent
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	for scanner.Scan() {
		var event codexReplayEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode native replay event %q: %v", scanner.Text(), err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return status, events
}

func codexHostDone(t *testing.T, events []codexReplayEvent) codexReplayEvent {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == "done" {
			return events[i]
		}
	}
	t.Fatalf("no native Codex done event: %+v", events)
	return codexReplayEvent{}
}

func codexWireRequest(t *testing.T, events []codexReplayEvent) []byte {
	t.Helper()
	for _, event := range events {
		if event.Type == "wire_request" {
			return bytes.Clone(event.Payload)
		}
	}
	t.Fatalf("no captured Codex wire request: %+v", events)
	return nil
}

func codexHasDone(events []codexReplayEvent) bool {
	for _, event := range events {
		if event.Type == "done" {
			return true
		}
	}
	return false
}

func assertCodexNormalizedBody(t *testing.T, raw []byte, model, userContent string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode final Codex request %s: %v", raw, err)
	}
	_, hasOutputLimit := body["max_output_tokens"]
	if body["store"] != false || body["stream"] != true || hasOutputLimit ||
		body["model"] != model || !strings.Contains(string(raw), userContent) {
		t.Fatalf("final Codex request did not preserve content and normalized defaults: %s", raw)
	}
	include, _ := body["include"].([]any)
	for _, value := range include {
		if value == "reasoning.encrypted_content" {
			return
		}
	}
	t.Fatalf("final Codex request omitted encrypted reasoning: %s", raw)
}

func assertCodexReplayItemUnchanged(t *testing.T, body, stateItem []byte) {
	t.Helper()
	var request struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("decode replay request: %v", err)
	}
	var want any
	if err := json.Unmarshal(stateItem, &want); err != nil {
		t.Fatalf("decode returned reasoning state: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range request.Input {
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatalf("decode replay input item: %v", err)
		}
		if item["type"] == "reasoning" {
			gotJSON, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("replayed signed reasoning item changed: got=%s want=%s", raw, stateItem)
			}
			return
		}
	}
	t.Fatal("replay request omitted the signed reasoning item")
}

func readCodexRequestCaptures(t *testing.T, path, session string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bodies [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var record privacy.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode privacy capture record: %v", err)
		}
		if record.Direction == privacy.DirectionRequest && record.SessionID == session {
			bodies = append(bodies, bytes.Clone(record.Body))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return bodies
}

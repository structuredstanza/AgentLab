package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/llmrec"
	"github.com/structuredstanza/norma/llm"
)

// exposeBody returns the bytes exposeReasoning would send for body, or its error.
func exposeBody(t *testing.T, format llm.Format, body string) (string, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://example.invalid/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	out, err := exposeReasoning(req, format)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b), nil
}

// runExposeReasoning is exposeBody for cases that must succeed.
func runExposeReasoning(t *testing.T, format llm.Format, body string) string {
	t.Helper()
	got, err := exposeBody(t, format, body)
	if err != nil {
		t.Fatalf("exposeReasoning: %v", err)
	}
	return got
}

func decodeJSONObject(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decode %s: %v", s, err)
	}
	return m
}

func TestExposeReasoningAnthropicSummarizesThinking(t *testing.T) {
	cases := []struct {
		name, body, display string
	}{
		{"adaptive", `{"thinking":{"type":"adaptive"}}`, "summarized"},
		{"enabled with budget", `{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":2048}}`, "summarized"},
		{"caller display kept", `{"thinking":{"type":"adaptive","display":"omitted"}}`, "omitted"},
		{"budget at minimum", `{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":1024}}`, "summarized"},
		{"budget below max", `{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":4095}}`, "summarized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatAnthropic, tc.body))
			th, _ := got["thinking"].(map[string]any)
			if th["display"] != tc.display {
				t.Fatalf("display=%v want %q", th["display"], tc.display)
			}
		})
	}
}

func TestExposeReasoningAnthropicRepairsMissingBudget(t *testing.T) {
	cases := []struct {
		name, body, display string
	}{
		{"plain enabled", `{"max_tokens":4096,"thinking":{"type":"enabled"}}`, "summarized"},
		{"caller display kept", `{"max_tokens":4096,"thinking":{"type":"enabled","display":"omitted"}}`, "omitted"},
		{"room for one token", `{"max_tokens":1025,"thinking":{"type":"enabled"}}`, "summarized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatAnthropic, tc.body))
			th, _ := got["thinking"].(map[string]any)
			if th["budget_tokens"] != float64(1024) {
				t.Fatalf("budget_tokens=%v want 1024", th["budget_tokens"])
			}
			if th["display"] != tc.display {
				t.Fatalf("display=%v want %q", th["display"], tc.display)
			}
			if want := decodeJSONObject(t, tc.body)["max_tokens"]; got["max_tokens"] != want {
				t.Fatalf("max_tokens=%v want %v", got["max_tokens"], want)
			}
		})
	}
}

func TestExposeReasoningAnthropicLeavesUnrepairableEnabledBodies(t *testing.T) {
	for _, body := range []string{
		`{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":512}}`,
		`{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":1023}}`,
		`{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":4096}}`,
		`{"max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":null}}`,
		`{"max_tokens":1024,"thinking":{"type":"enabled"}}`,
		`{"max_tokens":512,"thinking":{"type":"enabled"}}`,
		`{"max_tokens":null,"thinking":{"type":"enabled"}}`,
		`{"thinking":{"type":"enabled"}}`,
	} {
		if got := runExposeReasoning(t, llm.FormatAnthropic, body); got != body {
			t.Fatalf("body changed: %s", got)
		}
	}
}

func TestExposeReasoningAnthropicLeavesOtherBodiesByteIdentical(t *testing.T) {
	for _, body := range []string{
		`{"thinking":{"type":"disabled"}}`,
		`{"max_tokens":8,"messages":[]}`,
		`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"s"}]}]}`,
	} {
		if got := runExposeReasoning(t, llm.FormatAnthropic, body); got != body {
			t.Fatalf("body changed: %s", got)
		}
	}
}

func TestExposeReasoningResponsesRequestsSummaryAndEncryptedState(t *testing.T) {
	got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses,
		`{"model":"m","reasoning":{"effort":"medium"}}`))
	r, _ := got["reasoning"].(map[string]any)
	if r["summary"] != "auto" || r["effort"] != "medium" {
		t.Fatalf("reasoning=%v", r)
	}
	if inc, _ := got["include"].([]any); len(inc) != 1 || inc[0] != responsesEncryptedInclude {
		t.Fatalf("include=%v", got["include"])
	}
}

func TestExposeReasoningResponsesKeepsCallerValuesAndAppendsOnce(t *testing.T) {
	got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses,
		`{"reasoning":{"effort":"high","summary":"detailed"},"include":["web_search_call.results"]}`))
	r, _ := got["reasoning"].(map[string]any)
	if r["summary"] != "detailed" {
		t.Fatalf("summary=%v want detailed", r["summary"])
	}
	inc, _ := got["include"].([]any)
	if len(inc) != 2 || inc[0] != "web_search_call.results" || inc[1] != responsesEncryptedInclude {
		t.Fatalf("include=%v", inc)
	}

	got = decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses,
		`{"reasoning":{"effort":"high"},"include":["reasoning.encrypted_content"]}`))
	if inc, _ := got["include"].([]any); len(inc) != 1 {
		t.Fatalf("include=%v want encrypted state listed once", inc)
	}
	got = decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses,
		`{"reasoning":{"effort":"high","summary":null}}`))
	if r, _ := got["reasoning"].(map[string]any); r["summary"] != nil {
		t.Fatalf("summary=%v want explicit null kept", r["summary"])
	}
}

func TestExposeReasoningResponsesRequestsEncryptedStateWithoutSummaryOnDisabled(t *testing.T) {
	const body = `{"model":"m","input":"hi"}`
	got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses, body))
	if inc, _ := got["include"].([]any); len(inc) != 1 || inc[0] != responsesEncryptedInclude {
		t.Fatalf("include=%v", got["include"])
	}
	if got["reasoning"] != nil {
		t.Fatalf("reasoning forced: %v", got["reasoning"])
	}
}

func TestExposeReasoningResponsesRejectsNonArrayInclude(t *testing.T) {
	if _, err := exposeBody(t, llm.FormatOpenAIResponses,
		`{"reasoning":{"effort":"low"},"include":"x"}`); err == nil {
		t.Fatal("want error for non-array include")
	}
}

func TestExposeReasoningChatIsUntouched(t *testing.T) {
	const body = `{"model":"m","thinking":{"type":"enabled"},"reasoning":{"effort":"medium"}}`
	if got := runExposeReasoning(t, llm.FormatOpenAI, body); got != body {
		t.Fatalf("chat body changed: %s", got)
	}
}

func TestExposeReasoningResponsesAddsIncludeWithoutReasoningObject(t *testing.T) {
	for _, body := range []string{
		`{"model":"m","input":"hi"}`,
		`{"model":"m","input":"hi","reasoning":null}`,
		`{"input":[{"type":"reasoning","id":"r1","encrypted_content":"x"}]}`,
	} {
		got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses, body))
		if inc, _ := got["include"].([]any); len(inc) != 1 || inc[0] != responsesEncryptedInclude {
			t.Fatalf("include=%v for %s", got["include"], body)
		}
		if got["reasoning"] != nil {
			t.Fatalf("reasoning forced for %s: %v", body, got["reasoning"])
		}
	}
}

func TestExposeReasoningResponsesSkipsSummaryForEffortNone(t *testing.T) {
	got := decodeJSONObject(t, runExposeReasoning(t, llm.FormatOpenAIResponses, `{"reasoning":{"effort":"none"}}`))
	r, _ := got["reasoning"].(map[string]any)
	if _, set := r["summary"]; set {
		t.Fatalf("summary=%v want none for effort none", r["summary"])
	}
	if inc, _ := got["include"].([]any); len(inc) != 1 {
		t.Fatalf("include=%v", got["include"])
	}
}

// The raw capture must hold the rewritten bytes that were actually sent.
func TestCaptureRecordsRewrittenRequestBody(t *testing.T) {
	const orig = `{"model":"claude","max_tokens":8,"thinking":{"type":"adaptive"},"messages":[]}`
	received := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- string(b)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	client, err := quotaAwareHTTPClient("", "", llm.FormatAnthropic)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(orig))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	ctx, capt := llmrec.NewCapture(req.Context())
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	sent := <-received
	if sent == orig {
		t.Fatal("request body was not rewritten")
	}
	th, _ := decodeJSONObject(t, sent)["thinking"].(map[string]any)
	if th["display"] != "summarized" {
		t.Fatalf("display=%v want summarized in %s", th["display"], sent)
	}
	if capt.RawRequest() != sent {
		t.Fatalf("RawRequest()=%q, sent %q", capt.RawRequest(), sent)
	}
}

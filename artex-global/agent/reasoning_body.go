package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Autumn-27/norma/llm"
)

// responsesEncryptedInclude asks Responses for encrypted reasoning state. The
// state is stored opaque and never decrypted.
const responsesEncryptedInclude = "reasoning.encrypted_content"

// exposeReasoning rewrites an outgoing body so the provider returns its
// reasoning: summarized thinking for Anthropic, encrypted state for every
// Responses body, and a summary only where norma sent a reasoning object.
// Other formats pass through. The returned request sends exactly the bytes it
// carries, so the raw capture matches the wire.
func exposeReasoning(req *http.Request, format llm.Format) (*http.Request, error) {
	switch format {
	case llm.FormatAnthropic:
		return rewriteRequestBody(req, `"thinking"`, summarizeAnthropicThinking)
	case llm.FormatOpenAIResponses:
		// Every Responses body needs the include, so no key short-circuits the decode.
		return rewriteRequestBody(req, "", requestResponsesReasoning)
	}
	return req, nil
}

// rewriteRequestBody applies edit to the top-level JSON object of the body. The
// key check skips the decode when the field cannot be present; Go-marshaled JSON
// writes keys verbatim, so it has no false negatives.
func rewriteRequestBody(req *http.Request, key string, edit func(map[string]any) (bool, error)) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reasoning: read request body: %w", err)
	}
	out := raw
	if bytes.Contains(raw, []byte(key)) {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("reasoning: decode request body: %w", err)
		}
		if m == nil {
			return nil, fmt.Errorf("reasoning: request body is not a JSON object")
		}
		changed, err := edit(m)
		if err != nil {
			return nil, err
		}
		if changed {
			if out, err = json.Marshal(m); err != nil {
				return nil, fmt.Errorf("reasoning: encode request body: %w", err)
			}
		}
	}
	r := req.Clone(req.Context())
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(out)), nil }
	r.ContentLength = int64(len(out))
	return r, nil
}

// minBudget is the smallest budget_tokens Anthropic accepts. It is a json.Number,
// the type validBudget and the decoded body use.
const minBudget json.Number = "1024"

// summarizeAnthropicThinking sets display:"summarized" on adaptive and enabled
// thinking. Models that default display to "omitted" return empty thinking text.
// Enabled thinking that norma sent with no budget_tokens, which the
// API requires, gets minBudget when max_tokens leaves room for it; max_tokens is
// never raised. Present budgets are checked, not replaced. A caller-set display,
// null included, is kept. Bodies that need no change pass through byte-identical.
// shortcut: display goes to every Anthropic-format host, a gateway that rejects it
// fails the call, upgrade to a per-host switch when one does.
func summarizeAnthropicThinking(m map[string]any) (bool, error) {
	th, ok := m["thinking"].(map[string]any)
	if !ok {
		return false, nil
	}
	changed := false
	switch typ, _ := th["type"].(string); typ {
	case "adaptive":
	case "enabled":
		if _, set := th["budget_tokens"]; !set {
			if mx, isNum := m["max_tokens"].(json.Number); !isNum || !validBudget(minBudget, mx) {
				return false, nil
			}
			th["budget_tokens"] = minBudget
			changed = true
		} else if !validBudget(th["budget_tokens"], m["max_tokens"]) {
			return false, nil
		}
	default:
		return false, nil
	}
	if _, set := th["display"]; !set {
		th["display"] = "summarized"
		changed = true
	}
	return changed, nil
}

// validBudget reports whether budget is an integer of at least 1024 that is
// below maxTokens when that is present. Numbers arrive as json.Number.
func validBudget(budget, maxTokens any) bool {
	b, ok := budget.(json.Number)
	if !ok {
		return false
	}
	n, err := b.Int64()
	if err != nil || n < 1024 {
		return false
	}
	if mx, ok := maxTokens.(json.Number); ok {
		if v, err := mx.Int64(); err == nil && n >= v {
			return false
		}
	}
	return true
}

// requestResponsesReasoning always requests encrypted reasoning state. It asks
// for a summary only on a top-level reasoning object, which norma sends only
// when reasoning_effort is set and thinking is not disabled, because OpenAI
// returns no summary text unless summary is set. A caller-set summary, null
// included, is kept, and effort none gets no summary because no reasoning runs.
// shortcut: no summary for model-default effort, because norma omits the
// reasoning object there; upgrade when the per-request thinking signal reaches
// the transport.
func requestResponsesReasoning(m map[string]any) (bool, error) {
	changed := false
	if r, ok := m["reasoning"].(map[string]any); ok {
		effort, _ := r["effort"].(string)
		if _, set := r["summary"]; !set && effort != "none" {
			r["summary"] = "auto"
			changed = true
		}
	}
	switch inc := m["include"].(type) {
	case nil:
		m["include"] = []any{responsesEncryptedInclude}
		changed = true
	case []any:
		if !hasStringItem(inc, responsesEncryptedInclude) {
			m["include"] = append(inc, responsesEncryptedInclude)
			changed = true
		}
	default:
		return false, fmt.Errorf("reasoning: include is %T, want an array", inc)
	}
	return changed, nil
}

func hasStringItem(items []any, want string) bool {
	for _, it := range items {
		if s, ok := it.(string); ok && s == want {
			return true
		}
	}
	return false
}

package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"reflect"
	"strings"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/llmrec"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/nativeproxy"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/sidequestion"
	"github.com/structuredstanza/norma/llm"
	"github.com/structuredstanza/norma/transcript"
)

const nativeStateBlock llm.BlockType = "provider_state"

type fallbackChainKey struct{}

// WithAllowedFallbackChoices binds configured refusal models and effort levels.
func WithAllowedFallbackChoices(ctx context.Context, choices []NativeModelChoice) context.Context {
	if len(choices) == 0 {
		return ctx
	}
	return context.WithValue(ctx, fallbackChainKey{}, append([]NativeModelChoice(nil), choices...))
}

func allowedFallbackChoicesFrom(ctx context.Context) []NativeModelChoice {
	if ctx == nil {
		return nil
	}
	choices, _ := ctx.Value(fallbackChainKey{}).([]NativeModelChoice)
	return choices
}

func isAllowedFallbackChoice(allowed []NativeModelChoice, choice NativeModelChoice) bool {
	for _, candidate := range allowed {
		if candidate == choice {
			return true
		}
	}
	return false
}

func isAllowedFallbackModel(allowed []string, model string) bool {
	for _, m := range allowed {
		if m == model {
			return true
		}
	}
	return false
}

// DeriveSessionChainModel returns the latest valid same-profile/provider/session native envelope model and effort
// from history if present and allowed in the configured chain (fallbackModels).
// It examines the latest native envelope only and returns ("", "", false) if absent, invalid, or outside chain.
func DeriveSessionChainModel(ctx context.Context, messages []llm.Message, profileID, provider string, fallbackModels []string) (string, string, bool) {
	sessionID := transcript.SessionIDFrom(ctx)
	if sessionID == "" || len(messages) == 0 {
		return "", "", false
	}
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		env, ok, err := nativeEnvelope(m)
		if err != nil {
			return "", "", false
		}
		if !ok {
			continue
		}
		if env.Version == 2 && env.Provider == provider && env.ProfileID == profileID &&
			env.SessionID == sessionID && env.ResponseID != "" && env.Receipt != "" && len(env.State) > 0 {
			if isAllowedFallbackModel(fallbackModels, env.Model) {
				return env.Model, env.ReasoningEffort, true
			}
		}
		return "", "", false
	}
	return "", "", false
}

var errNativeStreamUnsupported = errors.New("native subscription providers support Complete only to preserve provider replay state")

type nativeProvider struct {
	proxy     *nativeproxy.Client
	profileID string
	provider  string
	model     string
	thinking  string
	effort    string
}

func (p *nativeProvider) RequiresComplete() bool { return true }

func (p *nativeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) { yield(llm.StreamEvent{}, errNativeStreamUnsupported) }
}

func (p *nativeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	body, _, err := p.requestBody(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("%w: %v", llm.ErrHistoryRejected, err)
	}
	resp, err := p.proxy.Infer(ctx, p.profileID, body)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, nativeCallError(ctx, err)
	}
	defer resp.Body.Close()
	if capt := llmrec.CaptureFrom(ctx); capt != nil {
		capt.SetRequest(string(body))
		resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)
	}
	term, err := readNativeTerminal(resp.Body)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, nativeCallError(ctx, err)
	}
	if term.Type == "error" {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("native inference failed: %s", safeNativeCode(term.Code))
	}
	switch term.Stop {
	case "end", "tool", "refusal", "length":
	case "error":
		return llm.Message{}, "", llm.Usage{}, errors.New("native inference failed")
	default:
		return llm.Message{}, "", llm.Usage{}, errors.New("native inference returned an unknown terminal stop")
	}
	if len(term.Response) == 0 || !json.Valid(term.Response) || len(term.State) == 0 || term.Receipt == "" {
		return llm.Message{}, "", llm.Usage{}, errors.New("native inference terminal response, state, or receipt is missing")
	}
	projected, responseID, err := projectNative(p.provider, term.State)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if responseID == "" {
		responseID = deriveNativeResponseID(term.Response, term.State)
	}
	env := nativeStateEnvelope{Version: 2, Provider: p.provider, Model: p.model, ReasoningEffort: p.effort, ProfileID: p.profileID, SessionID: transcript.SessionIDFrom(ctx), ResponseID: responseID, State: term.State, Receipt: term.Receipt}
	envRaw, err := json.Marshal(env)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, errors.New("native provider state could not be encoded")
	}
	projected = append(projected, llm.ContentBlock{Type: nativeStateBlock, Input: envRaw})
	if term.Stop == "refusal" {
		llmrec.MarkRefusal(ctx)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: projected}, nativeStop(term.Stop), term.Usage.llmUsage(), nil
}

type nativeStateEnvelope struct {
	Version         int             `json:"version"`
	Provider        string          `json:"provider"`
	Model           string          `json:"model"`
	ReasoningEffort string          `json:"reasoning_effort,omitempty"`
	ProfileID       string          `json:"profile_id"`
	SessionID       string          `json:"session_id"`
	ResponseID      string          `json:"response_id,omitempty"`
	State           json.RawMessage `json:"state"`
	Receipt         string          `json:"receipt"`
}

type nativeReplay struct {
	State   json.RawMessage `json:"state"`
	Receipt string          `json:"receipt"`
}
type nativeInferBody struct {
	Provider  string          `json:"provider"`
	Model     string          `json:"model"`
	SessionID string          `json:"session_id"`
	Input     json.RawMessage `json:"input"`
	Replay    []nativeReplay  `json:"replay"`
}

type nativeAntigravityState struct {
	ResponseID string `json:"responseId"`
	Candidates []struct {
		Content struct {
			Role  string            `json:"role"`
			Parts []json.RawMessage `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	PromptFeedback *struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
}

func (s *nativeAntigravityState) validTerminal() bool {
	if s.Candidates == nil {
		return false
	}
	reason := ""
	if s.PromptFeedback != nil {
		reason = s.PromptFeedback.BlockReason
	}
	blocked := reason != "" && reason != "BLOCK_REASON_UNSPECIFIED" && strings.TrimSpace(reason) == reason
	if len(s.Candidates) == 0 {
		return blocked
	}
	if blocked {
		return false
	}
	for i := range s.Candidates {
		if s.Candidates[i].Content.Role != "model" {
			return false
		}
	}
	return true
}

func (p *nativeProvider) requestBody(ctx context.Context, req llm.CompletionRequest) ([]byte, []nativeReplay, error) {
	// An operator-configured endpoint keeps no provider-side state, so there is nothing for a
	// replay receipt to prove: the transcript's own messages are the whole history. The
	// proof mechanism exists to detect a proxy tampering with opaque subscription state,
	// which a stateless endpoint does not have.
	if p.provider == "custom" {
		sessionID := transcript.SessionIDFrom(ctx)
		if sessionID == "" {
			return nil, nil, errors.New("native inference requires a session id")
		}
		input, err := p.encodeInput(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := json.Marshal(nativeInferBody{
			Provider: p.provider, Model: p.model, SessionID: sessionID, Input: input,
		})
		if err != nil {
			return nil, nil, err
		}
		return body, nil, nil
	}
	sessionID := transcript.SessionIDFrom(ctx)
	if sessionID == "" {
		return nil, nil, errors.New("native inference requires a session id")
	}

	allowedChoices := allowedFallbackChoicesFrom(ctx)
	currentChoice := NativeModelChoice{Model: p.model, ReasoningEffort: p.effort}
	if len(allowedChoices) > 0 && !isAllowedFallbackChoice(allowedChoices, currentChoice) {
		return nil, nil, errors.New("native replay rejected: unapproved destination model or effort")
	}

	suffixStart, handoff, activeSuffix := len(req.Messages), false, false
	for i := range req.Messages {
		m := req.Messages[i]
		if m.Role != llm.RoleAssistant {
			for _, b := range m.Content {
				if b.Type == llm.BlockToolResult {
					for _, child := range b.Content {
						if child.Type != llm.BlockText {
							return nil, nil, fmt.Errorf("native input: unsupported tool result block %q", child.Type)
						}
					}
				}
				if b.Type == nativeStateBlock {
					return nil, nil, errors.New("native replay rejected: provider state is not attached to an assistant turn")
				}
			}
			continue
		}
		env, ok, err := nativeEnvelope(m)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		if env.Version != 2 || env.Provider != p.provider || env.ProfileID != p.profileID ||
			env.SessionID != sessionID || env.ResponseID == "" || env.Receipt == "" || len(env.State) == 0 ||
			(NativeModelChoice{Model: env.Model, ReasoningEffort: env.ReasoningEffort} != currentChoice && !isAllowedFallbackChoice(allowedChoices, NativeModelChoice{Model: env.Model, ReasoningEffort: env.ReasoningEffort})) {
			return nil, nil, errors.New("native_replay_state_rejected: foreign, legacy, or unverifiable provider state")
		}
		projected, stateResponseID, err := projectNative(p.provider, env.State)
		if err != nil {
			return nil, nil, errors.New("native replay rejected: provider state is malformed")
		}
		if stateResponseID != "" && env.ResponseID != stateResponseID {
			return nil, nil, errors.New("native replay rejected: response id conflicts with provider state")
		}
		if !sameNativeProjection(stripNativeState(m.Content), projected) {
			return nil, nil, errors.New("native replay rejected: provider state conflicts with the neutral projection")
		}
		matchesChoice := env.Model == p.model && env.ReasoningEffort == p.effort
		if matchesChoice {
			if !activeSuffix {
				suffixStart = i
			}
		} else {
			handoff = true
			suffixStart = len(req.Messages)
		}
		activeSuffix = matchesChoice
	}

	copiedMessages := make([]llm.Message, len(req.Messages))
	replay := []nativeReplay{}
	for i, m := range req.Messages {
		if handoff && i < suffixStart {
			conv, err := sidequestion.ReadableHistoryMessage(m)
			if err != nil {
				return nil, nil, err
			}
			copiedMessages[i] = conv
			continue
		}
		copiedMessages[i] = m
		if m.Role == llm.RoleAssistant {
			env, ok, _ := nativeEnvelope(m)
			if ok && i >= suffixStart {
				replay = append(replay, nativeReplay{State: env.State, Receipt: env.Receipt})
			}
		}
	}

	outReq := req
	outReq.Messages = copiedMessages
	input, err := p.encodeInput(outReq)
	if err != nil {
		return nil, nil, err
	}
	body, err := json.Marshal(nativeInferBody{Provider: p.provider, Model: p.model, SessionID: sessionID, Input: input, Replay: replay})
	return body, replay, err
}

func stripNativeState(in []llm.ContentBlock) []llm.ContentBlock {
	out := make([]llm.ContentBlock, 0, len(in))
	for _, b := range in {
		if b.Type != nativeStateBlock {
			out = append(out, b)
		}
	}
	return out
}

func nativeEnvelope(m llm.Message) (nativeStateEnvelope, bool, error) {
	var found nativeStateEnvelope
	hasState := false
	for _, b := range m.Content {
		if b.Type != nativeStateBlock {
			continue
		}
		if hasState {
			return nativeStateEnvelope{}, false, errors.New("native replay rejected: multiple provider states in one assistant turn")
		}
		if json.Unmarshal(b.Input, &found) != nil {
			return nativeStateEnvelope{}, false, errors.New("native replay rejected: malformed provider state envelope")
		}
		hasState = true
	}
	return found, hasState, nil
}
func sameNativeProjection(a, b []llm.ContentBlock) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].Text != b[i].Text || a[i].Thinking != b[i].Thinking ||
			a[i].Signature != b[i].Signature || a[i].ID != b[i].ID || a[i].Name != b[i].Name ||
			a[i].ToolUseID != b[i].ToolUseID || a[i].IsError != b[i].IsError ||
			!reflect.DeepEqual(a[i].Content, b[i].Content) ||
			!jsonEquivalent(jsonOrNull(a[i].Input), jsonOrNull(b[i].Input)) {
			return false
		}
	}
	return true
}

func jsonEquivalent(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return json.Valid(a)
	}
	decode := func(raw json.RawMessage) (any, bool) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value, extra any
		if decoder.Decode(&value) != nil || decoder.Decode(&extra) != io.EOF {
			return nil, false
		}
		return value, true
	}
	av, aok := decode(a)
	bv, bok := decode(b)
	return aok && bok && reflect.DeepEqual(av, bv)
}

func jsonOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// toolInput returns a tool call's arguments as valid JSON.
//
// A model can emit several JSON objects back to back in one arguments field, most
// often when it decides to call a tool more than once in a single turn. The result is
// not valid JSON, and sending it back makes the upstream reject every later turn of the
// conversation. Only the first object is kept: it is the call the model started with,
// and the remaining ones are re-issued on the next turn at the cost of one round trip.
//
// Invalid input is repaired rather than rejected because a local endpoint holds no
// provider state that a rejected turn would protect, and a task that cannot send its
// history stays wedged until its process is restarted.
func toolInput(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("{}")
	}
	if json.Valid(raw) {
		return raw
	}
	if first, ok := firstJSONValue(raw); ok && json.Valid(first) {
		return first
	}
	return json.RawMessage("{}")
}

// firstJSONValue returns the leading complete JSON value of b, ignoring whatever
// follows it.
func firstJSONValue(b []byte) (json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var v json.RawMessage
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

// nativeSystemBlocks renders the system prompt for the Claude native API, putting a
// cache breakpoint on the static prefix named by DynamicBoundary. A zero boundary
// means no static prefix was declared, so the prompt is sent as one plain block and
// the upstream applies its own default policy.
func nativeSystemBlocks(req llm.CompletionRequest) []map[string]any {
	if len(req.System) == 0 {
		return nil
	}
	join := func(parts []string) string { return strings.Join(parts, "\n\n") }
	b := req.DynamicBoundary
	if b <= 0 {
		return []map[string]any{{"type": "text", "text": join(req.System)}}
	}
	cacheable := map[string]any{"type": "text", "text": join(req.System[:min(b, len(req.System))]),
		"cache_control": map[string]any{"type": "ephemeral"}}
	if b >= len(req.System) {
		return []map[string]any{cacheable}
	}
	return []map[string]any{cacheable, {"type": "text", "text": join(req.System[b:])}}
}

func (p *nativeProvider) encodeInput(req llm.CompletionRequest) (json.RawMessage, error) {
	system := strings.Join(req.System, "\n\n")
	thinking := p.thinking
	if req.Thinking != "" {
		thinking = req.Thinking
	}
	switch p.provider {
	case "claude":
		messages := make([]any, 0, len(req.Messages))
		for _, m := range req.Messages {
			role := "user"
			if m.Role == llm.RoleAssistant {
				role = "assistant"
			} else if m.Role != llm.RoleUser {
				return nil, fmt.Errorf("native input: unsupported role %q", m.Role)
			}
			if role == "assistant" {
				if env, ok, err := nativeEnvelope(m); err != nil {
					return nil, err
				} else if ok {
					var native struct {
						Role    string            `json:"role"`
						Content []json.RawMessage `json:"content"`
					}
					if json.Unmarshal(env.State, &native) != nil || native.Role != "assistant" {
						return nil, errors.New("claude replay state malformed")
					}
					messages = append(messages, map[string]any{"role": role, "content": native.Content})
					continue
				}
			}
			content := make([]any, 0, len(m.Content))
			for _, b := range m.Content {
				switch b.Type {
				case llm.BlockText:
					text := b.Text
					if m.Role == llm.RoleUser {
						text = stripWorkerChatMarker(text)
					}
					content = append(content, map[string]any{"type": "text", "text": text})
				case llm.BlockToolUse:
					content = append(content, map[string]any{"type": "tool_use", "id": b.ID, "name": b.Name, "input": jsonOrNull(b.Input)})
				case llm.BlockToolResult:
					parts := make([]any, 0, len(b.Content))
					for _, c := range b.Content {
						if c.Type != llm.BlockText {
							return nil, fmt.Errorf("native input: unsupported tool result block %q", c.Type)
						}
						parts = append(parts, map[string]any{"type": "text", "text": c.Text})
					}
					content = append(content, map[string]any{"type": "tool_result", "tool_use_id": b.ToolUseID, "content": parts, "is_error": b.IsError})
				case nativeStateBlock:
				default:
					return nil, fmt.Errorf("native input: unsupported block %q", b.Type)
				}
			}
			messages = append(messages, map[string]any{"role": role, "content": content})
		}
		// The subscription path joins the system prompt into one string, which throws
		// away DynamicBoundary and with it the cache breakpoint: every turn re-reads
		// the whole static prefix. Send it as blocks so the proxy can mark the prefix
		// cacheable, the same split the direct Anthropic path already makes.
		body := map[string]any{"system": nativeSystemBlocks(req), "messages": messages}
		if req.MaxTokens > 0 {
			body["max_tokens"] = req.MaxTokens
		}
		if req.Temperature != nil {
			body["temperature"] = *req.Temperature
		}
		if len(req.Stop) > 0 {
			body["stop_sequences"] = req.Stop
		}
		if len(req.Tools) > 0 {
			body["tools"] = req.Tools
		}
		if thinking != "disabled" && p.effort != "" {
			body["output_config"] = map[string]any{"effort": p.effort}
		}
		return json.Marshal(body)
	case "custom":
		// An operator-configured endpoint speaks the [OI] chat-completions format. Tool use is
		// expressed as assistant tool_calls plus role:tool results, which is what a
		// local server's template expects; there is no provider envelope to preserve.
		messages := make([]any, 0, len(req.Messages)+1)
		if system != "" {
			messages = append(messages, map[string]any{"role": "system", "content": system})
		}
		for _, m := range req.Messages {
			switch m.Role {
			case llm.RoleUser:
				texts := make([]string, 0, len(m.Content))
				for _, b := range m.Content {
					switch b.Type {
					case llm.BlockText:
						texts = append(texts, b.Text)
					case llm.BlockToolResult:
						messages = append(messages, map[string]any{
							"role": "tool", "tool_call_id": b.ToolUseID, "content": toolResultText(b),
						})
					}
				}
				if len(texts) > 0 {
					messages = append(messages, map[string]any{"role": "user", "content": strings.Join(texts, "\n\n")})
				}
			case llm.RoleAssistant:
				msg := map[string]any{"role": "assistant"}
				var texts []string
				var calls []any
				for _, b := range m.Content {
					switch b.Type {
					case llm.BlockText:
						texts = append(texts, b.Text)
					case llm.BlockToolUse:
						// A tool call's arguments must be a JSON object on the wire. An empty
						// input is common for no-argument tools, and a local server's chat
						// template rejects an empty string, so the empty object is sent instead.
						// toolInput also repairs a model that emitted several objects at once.
						calls = append(calls, map[string]any{
							"id": b.ID, "type": "function",
							"function": map[string]any{"name": b.Name, "arguments": string(toolInput(b.Input))},
						})
					}
				}
				msg["content"] = strings.Join(texts, "")
				if len(calls) > 0 {
					msg["tool_calls"] = calls
				}
				messages = append(messages, msg)
			default:
				return nil, fmt.Errorf("native input: unsupported role %q", m.Role)
			}
		}
		body := map[string]any{"messages": messages}
		if len(req.Tools) > 0 {
			tools := make([]any, 0, len(req.Tools))
			for _, t := range req.Tools {
				params := t.InputSchema
				if len(params) == 0 {
					// A function schema needs a JSON Schema object; an absent one makes the
					// local server's template fail before the model ever runs.
					params = map[string]any{"type": "object", "properties": map[string]any{}}
				}
				tools = append(tools, map[string]any{
					"type": "function",
					"function": map[string]any{
						"name": t.Name, "description": t.Description, "parameters": params,
					},
				})
			}
			body["tools"] = tools
		}
		if req.MaxTokens > 0 {
			body["max_tokens"] = req.MaxTokens
		}
		if req.Temperature != nil {
			body["temperature"] = *req.Temperature
		}
		if len(req.Stop) > 0 {
			body["stop"] = req.Stop
		}
		return json.Marshal(body)
	case "codex":
		input := make([]any, 0, len(req.Messages)+1)
		if system != "" {
			input = append(input, map[string]any{"role": "developer", "content": system})
		}
		for _, m := range req.Messages {
			if m.Role == llm.RoleAssistant {
				if env, ok, err := nativeEnvelope(m); err != nil {
					return nil, err
				} else if ok {
					var native struct {
						Output []json.RawMessage `json:"output"`
					}
					if json.Unmarshal(env.State, &native) != nil || native.Output == nil {
						return nil, errors.New("codex replay state malformed")
					}
					for _, item := range native.Output {
						input = append(input, item)
					}
					continue
				}
			}
			for _, b := range m.Content {
				switch b.Type {
				case llm.BlockText:
					typ := "input_text"
					if m.Role == llm.RoleAssistant {
						typ = "output_text"
					}
					text := b.Text
					if m.Role == llm.RoleUser {
						text = stripWorkerChatMarker(text)
					}
					input = append(input, map[string]any{"type": "message", "role": string(m.Role), "content": []any{map[string]any{"type": typ, "text": text}}})
				case llm.BlockToolUse:
					input = append(input, map[string]any{"type": "function_call", "call_id": b.ID, "name": b.Name, "arguments": string(jsonOrNull(b.Input))})
				case llm.BlockToolResult:
					input = append(input, map[string]any{"type": "function_call_output", "call_id": b.ToolUseID, "output": toolResultText(b)})
				case nativeStateBlock:
				default:
					return nil, fmt.Errorf("native input: unsupported block %q", b.Type)
				}
			}
		}
		body := map[string]any{"input": input}
		if len(req.Tools) > 0 {
			tools := make([]any, 0, len(req.Tools))
			for _, t := range req.Tools {
				tools = append(tools, map[string]any{"type": "function", "name": t.Name, "description": t.Description, "parameters": t.InputSchema})
			}
			body["tools"] = tools
		}
		if req.MaxTokens > 0 {
			body["max_output_tokens"] = req.MaxTokens
		}
		if req.Temperature != nil {
			body["temperature"] = *req.Temperature
		}
		if len(req.Stop) > 0 {
			body["stop"] = req.Stop
		}
		if thinking != "disabled" {
			reasoning := map[string]any{"summary": "auto"}
			if p.effort != "" {
				reasoning["effort"] = p.effort
			}
			body["reasoning"] = reasoning
		}
		return json.Marshal(body)
	case "antigravity":
		names := make(map[string]string)
		for _, m := range req.Messages {
			for _, b := range m.Content {
				if b.Type == llm.BlockToolUse {
					names[b.ID] = b.Name
				}
			}
		}
		contents := make([]any, 0, len(req.Messages))
		for _, m := range req.Messages {
			role := "user"
			if m.Role == llm.RoleAssistant {
				role = "model"
			} else if m.Role != llm.RoleUser {
				return nil, fmt.Errorf("native input: unsupported role %q", m.Role)
			}
			if role == "model" {
				if env, ok, err := nativeEnvelope(m); err != nil {
					return nil, err
				} else if ok {
					var native nativeAntigravityState
					if json.Unmarshal(env.State, &native) != nil || !native.validTerminal() {
						return nil, errors.New("antigravity replay state malformed")
					}
					for _, c := range native.Candidates {
						contents = append(contents, map[string]any{"role": role, "parts": c.Content.Parts})
					}
					continue
				}
			}
			parts := make([]any, 0, len(m.Content))
			for _, b := range m.Content {
				switch b.Type {
				case llm.BlockText:
					text := b.Text
					if m.Role == llm.RoleUser {
						text = stripWorkerChatMarker(text)
					}
					parts = append(parts, map[string]any{"text": text})
				case llm.BlockToolUse:
					args := jsonOrNull(b.Input)
					if !json.Valid(args) {
						return nil, errors.New("native tool input malformed")
					}
					parts = append(parts, map[string]any{"functionCall": map[string]any{"id": b.ID, "name": b.Name, "args": args}})
				case llm.BlockToolResult:
					name, ok := names[b.ToolUseID]
					if !ok {
						return nil, errors.New("native replay: tool result has no matching call")
					}
					parts = append(parts, map[string]any{"functionResponse": map[string]any{"name": name, "response": map[string]any{"content": toolResultText(b)}}})
				case nativeStateBlock:
				default:
					return nil, fmt.Errorf("native input: unsupported block %q", b.Type)
				}
			}
			contents = append(contents, map[string]any{"role": role, "parts": parts})
		}
		body := map[string]any{"contents": contents}
		if system != "" {
			body["systemInstruction"] = map[string]any{"parts": []any{map[string]any{"text": system}}}
		}
		generation := map[string]any{}
		if req.MaxTokens > 0 {
			generation["maxOutputTokens"] = req.MaxTokens
		}
		if req.Temperature != nil {
			generation["temperature"] = *req.Temperature
		}
		if len(req.Stop) > 0 {
			generation["stopSequences"] = req.Stop
		}
		if thinking != "disabled" {
			thinkingConfig := map[string]any{"includeThoughts": true}
			if p.effort != "" {
				thinkingConfig["thinkingLevel"] = p.effort
			}
			generation["thinkingConfig"] = thinkingConfig
		}
		if len(generation) > 0 {
			body["generationConfig"] = generation
		}
		if len(req.Tools) > 0 {
			decl := make([]any, 0, len(req.Tools))
			for _, t := range req.Tools {
				decl = append(decl, map[string]any{"name": t.Name, "description": t.Description, "parameters": t.InputSchema})
			}
			body["tools"] = []any{map[string]any{"functionDeclarations": decl}}
		}
		return json.Marshal(body)
	default:
		return nil, errors.New("unknown native provider")
	}
}

func decodeNativeArguments(raw json.RawMessage) (json.RawMessage, error) {
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		if !json.Valid([]byte(encoded)) {
			return nil, errors.New("native tool arguments are not valid JSON")
		}
		return json.RawMessage(encoded), nil
	}
	if !json.Valid(raw) {
		return nil, errors.New("native tool arguments are not valid JSON")
	}
	return raw, nil
}

func toolResultText(b llm.ContentBlock) string {
	var s strings.Builder
	for _, c := range b.Content {
		if c.Type == llm.BlockText {
			s.WriteString(c.Text)
		}
	}
	return s.String()
}

func projectNative(provider string, raw json.RawMessage) ([]llm.ContentBlock, string, error) {
	out := make([]llm.ContentBlock, 0)
	switch provider {
	case "claude":
		var state struct {
			ID      string            `json:"id"`
			Role    string            `json:"role"`
			Content []json.RawMessage `json:"content"`
		}
		if json.Unmarshal(raw, &state) != nil || state.Role != "assistant" {
			return nil, "", errors.New("claude terminal state malformed")
		}
		for _, item := range state.Content {
			var b struct {
				Type      string          `json:"type"`
				Text      string          `json:"text"`
				Thinking  string          `json:"thinking"`
				Signature string          `json:"signature"`
				ID        string          `json:"id"`
				Name      string          `json:"name"`
				Input     json.RawMessage `json:"input"`
			}
			if json.Unmarshal(item, &b) != nil {
				return nil, "", errors.New("claude content block malformed")
			}
			switch b.Type {
			case "text":
				out = append(out, llm.ContentBlock{Type: llm.BlockText, Text: b.Text})
			case "thinking":
				out = append(out, llm.ContentBlock{Type: llm.BlockThinking, Thinking: b.Thinking, Signature: b.Signature})
			case "tool_use":
				out = append(out, llm.ContentBlock{Type: llm.BlockToolUse, ID: b.ID, Name: b.Name, Input: jsonOrNull(b.Input)})
			default: // Native-only blocks stay in the unchanged state envelope.
			}
		}
		return out, state.ID, nil
	case "custom":
		var state struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		}
		if json.Unmarshal(raw, &state) != nil {
			return nil, "", errors.New("local terminal state malformed")
		}
		if state.Content != "" {
			out = append(out, llm.ContentBlock{Type: llm.BlockText, Text: state.Content})
		}
		for _, call := range state.ToolCalls {
			out = append(out, llm.ContentBlock{
				Type: llm.BlockToolUse, ID: call.ID, Name: call.Function.Name,
				// Repaired here as well as on the way out: this is where a bad call
				// enters the conversation, and an invalid block cannot be serialized to
				// the transcript, so it would live only in memory and be replayed from
				// there for the rest of the task.
				Input: toolInput(json.RawMessage(call.Function.Arguments)),
			})
		}
		return out, "", nil
	case "codex":
		var state struct {
			ID     string            `json:"id"`
			Output []json.RawMessage `json:"output"`
		}
		if json.Unmarshal(raw, &state) != nil || state.Output == nil {
			return nil, "", errors.New("codex terminal state malformed")
		}
		for _, item := range state.Output {
			var b struct {
				Type      string          `json:"type"`
				ID        string          `json:"call_id"`
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
				Content   []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
				Summary []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"summary"`
			}
			if json.Unmarshal(item, &b) != nil {
				return nil, "", errors.New("codex output item malformed")
			}
			switch b.Type {
			case "message":
				for _, c := range b.Content {
					if c.Type == "output_text" {
						out = append(out, llm.ContentBlock{Type: llm.BlockText, Text: c.Text})
					}
				}
			case "function_call":
				args, err := decodeNativeArguments(b.Arguments)
				if err != nil {
					return nil, "", errors.New("codex function arguments malformed")
				}
				out = append(out, llm.ContentBlock{Type: llm.BlockToolUse, ID: b.ID, Name: b.Name, Input: args})
			case "reasoning":
				for _, s := range b.Summary {
					if s.Text != "" {
						out = append(out, llm.ContentBlock{Type: llm.BlockThinking, Thinking: s.Text})
					}
				}
			default: // All native output items remain in the unchanged state envelope.
			}
		}
		return out, state.ID, nil
	case "antigravity":
		var state nativeAntigravityState
		if json.Unmarshal(raw, &state) != nil || !state.validTerminal() {
			return nil, "", errors.New("antigravity terminal state malformed")
		}
		if len(state.Candidates) == 0 {
			return out, state.ResponseID, nil
		}
		// Antigravity may omit function-call IDs; derive stable local IDs without mutating signed native parts.
		sum := sha256.Sum256(raw)
		for ci, candidate := range state.Candidates {
			for pi, part := range candidate.Content.Parts {
				var b struct {
					Text             string `json:"text"`
					Thought          bool   `json:"thought"`
					ThoughtSignature string `json:"thoughtSignature"`
					FunctionCall     *struct {
						ID   string          `json:"id"`
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				}
				if json.Unmarshal(part, &b) != nil {
					return nil, "", errors.New("antigravity part malformed")
				}
				if b.FunctionCall != nil {
					id := b.FunctionCall.ID
					if id == "" {
						id = fmt.Sprintf("ag_%x_%d_%d", sum[:6], ci, pi)
					}
					out = append(out, llm.ContentBlock{Type: llm.BlockToolUse, ID: id, Name: b.FunctionCall.Name, Input: jsonOrNull(b.FunctionCall.Args)})
				} else if b.Thought {
					out = append(out, llm.ContentBlock{Type: llm.BlockThinking, Thinking: b.Text, Signature: b.ThoughtSignature})
				} else if b.Text != "" {
					out = append(out, llm.ContentBlock{Type: llm.BlockText, Text: b.Text})
				}
			}
		}
		return out, state.ResponseID, nil
	default:
		return nil, "", errors.New("unknown native provider")
	}
}
func nativeStop(s string) string {
	switch s {
	case "tool":
		return "tool_use"
	case "refusal":
		return "refusal"
	case "length":
		return "max_tokens"
	default:
		return "end_turn"
	}
}
func nativeCallError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
func safeNativeCode(s string) string {
	if s == "" {
		return "unknown"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "unknown"
		}
	}
	return s
}

func deriveNativeResponseID(response, state json.RawMessage) string {
	h := sha256.New()
	_, _ = h.Write(response)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(state)
	return fmt.Sprintf("response_%x", h.Sum(nil)[:16])
}

type nativeTerminal struct {
	Type     string          `json:"type"`
	Response json.RawMessage `json:"response"`
	State    json.RawMessage `json:"state"`
	Receipt  string          `json:"receipt"`
	Stop     string          `json:"stop"`
	Code     string          `json:"code"`
	Usage    nativeUsage     `json:"usage"`
}
type nativeUsage struct {
	Input      int `json:"input_tokens"`
	Output     int `json:"output_tokens"`
	CacheRead  int `json:"cache_read_tokens"`
	CacheWrite int `json:"cache_write_tokens"`
}

func (u nativeUsage) llmUsage() llm.Usage {
	return llm.Usage{InputTokens: u.Input, OutputTokens: u.Output, CacheReadTokens: u.CacheRead, CacheWriteTokens: u.CacheWrite}
}
func readNativeTerminal(r io.Reader) (nativeTerminal, error) {
	limit := int64(nativeproxy.MaxInferenceBodyBytes)
	br := bufio.NewReader(io.LimitReader(r, limit+1))
	var terminal nativeTerminal
	var total int64
	seenTerminal := false
	for {
		line, err := br.ReadBytes('\n')
		total += int64(len(line))
		if total > limit {
			return nativeTerminal{}, errors.New("native inference stream exceeds 8 MiB")
		}
		if len(bytes.TrimSpace(line)) > 0 {
			if seenTerminal {
				return nativeTerminal{}, errors.New("native inference stream has events after its terminal event")
			}
			var event nativeTerminal
			if json.Unmarshal(bytes.TrimSpace(line), &event) != nil {
				return nativeTerminal{}, errors.New("native inference stream malformed")
			}
			switch event.Type {
			case "wire_request", "wire_sse":
			case "done", "error":
				terminal, seenTerminal = event, true
			default:
				return nativeTerminal{}, errors.New("native inference stream has unknown event")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nativeTerminal{}, errors.New("native inference stream read failed")
		}
	}
	if !seenTerminal {
		return nativeTerminal{}, errors.New("native inference stream ended without a terminal event")
	}
	return terminal, nil
}

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"reflect"
	"strings"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/sdkbridge"
	"github.com/Autumn-27/norma/llm"
)

// sdkStateBlock carries the terminal native AssistantMessage of one SDK turn. The
// neutral blocks are a projection of it; replay sends the native message back so
// signed thinking, encrypted reasoning and provider payloads survive unchanged.
const sdkStateBlock llm.BlockType = "provider_state"

var errSDKStreamUnsupported = errors.New("sdk provider supports Complete only: the SDK bridge stream carries native state the neutral stream cannot hold")

// sdkProvider is an llm.Provider for profiles whose credentials live in the host SDK bridge.
// The SDK streams internally; Complete reads the full native NDJSON.
type sdkProvider struct {
	bridge    *sdkbridge.Client
	profileID string
	provider  string // bridge provider: anthropic | openai-codex | google-antigravity
	model     string
	thinking  string // Config.ThinkingType
	effort    string // Config.ReasoningEffort
}

func (p *sdkProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errSDKStreamUnsupported)
	}
}

func (p *sdkProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	body, err := p.requestBody(req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	resp, err := p.bridge.Infer(ctx, p.profileID, body)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, sdkCallError(ctx, err)
	}
	defer resp.Body.Close()
	// The capture records the bridge JSON request and the bridge NDJSON response. It is not upstream HTTP wire.
	if capt := llmrec.CaptureFrom(ctx); capt != nil {
		capt.SetRequest(string(body))
		resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)
	}
	reason, native, err := readSDKTerminal(resp.Body)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, sdkCallError(ctx, err)
	}
	if reason == "aborted" {
		return llm.Message{}, "", llm.Usage{}, errors.New("sdk inference aborted")
	}
	msg, err := decodeSDKMessage(native)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	blocks, err := projectSDKBlocks(msg.Content)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	stop := sdkStopReason(reason)
	switch {
	case reason == "error":
		return llm.Message{}, "", llm.Usage{}, errors.New("sdk inference failed")
	case msg.refusal():
		llmrec.MarkRefusal(ctx)
		stop = "refusal"
	}
	blocks = append(blocks, llm.ContentBlock{Type: sdkStateBlock, Input: native})
	return llm.Message{Role: llm.RoleAssistant, Content: blocks}, stop, msg.usage(), nil
}

// requestBody builds the bridge inference request from the neutral request. Options the bridge
// allowlist cannot express are rejected rather than dropped.
func (p *sdkProvider) requestBody(req llm.CompletionRequest) ([]byte, error) {
	msgs, err := p.replayMessages(req.Messages)
	if err != nil {
		return nil, err
	}
	ctxObj := sdkContext{SystemPrompt: strings.Join(req.System, "\n\n"), Messages: msgs}
	for _, t := range req.Tools {
		ctxObj.Tools = append(ctxObj.Tools, sdkTool{Name: t.Name, Description: t.Description, Parameters: t.InputSchema})
	}
	opts := map[string]any{}
	if req.MaxTokens > 0 {
		opts["maxTokens"] = req.MaxTokens
	}
	if req.Temperature != nil {
		opts["temperature"] = *req.Temperature
	}
	if len(req.Stop) > 0 {
		opts["stopSequences"] = req.Stop
	}
	thinking := p.thinking
	if req.Thinking != "" {
		thinking = req.Thinking
	}
	switch thinking {
	case "enabled":
		if p.effort != "" {
			opts["reasoning"] = p.effort
		}
	case "disabled":
		opts["forceReasoningOff"] = true
	}
	return json.Marshal(sdkInferBody{Provider: p.provider, Model: p.model, Context: ctxObj, Options: opts})
}

// replayMessages converts neutral history to native pi-ai messages. An assistant turn with native
// state is replayed only after its projection matches the neutral blocks exactly. Without state,
// the turn carries text and tool calls only.
func (p *sdkProvider) replayMessages(msgs []llm.Message) ([]json.RawMessage, error) {
	names := map[string]string{}
	now := time.Now().UnixMilli()
	var out []json.RawMessage
	for _, m := range msgs {
		switch m.Role {
		case llm.RoleUser:
			var texts []map[string]any
			for _, b := range m.Content {
				switch b.Type {
				case llm.BlockToolResult:
					raw, err := sdkToolResultMessage(b, names, now)
					if err != nil {
						return nil, err
					}
					out = append(out, raw)
				case llm.BlockText:
					texts = append(texts, map[string]any{"type": "text", "text": b.Text})
				default:
					return nil, fmt.Errorf("sdk replay: unsupported user block %q", b.Type)
				}
			}
			if len(texts) > 0 {
				raw, err := json.Marshal(map[string]any{"role": "user", "content": texts, "timestamp": now})
				if err != nil {
					return nil, err
				}
				out = append(out, raw)
			}
		case llm.RoleAssistant:
			raw, err := p.replayAssistant(m, names, now)
			if err != nil {
				return nil, err
			}
			out = append(out, raw)
		default:
			return nil, fmt.Errorf("sdk replay: unsupported role %q", m.Role)
		}
	}
	return out, nil
}

func (p *sdkProvider) replayAssistant(m llm.Message, names map[string]string, now int64) (json.RawMessage, error) {
	var neutral []llm.ContentBlock
	var state json.RawMessage
	for _, b := range m.Content {
		if b.Type == sdkStateBlock {
			if state != nil {
				return nil, errors.New("sdk replay: assistant turn has more than one provider state")
			}
			state = b.Input
			continue
		}
		neutral = append(neutral, b)
		if b.Type == llm.BlockToolUse {
			names[b.ID] = b.Name
		}
	}
	if state != nil {
		native, err := decodeSDKMessage(state)
		if err != nil {
			return nil, err
		}
		projected, err := projectSDKBlocks(native.Content)
		if err != nil {
			return nil, err
		}
		if !sameSDKProjection(neutral, projected) {
			return nil, errors.New("sdk replay: provider state conflicts with the neutral message; refusing to replay")
		}
		return state, nil
	}
	// shortcut: thinking without native state is not replayed, so foreign signatures are never applied; upgrade if a
	// foreign-provider transcript must keep its reasoning on this SDK path.
	var content []map[string]any
	for _, b := range neutral {
		switch b.Type {
		case llm.BlockText:
			content = append(content, map[string]any{"type": "text", "text": b.Text})
		case llm.BlockToolUse:
			content = append(content, map[string]any{"type": "toolCall", "id": b.ID, "name": b.Name, "arguments": jsonOrNull(b.Input)})
		}
	}
	return json.Marshal(map[string]any{
		"role": "assistant", "content": content, "provider": p.provider, "model": p.model,
		"usage":      map[string]any{"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
		"stopReason": "stop", "timestamp": now,
	})
}

func sdkToolResultMessage(b llm.ContentBlock, names map[string]string, now int64) (json.RawMessage, error) {
	name, ok := names[b.ToolUseID]
	if !ok {
		return nil, errors.New("sdk replay: tool result has no matching tool call")
	}
	var content []map[string]any
	for _, c := range b.Content {
		if c.Type != llm.BlockText {
			return nil, fmt.Errorf("sdk replay: unsupported tool result block %q", c.Type)
		}
		content = append(content, map[string]any{"type": "text", "text": c.Text})
	}
	return json.Marshal(map[string]any{
		"role": "toolResult", "toolCallId": b.ToolUseID, "toolName": name,
		"content": content, "isError": b.IsError, "timestamp": now,
	})
}

// readSDKTerminal reads the bridge NDJSON to EOF and returns the terminal reason and native message.
func readSDKTerminal(r io.Reader) (string, json.RawMessage, error) {
	br := bufio.NewReader(r)
	var reason string
	var native json.RawMessage
	for {
		line, err := br.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 && reason == "" {
			var ev struct {
				Type    string          `json:"type"`
				Reason  string          `json:"reason"`
				Message json.RawMessage `json:"message"`
				Error   json.RawMessage `json:"error"`
				Code    string          `json:"code"`
			}
			if jerr := json.Unmarshal(trimmed, &ev); jerr != nil {
				return "", nil, errors.New("sdk stream line is malformed")
			}
			switch ev.Type {
			case "done":
				reason, native = ev.Reason, ev.Message
			case "error":
				reason, native = ev.Reason, ev.Error
			case "bridge_error":
				return "", nil, fmt.Errorf("sdk bridge stream failed: %s", safeSDKCode(ev.Code))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, errors.New("sdk stream read failed")
		}
	}
	if reason == "" {
		return "", nil, errors.New("sdk stream ended without a terminal event")
	}
	return reason, native, nil
}

func safeSDKCode(code string) string {
	if code == "" {
		return "unknown"
	}
	return code
}

// sdkCallError keeps cancellation visible and returns the bridge's safe error text otherwise.
func sdkCallError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// sdkMessage is the subset of pi-ai's AssistantMessage that the projection and usage need.
type sdkMessage struct {
	Content     []sdkBlock `json:"content"`
	Usage       sdkUsage   `json:"usage"`
	StopDetails *struct {
		Type string `json:"type"`
	} `json:"stopDetails"`
}

type sdkBlock struct {
	Type              string          `json:"type"`
	Text              string          `json:"text"`
	Thinking          string          `json:"thinking"`
	ThinkingSignature string          `json:"thinkingSignature"`
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Arguments         json.RawMessage `json:"arguments"`
}

type sdkUsage struct {
	Input      int `json:"input"`
	Output     int `json:"output"`
	CacheRead  int `json:"cacheRead"`
	CacheWrite int `json:"cacheWrite"`
}

func (m sdkMessage) refusal() bool {
	return m.StopDetails != nil && m.StopDetails.Type == "refusal"
}

func (m sdkMessage) usage() llm.Usage {
	return llm.Usage{
		InputTokens:      m.Usage.Input,
		OutputTokens:     m.Usage.Output,
		CacheReadTokens:  m.Usage.CacheRead,
		CacheWriteTokens: m.Usage.CacheWrite,
	}
}

func decodeSDKMessage(raw json.RawMessage) (sdkMessage, error) {
	var m sdkMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return sdkMessage{}, errors.New("sdk native message is malformed")
	}
	return m, nil
}

// projectSDKBlocks maps native blocks to neutral blocks. Unknown block types fail: nothing is dropped.
func projectSDKBlocks(blocks []sdkBlock) ([]llm.ContentBlock, error) {
	out := make([]llm.ContentBlock, 0, len(blocks))
	for _, b := range blocks {
		switch b.Type {
		case "text":
			out = append(out, llm.ContentBlock{Type: llm.BlockText, Text: b.Text})
		case "thinking":
			out = append(out, llm.ContentBlock{Type: llm.BlockThinking, Thinking: b.Thinking, Signature: b.ThinkingSignature})
		case "toolCall":
			out = append(out, llm.ContentBlock{Type: llm.BlockToolUse, ID: b.ID, Name: b.Name, Input: jsonOrNull(b.Arguments)})
		case "redactedThinking", "fallback", "anthropicServerTool", "image":
			// norma cannot project these native-only blocks. redactedThinking.data is opaque encrypted state, not a
			// thinking signature. All stay verbatim in provider_state; image payloads are not duplicated into neutral blocks.
			continue
		default:
			return nil, fmt.Errorf("sdk native message has unsupported block type %q", b.Type)
		}
	}
	return out, nil
}

// sameSDKProjection reports whether the native projection equals the neutral blocks exactly.
func sameSDKProjection(neutral, projected []llm.ContentBlock) bool {
	if len(neutral) != len(projected) {
		return false
	}
	for i := range neutral {
		a, b := neutral[i], projected[i]
		if a.Type != b.Type || a.Text != b.Text || a.Thinking != b.Thinking || a.Signature != b.Signature ||
			a.ID != b.ID || a.Name != b.Name {
			return false
		}
		if !jsonEquivalent(jsonOrNull(a.Input), jsonOrNull(b.Input)) {
			return false
		}
	}
	return true
}

func jsonEquivalent(a, b json.RawMessage) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func jsonOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

func sdkStopReason(reason string) string {
	switch reason {
	case "toolUse":
		return "tool_use"
	case "length":
		return "max_tokens"
	default:
		return "end_turn"
	}
}

type sdkContext struct {
	SystemPrompt string            `json:"systemPrompt,omitempty"`
	Messages     []json.RawMessage `json:"messages"`
	Tools        []sdkTool         `json:"tools,omitempty"`
}

type sdkTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type sdkInferBody struct {
	Provider string         `json:"provider"`
	Model    string         `json:"model"`
	Context  sdkContext     `json:"context"`
	Options  map[string]any `json:"options,omitempty"`
}

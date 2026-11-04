package infer

import (
	"encoding/json"
	"strings"

	"github.com/artex/cliproxyhost/internal/contract"
)

const (
	maxBlocks     = 4096
	maxCandidates = 8
)

type turnResult struct {
	response []byte
	state    []byte
	usage    Usage
	stop     string
}

// accumulator folds decoded SSE frames into the native terminal object.
type accumulator interface {
	feed(ev map[string]any) error
	result() (turnResult, bool, error)
}

func newAccumulator(p contract.Provider) accumulator {
	switch p {
	case contract.ProviderClaude:
		return &claudeTurn{usage: map[string]any{}, buffers: map[int]map[string]*strings.Builder{}}
	case contract.ProviderCodex:
		return &codexTurn{}
	case contract.ProviderLocal:
		// A local model answers in the [OI] chat-completions shape.
		return &chatTurn{toolCalls: map[int]*pendingCall{}}
	default:
		return &geminiTurn{parts: map[int][]any{}, finish: map[int]string{}, role: "model"}
	}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func obj(m map[string]any, k string) map[string]any {
	o, _ := m[k].(map[string]any)
	return o
}

func arr(m map[string]any, k string) []any {
	a, _ := m[k].([]any)
	return a
}

func num(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case float64:
		return int(v)
	}
	return 0
}

// Claude

type claudeTurn struct {
	msg        map[string]any
	blocks     []map[string]any
	buffers    map[int]map[string]*strings.Builder
	usage      map[string]any
	stopReason string
	terminal   bool
}

func (c *claudeTurn) feed(ev map[string]any) error {
	idx := num(ev, "index")
	switch str(ev, "type") {
	case "message_start":
		c.msg = obj(ev, "message")
		if c.msg == nil {
			return fail(CodeUnavailable)
		}
		for k, v := range obj(c.msg, "usage") {
			c.usage[k] = v
		}
	case "content_block_start":
		block := obj(ev, "content_block")
		if block == nil || idx < 0 || idx >= maxBlocks {
			return fail(CodeUnavailable)
		}
		for len(c.blocks) <= idx {
			c.blocks = append(c.blocks, nil)
		}
		c.blocks[idx] = block
	case "content_block_delta":
		block := c.block(idx)
		if block == nil {
			return fail(CodeUnavailable)
		}
		delta := obj(ev, "delta")
		switch str(delta, "type") {
		case "text_delta":
			c.appendText(idx, "text", str(delta, "text"))
		case "thinking_delta":
			c.appendText(idx, "thinking", str(delta, "thinking"))
		case "input_json_delta":
			c.appendText(idx, "partial_json", str(delta, "partial_json"))
		case "signature_delta":
			block["signature"] = str(delta, "signature")
		default:
			return fail(CodeUnavailable)
		}
	case "content_block_stop":
		return c.flush(idx)
	case "message_delta":
		if sr := str(obj(ev, "delta"), "stop_reason"); sr != "" {
			c.stopReason = sr
		}
		for k, v := range obj(ev, "usage") {
			c.usage[k] = v
		}
	case "message_stop":
		c.terminal = true
	case "ping":
	default:
		// Includes "error" frames: a native error is not a done record.
		return fail(CodeUnavailable)
	}
	return nil
}

func (c *claudeTurn) block(idx int) map[string]any {
	if idx < 0 || idx >= len(c.blocks) {
		return nil
	}
	return c.blocks[idx]
}

func (c *claudeTurn) appendText(idx int, field, s string) {
	if c.buffers[idx] == nil {
		c.buffers[idx] = map[string]*strings.Builder{}
	}
	sb := c.buffers[idx][field]
	if sb == nil {
		sb = &strings.Builder{}
		c.buffers[idx][field] = sb
	}
	sb.WriteString(s)
}

func (c *claudeTurn) flush(idx int) error {
	block := c.block(idx)
	if block == nil {
		return fail(CodeUnavailable)
	}
	for field, sb := range c.buffers[idx] {
		if field != "partial_json" {
			block[field] = sb.String()
			continue
		}
		var input map[string]any
		if sb.Len() > 0 {
			var err error
			input, err = decodeObject([]byte(sb.String()))
			if err != nil {
				return fail(CodeUnavailable)
			}
		} else {
			input = map[string]any{}
		}
		block["input"] = input
	}
	delete(c.buffers, idx)
	return nil
}

func (c *claudeTurn) result() (turnResult, bool, error) {
	if !c.terminal {
		return turnResult{}, false, nil
	}
	if c.msg == nil {
		return turnResult{}, false, fail(CodeUnavailable)
	}
	content := make([]any, 0, len(c.blocks))
	for _, b := range c.blocks {
		if b != nil {
			content = append(content, b)
		}
	}
	c.msg["content"] = content
	c.msg["stop_reason"] = c.stopReason
	c.msg["usage"] = c.usage
	state, err := json.Marshal(map[string]any{"role": "assistant", "content": content})
	if err != nil {
		return turnResult{}, false, err
	}
	response, err := json.Marshal(c.msg)
	if err != nil {
		return turnResult{}, false, err
	}
	out := turnResult{
		response: response,
		state:    state,
		usage: Usage{
			InputTokens:      num(c.usage, "input_tokens"),
			OutputTokens:     num(c.usage, "output_tokens"),
			CacheReadTokens:  num(c.usage, "cache_read_input_tokens"),
			CacheWriteTokens: num(c.usage, "cache_creation_input_tokens"),
		},
		stop: claudeStop(c.stopReason),
	}
	return out, true, nil
}

func claudeStop(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence":
		return StopEnd
	case "tool_use":
		return StopTool
	case "max_tokens":
		return StopLength
	case "refusal":
		return StopRefusal
	}
	return StopError
}

// Codex

type codexTurn struct {
	items    []any
	response map[string]any
	status   string
	terminal bool
}

func (c *codexTurn) feed(ev map[string]any) error {
	switch t := str(ev, "type"); t {
	case "response.output_item.done":
		if item := ev["item"]; item != nil {
			c.items = append(c.items, item)
		}
	case "response.completed", "response.incomplete", "response.failed":
		r := obj(ev, "response")
		if r == nil {
			return fail(CodeUnavailable)
		}
		c.response, c.status, c.terminal = r, t, true
	case "error":
		return fail(CodeUnavailable)
	}
	return nil
}

func (c *codexTurn) result() (turnResult, bool, error) {
	if !c.terminal {
		return turnResult{}, false, nil
	}
	output := arr(c.response, "output")
	if len(output) == 0 {
		output = c.items
	}
	c.response["output"] = output
	state, err := json.Marshal(map[string]any{"output": output})
	if err != nil {
		return turnResult{}, false, err
	}
	response, err := json.Marshal(c.response)
	if err != nil {
		return turnResult{}, false, err
	}
	u := obj(c.response, "usage")
	out := turnResult{
		response: response,
		state:    state,
		usage: Usage{
			InputTokens:     num(u, "input_tokens"),
			OutputTokens:    num(u, "output_tokens"),
			CacheReadTokens: num(obj(u, "input_tokens_details"), "cached_tokens"),
			ReasoningTokens: num(obj(u, "output_tokens_details"), "reasoning_tokens"),
		},
		stop: codexStop(c.status, c.response, output),
	}
	return out, true, nil
}

func codexStop(status string, resp map[string]any, output []any) string {
	if status == "response.failed" {
		return StopError
	}
	if hasRefusal(output) {
		return StopRefusal
	}
	if status == "response.incomplete" {
		switch str(obj(resp, "incomplete_details"), "reason") {
		case "max_output_tokens":
			return StopLength
		case "content_filter":
			return StopRefusal
		}
		return StopError
	}
	if hasItemType(output, "function_call") {
		return StopTool
	}
	return StopEnd
}

func hasRefusal(output []any) bool {
	for _, it := range output {
		item, _ := it.(map[string]any)
		if str(item, "type") != "message" {
			continue
		}
		for _, p := range arr(item, "content") {
			if part, _ := p.(map[string]any); str(part, "type") == "refusal" {
				return true
			}
		}
	}
	return false
}

func hasItemType(items []any, t string) bool {
	for _, it := range items {
		if m, _ := it.(map[string]any); str(m, "type") == t {
			return true
		}
	}
	return false
}

// Antigravity (Gemini-shaped candidates)

type geminiTurn struct {
	parts    map[int][]any
	finish   map[int]string
	role     string
	cands    int
	usage    map[string]any
	feedback map[string]any
}

func (g *geminiTurn) feed(ev map[string]any) error {
	body := ev
	if r := obj(ev, "response"); r != nil {
		body = r
	}
	if _, ok := body["error"]; ok {
		return fail(CodeUnavailable)
	}
	if u := obj(body, "usageMetadata"); u != nil {
		g.usage = u
	}
	if raw, present := body["promptFeedback"]; present && raw != nil {
		feedback, ok := raw.(map[string]any)
		if !ok {
			return fail(CodeUnavailable)
		}
		if reason, present := feedback["blockReason"]; present && reason != nil {
			if _, ok := reason.(string); !ok {
				return fail(CodeUnavailable)
			}
		}
		g.feedback = feedback
	}
	candidates := arr(body, "candidates")
	if raw, present := body["candidates"]; present && raw != nil && candidates == nil {
		return fail(CodeUnavailable)
	}
	for i, raw := range candidates {
		cand, ok := raw.(map[string]any)
		if !ok || i >= maxCandidates {
			return fail(CodeUnavailable)
		}
		if i+1 > g.cands {
			g.cands = i + 1
		}
		if content := obj(cand, "content"); content != nil {
			if r := str(content, "role"); r != "" {
				g.role = r
			}
			g.parts[i] = append(g.parts[i], arr(content, "parts")...)
		}
		if fr := str(cand, "finishReason"); fr != "" {
			g.finish[i] = fr
		}
	}
	return nil
}

// Tool calls can terminate at clean EOF; text requires a native finish marker.
func (g *geminiTurn) result() (turnResult, bool, error) {
	reason := str(g.feedback, "blockReason")
	blocked := reason != "" && reason != "BLOCK_REASON_UNSPECIFIED" && strings.TrimSpace(reason) == reason
	if g.cands == 0 && !blocked {
		return turnResult{}, false, nil
	}
	if g.cands > 0 && blocked {
		return turnResult{}, false, fail(CodeUnavailable)
	}
	for i := range g.cands {
		if g.finish[i] == "" && !hasFunctionCall(g.parts[i]) {
			return turnResult{}, false, nil
		}
	}
	contents := make([]any, 0, g.cands)
	respCands := make([]any, 0, g.cands)
	for i := range g.cands {
		parts := g.parts[i]
		if parts == nil {
			parts = []any{}
		}
		content := map[string]any{"role": g.role, "parts": parts}
		contents = append(contents, map[string]any{"index": i, "content": content})
		rc := map[string]any{"index": i, "content": content}
		if fr, ok := g.finish[i]; ok {
			rc["finishReason"] = fr
		}
		respCands = append(respCands, rc)
	}
	usage := g.usage
	if usage == nil {
		usage = map[string]any{}
	}
	stateBody := map[string]any{"candidates": contents}
	responseBody := map[string]any{"candidates": respCands, "usageMetadata": usage}
	if g.feedback != nil {
		stateBody["promptFeedback"] = g.feedback
		responseBody["promptFeedback"] = g.feedback
	}
	state, err := json.Marshal(stateBody)
	if err != nil {
		return turnResult{}, false, err
	}
	response, err := json.Marshal(responseBody)
	if err != nil {
		return turnResult{}, false, err
	}
	stop := StopEnd
	if blocked {
		stop = StopRefusal
	} else if fr, ok := g.finish[0]; ok {
		stop = geminiStop(fr, g.parts[0])
	} else if hasFunctionCall(g.parts[0]) {
		stop = StopTool
	}
	out := turnResult{
		response: response,
		state:    state,
		usage: Usage{
			InputTokens:     num(usage, "promptTokenCount"),
			OutputTokens:    num(usage, "candidatesTokenCount"),
			CacheReadTokens: num(usage, "cachedContentTokenCount"),
			ReasoningTokens: num(usage, "thoughtsTokenCount"),
		},
		stop: stop,
	}
	return out, true, nil
}

func geminiStop(fr string, parts []any) string {
	switch fr {
	case "STOP":
		if hasFunctionCall(parts) {
			return StopTool
		}
		return StopEnd
	case "MAX_TOKENS":
		return StopLength
	case "SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII":
		return StopRefusal
	}
	return StopError
}

func hasFunctionCall(parts []any) bool {
	for _, p := range parts {
		if m, ok := p.(map[string]any); ok {
			if _, ok := m["functionCall"]; ok {
				return true
			}
		}
	}
	return false
}

// chatTurn folds [OI] chat-completion frames. A local upstream may answer with one
// whole object or with SSE deltas, so both carry the text in a nested object that
// this reads the same way: "message" for a complete response, "delta" for a chunk.
type chatTurn struct {
	content   strings.Builder
	reasoning strings.Builder
	// toolCalls are keyed by the call's index: a streaming server sends one call's id
	// and name once and then its arguments as successive fragments under the same
	// index, so each fragment must extend the existing call rather than start a new
	// one. Appending per fragment would emit one tool call per character.
	toolCalls map[int]*pendingCall
	order     []int
	finish    string
	usage     Usage
	seen      bool
}

// pendingCall is one tool call being assembled from its fragments.
type pendingCall struct {
	id      string
	name    string
	args    strings.Builder
	hasArgs bool
}

func (c *chatTurn) feed(ev map[string]any) error {
	if e := obj(ev, "error"); e != nil {
		return fail(CodeUnavailable)
	}
	// A local server may report its counters as "timings" instead of an [OI] usage
	// object: prompt_n are the tokens it had to read, cache_n the ones it reused from
	// the prefix cache. Reading both keeps the turn's accounting honest either way.
	if t := obj(ev, "timings"); t != nil {
		cached, read, predicted := intOf(t["cache_n"]), intOf(t["prompt_n"]), intOf(t["predicted_n"])
		if read+cached+predicted > 0 {
			c.usage.CacheReadTokens = cached
			c.usage.InputTokens = read + cached
			c.usage.OutputTokens = predicted
		}
	}
	if u := obj(ev, "usage"); u != nil {
		c.usage.InputTokens = intOf(u["prompt_tokens"])
		c.usage.OutputTokens = intOf(u["completion_tokens"])
		if details := obj(u, "prompt_tokens_details"); details != nil {
			c.usage.CacheReadTokens = intOf(details["cached_tokens"])
		}
		if details := obj(u, "completion_tokens_details"); details != nil {
			c.usage.ReasoningTokens = intOf(details["reasoning_tokens"])
		}
	}
	for _, raw := range arr(ev, "choices") {
		choice, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		c.seen = true
		part := obj(choice, "delta")
		if part == nil {
			part = obj(choice, "message")
		}
		if part != nil {
			c.content.WriteString(str(part, "content"))
			c.reasoning.WriteString(str(part, "reasoning_content"))
			for pos, raw := range arr(part, "tool_calls") {
				call, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				// The index decides which call a fragment belongs to. Decoded numbers are
				// json.Number (the decoder disables float64 coercion), so both forms are
				// read here; missing one would silently merge every call into slot 0.
				idx, indexed := intValue(call["index"])
				if !indexed {
					idx = pos
				}
				id := str(call, "id")
				pending, exists := c.toolCalls[idx]
				// Only when the server sends no index at all: a fresh id on an occupied
				// slot starts a new call, rather than concatenating several calls'
				// arguments into one entry the server cannot parse.
				if !indexed && exists && id != "" && pending.id != "" && id != pending.id {
					idx = len(c.order)
					pending, exists = c.toolCalls[idx]
				}
				if !exists {
					pending = &pendingCall{}
					c.toolCalls[idx] = pending
					c.order = append(c.order, idx)
				}
				if id != "" {
					pending.id = id
				}
				if fn := obj(call, "function"); fn != nil {
					if name := str(fn, "name"); name != "" {
						pending.name = name
					}
					// Arguments arrive split across fragments, in order.
					if frag := str(fn, "arguments"); frag != "" {
						pending.args.WriteString(frag)
						pending.hasArgs = true
					}
				}
			}
		}
		if finish := str(choice, "finish_reason"); finish != "" {
			c.finish = finish
		}
	}
	return nil
}

func (c *chatTurn) result() (turnResult, bool, error) {
	if !c.seen {
		return turnResult{}, false, nil
	}
	message := map[string]any{"role": "assistant", "content": c.content.String()}
	if c.reasoning.Len() > 0 {
		message["reasoning_content"] = c.reasoning.String()
	}
	if len(c.order) > 0 {
		calls := make([]any, 0, len(c.order))
		for _, idx := range c.order {
			pending := c.toolCalls[idx]
			if pending == nil || pending.name == "" {
				// A fragment without a name never became a usable call; dropping it is
				// better than sending a call the server cannot dispatch.
				continue
			}
			args := pending.args.String()
			if !pending.hasArgs || strings.TrimSpace(args) == "" {
				// A no-argument tool still needs a JSON object on the wire.
				args = "{}"
			}
			calls = append(calls, map[string]any{
				"id": pending.id, "type": "function",
				"function": map[string]any{"name": pending.name, "arguments": args},
			})
		}
		if len(calls) > 0 {
			message["tool_calls"] = calls
		}
	}
	response, err := json.Marshal(message)
	if err != nil {
		return turnResult{}, false, fail(CodeUnavailable)
	}
	// The replay state is the assistant message itself: a stateless local model has
	// nothing else to carry between turns, and keeping it lets a retried turn replay
	// exactly what the model said.
	return turnResult{response: response, state: response, usage: c.usage, stop: localStop(c.finish)}, true, nil
}

// intOf reads a JSON number in any representation the decoders produce.
func intOf(v any) int {
	n, ok := intValue(v)
	if !ok {
		return 0
	}
	return n
}

// intValue reports a whole number as an int, accepting the json.Number the
// use-number decoder produces as well as a plain float or int.
func intValue(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
		if f, err := n.Float64(); err == nil {
			return int(f), true
		}
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// localStop maps a chat-completion finish_reason onto the native terminal vocabulary
// the host contract uses. Sending the raw value would fail admission downstream, since
// "stop" is not one of the four terminal reasons the native protocol defines.
func localStop(finish string) string {
	switch strings.ToLower(strings.TrimSpace(finish)) {
	case "tool_calls", "function_call":
		return "tool"
	case "length":
		return "length"
	case "content_filter":
		return "refusal"
	default:
		return "end"
	}
}

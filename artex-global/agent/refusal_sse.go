package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/structuredstanza/AgentLab/artex-global/llmrec"
	"github.com/structuredstanza/norma/llm"
)

// sseMaxLine bounds the per-line buffer. Longer lines are skipped without
// classification so a hostile or huge event cannot grow memory unboundedly.
const sseMaxLine = 64 << 10

// observeRefusalSSE wraps a 200 text/event-stream body. It marks the call's
// refusal sink when an explicit native refusal signal passes through. Bytes,
// read errors and Close are passed through unchanged; the observer never
// alters or swallows what the consumer sees.
func observeRefusalSSE(ctx context.Context, format llm.Format, body io.ReadCloser) io.ReadCloser {
	return &refusalSSEBody{ctx: ctx, format: format, body: body}
}

type refusalSSEBody struct {
	ctx    context.Context
	format llm.Format
	body   io.ReadCloser
	line   []byte
	skip   bool // current line overflowed sseMaxLine; discard until newline
	marked bool
}

func (b *refusalSSEBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	b.scan(p[:n])
	if err == io.EOF {
		// A trailing unterminated line is complete at EOF.
		b.endLine()
	}
	if err != nil && err != io.EOF {
		// A transport error means the final partial line is not trustworthy.
		b.line, b.skip = b.line[:0], false
	}
	return n, err
}

func (b *refusalSSEBody) Close() error { return b.body.Close() }

func (b *refusalSSEBody) scan(chunk []byte) {
	for len(chunk) > 0 {
		seg, rest, hasNL := chunk, []byte(nil), false
		if i := bytes.IndexByte(chunk, '\n'); i >= 0 {
			seg, rest, hasNL = chunk[:i], chunk[i+1:], true
		}
		if !b.skip {
			if len(b.line)+len(seg) > sseMaxLine {
				b.skip = true
				b.line = b.line[:0]
			} else {
				b.line = append(b.line, seg...)
			}
		}
		if !hasNL {
			return
		}
		b.endLine()
		chunk = rest
	}
}

func (b *refusalSSEBody) endLine() {
	if !b.skip && len(b.line) > 0 {
		b.classify(b.line)
	}
	b.line, b.skip = b.line[:0], false
}

func (b *refusalSSEBody) classify(line []byte) {
	if b.marked {
		return
	}
	data, ok := bytes.CutPrefix(line, []byte("data:"))
	if !ok {
		return
	}
	if sseRefusalEvent(b.format, bytes.TrimSpace(data)) {
		b.marked = true
		llmrec.MarkRefusal(b.ctx)
	}
}

// sseRefusalEvent reports whether one SSE data payload carries an explicit
// native refusal signal for the wire format. It never inspects prose.
func sseRefusalEvent(format llm.Format, data []byte) bool {
	switch format {
	case llm.FormatAnthropic:
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		return json.Unmarshal(data, &ev) == nil && ev.Type == "message_delta" && ev.Delta.StopReason == "refusal"
	case llm.FormatOpenAI:
		var ev struct {
			Choices []struct {
				FinishReason string `json:"finish_reason"`
				Delta        struct {
					Refusal string `json:"refusal"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(data, &ev) != nil {
			return false
		}
		for _, c := range ev.Choices {
			if c.Delta.Refusal != "" || c.FinishReason == "content_filter" {
				return true
			}
		}
	case llm.FormatOpenAIResponses:
		var ev struct {
			Type string `json:"type"`
			Part struct {
				Type string `json:"type"`
			} `json:"part"`
			Item struct {
				Content []refusalPartType `json:"content"`
			} `json:"item"`
			Response struct {
				IncompleteDetails struct {
					Reason string `json:"reason"`
				} `json:"incomplete_details"`
				Output []struct {
					Content []refusalPartType `json:"content"`
				} `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal(data, &ev) != nil {
			return false
		}
		switch ev.Type {
		case "response.refusal.delta", "response.refusal.done":
			return true
		case "response.content_part.added", "response.content_part.done":
			return ev.Part.Type == "refusal"
		case "response.output_item.added", "response.output_item.done":
			return hasRefusalPart(ev.Item.Content)
		case "response.incomplete", "response.completed":
			if ev.Response.IncompleteDetails.Reason == "content_filter" {
				return true
			}
			for _, out := range ev.Response.Output {
				if hasRefusalPart(out.Content) {
					return true
				}
			}
		}
	}
	return false
}

type refusalPartType struct {
	Type string `json:"type"`
}

func hasRefusalPart(parts []refusalPartType) bool {
	for _, p := range parts {
		if p.Type == "refusal" {
			return true
		}
	}
	return false
}

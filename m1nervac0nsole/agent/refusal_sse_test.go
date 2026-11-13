package agent

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/llmrec"
	"github.com/structuredstanza/norma/llm"
)

func TestObserveRefusalSSESignals(t *testing.T) {
	cases := []struct {
		name   string
		format llm.Format
		body   string
		want   bool
	}{
		{"anthropic refusal stop", llm.FormatAnthropic, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\"}}\n\n", true},
		{"anthropic end_turn", llm.FormatAnthropic, "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n", false},
		{"anthropic text mentions refusal", llm.FormatAnthropic, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"refusal\"}}\n\n", false},
		{"chat refusal delta", llm.FormatOpenAI, "data: {\"choices\":[{\"delta\":{\"refusal\":\"I cannot\"}}]}\n\n", true},
		{"chat content filter", llm.FormatOpenAI, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"content_filter\"}]}\n\n", true},
		{"chat normal with null refusal", llm.FormatOpenAI, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\",\"refusal\":null},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n", false},
		{"chat crlf endings", llm.FormatOpenAI, "data: {\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}\r\n\r\n", true},
		{"chat missing data prefix", llm.FormatOpenAI, "{\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}\n", false},
		{"chat partial last line at EOF", llm.FormatOpenAI, "data: {\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}", true},
		{"chat invalid json", llm.FormatOpenAI, "data: {bad\n", false},
		{"wrong format for payload", llm.FormatAnthropic, "data: {\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}\n", false},
		{"responses refusal delta", llm.FormatOpenAIResponses, "data: {\"type\":\"response.refusal.delta\",\"delta\":\"no\"}\n\n", true},
		{"responses refusal content part", llm.FormatOpenAIResponses, "data: {\"type\":\"response.content_part.added\",\"part\":{\"type\":\"refusal\"}}\n\n", true},
		{"responses refusal output item", llm.FormatOpenAIResponses, "data: {\"type\":\"response.output_item.done\",\"item\":{\"content\":[{\"type\":\"refusal\"}]}}\n\n", true},
		{"responses incomplete content filter", llm.FormatOpenAIResponses, "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"content_filter\"}}}\n\n", true},
		{"responses completed with refusal part", llm.FormatOpenAIResponses, "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"content\":[{\"type\":\"refusal\"}]}]}}\n\n", true},
		{"responses text delta", llm.FormatOpenAIResponses, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"refusal\"}\n\n", false},
	}
	for _, tc := range cases {
		for _, reader := range []struct {
			name string
			wrap func(string) io.Reader
		}{
			{"whole", func(s string) io.Reader { return strings.NewReader(s) }},
			{"one byte per read", func(s string) io.Reader { return iotest.OneByteReader(strings.NewReader(s)) }},
		} {
			t.Run(tc.name+"/"+reader.name, func(t *testing.T) {
				ctx := llmrec.WithRefusalSink(context.Background())
				body := io.NopCloser(reader.wrap(tc.body))
				out, err := io.ReadAll(observeRefusalSSE(ctx, tc.format, body))
				if err != nil {
					t.Fatal(err)
				}
				if string(out) != tc.body {
					t.Fatalf("observer altered bytes: %q", out)
				}
				if got := llmrec.RefusalObserved(ctx); got != tc.want {
					t.Fatalf("observed=%v want %v", got, tc.want)
				}
			})
		}
	}
}

// errAfterReader yields data and then a transport error instead of EOF.
type errAfterReader struct {
	data []byte
	err  error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *errAfterReader) Close() error { return nil }

func TestObserveRefusalSSEPropagatesReadError(t *testing.T) {
	boom := errors.New("connection reset")
	ctx := llmrec.WithRefusalSink(context.Background())
	body := &errAfterReader{data: []byte("data: {\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}\n"), err: boom}
	if _, err := io.ReadAll(observeRefusalSSE(ctx, llm.FormatOpenAI, body)); !errors.Is(err, boom) {
		t.Fatalf("read error not propagated: %v", err)
	}
}

func TestObserveRefusalSSEDropsTruncatedLineOnTransportError(t *testing.T) {
	boom := errors.New("connection reset")
	ctx := llmrec.WithRefusalSink(context.Background())
	body := &errAfterReader{data: []byte("data: {\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}"), err: boom}
	if _, err := io.ReadAll(observeRefusalSSE(ctx, llm.FormatOpenAI, body)); !errors.Is(err, boom) {
		t.Fatalf("read error not propagated: %v", err)
	}
	if llmrec.RefusalObserved(ctx) {
		t.Fatal("unterminated line cut by a transport error must not be classified")
	}
}

func TestObserveRefusalSSESkipsOverlongLine(t *testing.T) {
	long := "data: {\"pad\":\"" + strings.Repeat("a", sseMaxLine) + "\"}\n"
	body := long + "data: {\"choices\":[{\"delta\":{\"refusal\":\"x\"}}]}\n"
	ctx := llmrec.WithRefusalSink(context.Background())
	out, err := io.ReadAll(observeRefusalSSE(ctx, llm.FormatOpenAI, io.NopCloser(strings.NewReader(body))))
	if err != nil || string(out) != body {
		t.Fatalf("bytes or error changed: err=%v", err)
	}
	if !llmrec.RefusalObserved(ctx) {
		t.Fatal("line after an overlong line must still be classified")
	}
}

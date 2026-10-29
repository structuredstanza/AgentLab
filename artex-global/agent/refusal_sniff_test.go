package agent

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestRefusalInRawResponse(t *testing.T) {
	cases := []struct {
		name   string
		format llm.Format
		body   string
		want   bool
	}{
		{"anthropic refusal", llm.FormatAnthropic, `{"stop_reason":"refusal"}`, true},
		{"anthropic normal", llm.FormatAnthropic, `{"stop_reason":"end_turn"}`, false},
		{"chat message refusal", llm.FormatOpenAI, `{"choices":[{"message":{"refusal":"I cannot"}}]}`, true},
		{"chat content filter", llm.FormatOpenAI, `{"choices":[{"finish_reason":"content_filter"}]}`, true},
		{"chat normal", llm.FormatOpenAI, `{"choices":[{"finish_reason":"stop","message":{"content":"ok"}}]}`, false},
		{"responses content filter", llm.FormatOpenAIResponses, `{"status":"incomplete","incomplete_details":{"reason":"content_filter"}}`, true},
		{"responses refusal part", llm.FormatOpenAIResponses, `{"output":[{"content":[{"type":"refusal","refusal":"no"}]}]}`, true},
		{"responses normal", llm.FormatOpenAIResponses, `{"status":"completed","output":[]}`, false},
		{"invalid", llm.FormatOpenAI, `{`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RefusalInRawResponse(tc.format, []byte(tc.body)); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

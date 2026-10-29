package agent

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/norma/llm"
)

// RefusalInRawResponse detects refusal signals from complete raw provider responses.
// The provider RoundTrip integration calls this before decoding the response body.
func RefusalInRawResponse(format llm.Format, body []byte) bool {
	var v map[string]json.RawMessage
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	switch format {
	case llm.FormatAnthropic:
		var reason string
		return json.Unmarshal(v["stop_reason"], &reason) == nil && reason == "refusal"
	case llm.FormatOpenAI:
		var choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Refusal string `json:"refusal"`
			} `json:"message"`
		}
		if json.Unmarshal(v["choices"], &choices) != nil {
			return false
		}
		for _, c := range choices {
			if c.Message.Refusal != "" || c.FinishReason == "content_filter" {
				return true
			}
		}
	case llm.FormatOpenAIResponses:
		var status string
		_ = json.Unmarshal(v["status"], &status)
		if status == "incomplete" {
			var details struct {
				Reason string `json:"reason"`
			}
			if json.Unmarshal(v["incomplete_details"], &details) == nil && details.Reason == "content_filter" {
				return true
			}
		}
		var output []struct {
			Content []struct {
				Type string `json:"type"`
			} `json:"content"`
		}
		if json.Unmarshal(v["output"], &output) == nil {
			for _, item := range output {
				for _, part := range item.Content {
					if part.Type == "refusal" {
						return true
					}
				}
			}
		}
	}
	return false
}

type workerSessionSuffixKey struct{}

// WithWorkerSessionSuffix gives a replay a separate transcript instead of
// resuming the assistant response that triggered it.
func WithWorkerSessionSuffix(ctx context.Context, suffix string) context.Context {
	return context.WithValue(ctx, workerSessionSuffixKey{}, suffix)
}

func workerSessionSuffix(ctx context.Context) string {
	suffix, _ := ctx.Value(workerSessionSuffixKey{}).(string)
	return suffix
}

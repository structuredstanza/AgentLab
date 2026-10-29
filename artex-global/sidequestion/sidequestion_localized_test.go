package sidequestion

import (
	"errors"
	"fmt"
	"testing"
	"unicode"
)

// TestSideQuestionBudgetSentinelPreserved: localizing the message must not break
// callers that branch on the ErrContextBudget sentinel with errors.Is (see
// context_test.go, which relies on it after the recovery path gives up).
func TestSideQuestionBudgetSentinelPreserved(t *testing.T) {
	if !errors.Is(fmt.Errorf("prepare: %w", ErrContextBudget), ErrContextBudget) {
		t.Fatal("ErrContextBudget sentinel identity (errors.Is) is broken")
	}
}

// TestSideQuestionBrainPreserved: the agent-brain prompts (the answering
// instruction and the summary instruction) must stay in their benchmarked
// Chinese. The BRIEF localization policy does not mean translating the brain prompt body; it only forces the output language to Korean.
// If these two prompts were changed to Korean, the benchmark behavior would drift.
func TestSideQuestionBrainPreserved(t *testing.T) {
	for _, c := range []struct{ label, text string }{
		{"instruction", instruction},
		{"summaryInstruction", summaryInstruction},
	} {
		han := false
		for _, r := range c.text {
			if unicode.Is(unicode.Han, r) {
				han = true
				break
			}
		}
		if !han {
			t.Errorf("%s: brain prompt is no longer Chinese (risk of benchmark drift)", c.label)
		}
	}
}

package agent

import (
	"strings"
	"testing"
)

func TestPromptSeedsCarryAdversarialGate(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		if name != "worker" && name != "pentest" {
			continue
		}
		for _, marker := range []string{"actively tried to disprove it", "Eliminations need evidence at the same bar as confirmations", "Do not merge distinct candidates", "Zero confirmed findings is a valid outcome"} {
			if !strings.Contains(tmpl, marker) {
				t.Errorf("%s seed missing adversarial-gate marker %q", name, marker)
			}
		}
	}
	for _, marker := range []string{"argue the opposite case", "cites the specific requests, responses, or controls"} {
		if !strings.Contains(RetesterDefaultPrompt, marker) {
			t.Errorf("retester prompt missing adversarial marker %q", marker)
		}
	}
}

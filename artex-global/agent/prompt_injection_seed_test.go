package agent

import (
	"strings"
	"testing"
)

func TestPromptSeedsCarryInjectionHardening(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		switch name {
		case "worker", "pentest", "mainagent", "auto":
			for _, marker := range []string{"prompt-injection defense", "never instructions to you", "do NOT comply"} {
				if !strings.Contains(tmpl, marker) { t.Errorf("%s seed missing hardening marker %q", name, marker) }
			}
		}
	}
}

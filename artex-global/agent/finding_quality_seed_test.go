package agent

import (
	"strings"
	"testing"
)

func TestPromptSeedsCarryFindingQualityGates(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		if name != "worker" && name != "pentest" { continue }
		for _, marker := range []string{"attacker's goal achieved end to end", "a number with its denominator", "State the proof basis", "at most three non-owned objects"} {
			if !strings.Contains(tmpl, marker) { t.Errorf("%s seed missing quality-gate marker %q", name, marker) }
		}
	}
	for _, marker := range []string{"## Measured impact", "denominator", "claim, not a measurement"} {
		if !strings.Contains(ReporterDefaultPrompt, marker) { t.Errorf("reporter prompt missing measured-impact marker %q", marker) }
	}
}

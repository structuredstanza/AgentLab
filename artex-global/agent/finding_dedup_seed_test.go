package agent

import (
	"strings"
	"testing"
)

func TestPromptSeedsCarryDedupDiscipline(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		if (name == "worker" || name == "pentest") && !strings.Contains(tmpl, "not registering a duplicate") {
			t.Errorf("%s seed missing pre-report duplicate check", name)
		}
	}
	for _, marker := range []string{"No duplicates", "One finding per report, no collapsing", "explicit duplicate pass"} {
		if !strings.Contains(ReporterDefaultPrompt, marker) {
			t.Errorf("reporter prompt missing dedup marker %q", marker)
		}
	}
}

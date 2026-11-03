package agent

import (
	"strings"
	"testing"
)

func TestPromptSeedsCarryDeadlineContract(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		if name != "worker" && name != "pentest" { continue }
		for _, marker := range []string{"timeout can outlive", "prefer the smaller variant that lands"} {
			if !strings.Contains(tmpl, marker) { t.Errorf("%s seed missing deadline-contract marker %q", name, marker) }
		}
	}
}

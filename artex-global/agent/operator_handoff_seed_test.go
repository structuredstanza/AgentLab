package agent

import (
	"strings"
	"testing"
)

func TestPromptSeedsCarryOperatorHandoff(t *testing.T) {
	for name, tmpl := range BuiltinPromptSeeds() {
		if name != "worker" && name != "pentest" { continue }
		for _, marker := range []string{"Operator handoff on environmental blocks", "one line, copy-pastable", "never batch"} {
			if !strings.Contains(tmpl, marker) { t.Errorf("%s seed missing operator-handoff marker %q", name, marker) }
		}
	}
}

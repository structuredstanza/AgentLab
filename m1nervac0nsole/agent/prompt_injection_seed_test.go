package agent

import (
	"strings"
	"testing"
)

func TestRoleSystemPromptsKeepDefensiveGuidance(t *testing.T) {
	prev := PromptOverride
	t.Cleanup(func() { PromptOverride = prev })
	dir := t.TempDir()
	roles := map[string]func() string{
		"goals":     func() string { return goalsSystem(dir, true) },
		"planner":   func() string { return plannerSystem("goal", dir, dir) },
		"worker":    func() string { return workerSystem("", "", dir, dir) },
		"mainagent": func() string { return mainAgentSystem("goal", dir, dir) },
	}
	for _, role := range []string{"auto", "pentest", "reporter", "curator", "drafter", "toolcurator", "custom"} {
		roles[role] = func() string { return chatSystem(role, dir) }
	}
	for role, build := range roles {
		t.Run(role, func(t *testing.T) {
			for _, tmpl := range []string{"", "Stored body for {{.DataDir}}.", "{{.UnknownField}}"} {
				PromptOverride = func(key string) (string, bool) { return tmpl, key == role && tmpl != "" }
				got := build()
				if strings.Count(got, defensiveSystemGuidance) != 1 {
					t.Fatalf("defensive guidance must be present exactly once for template %q", tmpl)
				}
				if tmpl == "Stored body for {{.DataDir}}." && !strings.Contains(got, "Stored body for "+dir+".") {
					t.Fatal("guidance must not replace a valid stored template")
				}
				if role == "reporter" && !strings.Contains(got, reporterEvidenceGuidance) {
					t.Fatal("stored or fallback reporter prompts must include the evidence boundary")
				}
			}
		})
	}
}

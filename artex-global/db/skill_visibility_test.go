package db

import "testing"

// recon-orchestration must ship visible to the agents that hold run_tool.
//
// It was absent from builtinSkillVisibility, so no agent saw it by default —
// the skill explaining how to choose and drive a manifest tool never reached the
// agents the tool was bound to. Binding run_tool without it left the model to
// rediscover the tool ranking itself, or skip it and hand-build a Bash command.
func TestReconOrchestrationShipsVisibleToExecutingAgents(t *testing.T) {
	// The declaration itself, independent of any database state.
	for _, key := range []string{"auto", "pentest", "worker", "planner"} {
		if !containsStr(builtinSkillVisibility["recon-orchestration"], key) {
			t.Errorf("recon-orchestration is not declared for %q (got %v)",
				key, builtinSkillVisibility["recon-orchestration"])
		}
	}

	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	// Clear the rows so the seed has to create them; the seed only inserts, so a
	// database that already ran it would otherwise pass regardless of the map.
	if _, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE skill_name='recon-orchestration'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM agent_skill_visibility WHERE skill_name='recon-orchestration'`)
	})

	if err := d.seedBuiltinSkillVisibility(); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"auto", "pentest", "worker", "planner"} {
		ag, err := d.GetAgentByKey(key)
		if err != nil || ag == nil {
			t.Fatalf("agent %q missing: %v", key, err)
		}
		got, err := d.AgentSkillNames(ag.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !containsStr(got, "recon-orchestration") {
			t.Errorf("%s cannot see recon-orchestration (has %v)", key, got)
		}
	}

	// mainagent is the human interface and does not run scans; the seed must not
	// bind every skill to every agent.
	if ag, err := d.GetAgentByKey("mainagent"); err == nil && ag != nil {
		got, _ := d.AgentSkillNames(ag.ID)
		if containsStr(got, "recon-orchestration") {
			t.Errorf("mainagent should not get recon-orchestration, has %v", got)
		}
	}
	// A skill that ships invisible stays invisible.
	if ag, err := d.GetAgentByKey("worker"); err == nil && ag != nil {
		got, _ := d.AgentSkillNames(ag.ID)
		if containsStr(got, "scopesentry") {
			t.Errorf("scopesentry should ship invisible, worker has %v", got)
		}
	}
}

// Turning a skill off must survive a restart.
//
// The seed runs on every startup. ToggleSkillVisibility(off) used to DELETE the
// row, which erased the only record of the user's decision, so the seed inserted
// the skill straight back — silently undoing the toggle-off.
func TestSkillToggleOffSurvivesReseed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	ag, err := d.GetAgentByKey("worker")
	if err != nil || ag == nil {
		t.Skipf("worker agent not seeded (%v)", err)
	}
	const skill = "api-recon"

	if err := d.seedBuiltinSkillVisibility(); err != nil {
		t.Fatal(err)
	}
	orig, _ := d.AgentSkillNames(ag.ID)
	t.Cleanup(func() { _ = d.SetAgentSkillVisibility(ag.ID, orig) })

	if err := d.ToggleSkillVisibility(ag.ID, skill, false); err != nil {
		t.Fatal(err)
	}
	if names, _ := d.AgentSkillNames(ag.ID); containsStr(names, skill) {
		t.Fatalf("%s still visible immediately after toggle-off", skill)
	}

	// Restart: the seed runs again and must not resurrect it.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		t.Fatal(err)
	}
	if names, _ := d.AgentSkillNames(ag.ID); containsStr(names, skill) {
		t.Fatalf("%s was resurrected by the seed after the user turned it off", skill)
	}

	// The same must hold for the replace-all path the UI uses: dropping a skill
	// from the list is a decision, not an absence of one.
	if err := d.SetAgentSkillVisibility(ag.ID, []string{"recon-orchestration"}); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		t.Fatal(err)
	}
	names, _ := d.AgentSkillNames(ag.ID)
	if containsStr(names, skill) {
		t.Fatalf("%s was resurrected after being dropped from the visibility list", skill)
	}
	if !containsStr(names, "recon-orchestration") {
		t.Errorf("recon-orchestration was lost; have %v", names)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

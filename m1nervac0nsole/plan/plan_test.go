package plan

import (
	"strings"
	"testing"
)

func valid() Proposal {
	return Proposal{
		Summary: "Enumerate the web tier, then test the login for injection.",
		Goals: []Goal{
			{Ref: "g1", Text: "Map every reachable HTTP service on the web tier"},
			{Ref: "g2", Text: "Prove or disprove SQL injection in the login form"},
		},
		Intents: []Intent{
			{Ref: "i1", Goal: "g1", Summary: "Fingerprint the web tier and enumerate paths", AssetIDs: []int64{1, 2}},
			{Ref: "i2", Goal: "g2", Summary: "Test the login form for SQL injection", AssetIDs: []int64{2}, DependsOn: []string{"i1"}},
		},
		Hints: []Hint{{Text: "Stay under 5 requests per second", Rule: true}},
		Scope: []Scope{{Effect: "exclude", Kind: "root_domain", Value: "thirdparty.example", Note: "vendor"}},
	}
}

func TestValidateAcceptsAWellFormedProposal(t *testing.T) {
	if errs := Validate(valid(), Context{AssetIDs: map[int64]bool{1: true, 2: true}}); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	p := valid()
	p.Summary = ""
	p.Goals[0].Text = ""
	p.Intents[0].Goal = "nope"
	p.Intents[1].DependsOn = []string{"i2"}
	p.Intents[1].AssetIDs = []int64{99}
	p.Hints[0].Text = ""
	p.Scope[0].Effect = "maybe"
	p.Scope[0].Kind = "asn"

	errs := Validate(p, Context{AssetIDs: map[int64]bool{1: true, 2: true}})
	joined := errorsText(errs)
	for _, want := range []string{
		"summary is empty",
		"goals[0].text is empty",
		"intents[0].goal \"nope\" is not a goal",
		"intents[1].depends_on names itself",
		"asset_ids has 99",
		"hints[0].text is empty",
		"scope[0].effect is \"maybe\"",
		"scope[0].kind is \"asn\"",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestValidateRejectsDuplicateRefsAcrossKinds(t *testing.T) {
	p := valid()
	p.Intents[0].Ref = "g1"
	errs := Validate(p, Context{})
	if !strings.Contains(errorsText(errs), `"g1" is already used by a goal`) {
		t.Fatalf("duplicate ref not reported: %v", errs)
	}
}

func TestValidateRejectsCycles(t *testing.T) {
	p := valid()
	p.Intents[0].DependsOn = []string{"i2"}
	errs := Validate(p, Context{})
	if !strings.Contains(errorsText(errs), "cycle") {
		t.Fatalf("cycle not reported: %v", errs)
	}
}

func TestValidateEnforcesLimits(t *testing.T) {
	p := valid()
	p.Intents = nil
	for i := 0; i < 4; i++ {
		p.Intents = append(p.Intents, Intent{Ref: "x" + string(rune('a'+i)), Goal: "g1", Summary: "s"})
	}
	errs := Validate(p, Context{Limits: Limits{Goals: 8, Intents: 3, Hints: 16, Scope: 32}})
	if !strings.Contains(errorsText(errs), "4 intents, the limit is 3") {
		t.Fatalf("limit not enforced: %v", errs)
	}
}

func TestValidateRejectsAnEmptyProposal(t *testing.T) {
	errs := Validate(Proposal{Summary: "nothing"}, Context{})
	if !strings.Contains(errorsText(errs), "would create nothing") {
		t.Fatalf("empty proposal accepted: %v", errs)
	}
}

func TestValidateSkipsAssetMembershipWhenUnknown(t *testing.T) {
	p := valid()
	p.Intents[0].AssetIDs = []int64{4242}
	if errs := Validate(p, Context{}); len(errs) != 0 {
		t.Fatalf("asset check ran without a task asset set: %v", errs)
	}
}

func TestHasInclude(t *testing.T) {
	p := valid()
	if HasInclude(p) {
		t.Fatal("an exclusion-only proposal reported an inclusion")
	}
	p.Scope = append(p.Scope, Scope{Effect: "include", Kind: "ip", Value: "10.0.0.1"})
	if !HasInclude(p) {
		t.Fatal("an inclusion was not reported")
	}
}

func errorsText(errs []error) string {
	var b strings.Builder
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return b.String()
}

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/agent"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

// hasSkillTool reports whether the packed tool set contains the Skill meta-tool.
func hasSkillTool(tools []actool.CoreTool) bool {
	for _, t := range tools {
		if t.Name() == "Skill" {
			return true
		}
	}
	return false
}

// TestAssembleVisibleSkill verifies a filesystem skill made visible to an agent is
// packed into that agent's tool set (as the single Skill meta-tool) via the wired
// ToolAugment hook. Skills live on disk under skillDir; visibility is a per-agent
// (agent × skill_name) row keyed by the skill's directory name.
func TestAssembleVisibleSkill(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// Filesystem skill fixture: <skillDir>/t-assemble/SKILL.md. The directory name
	// (t-assemble) is the visibility key matched against AgentSkillNames.
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	if err := os.WriteFile(filepath.Join(skillDir, skillName, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	wireAgentAugment(pg, skillDir, nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	ag, _ := pg.GetAgentByKey("planner")
	if ag == nil {
		t.Fatal("planner agent missing")
	}

	// Isolate this test from whatever skill visibility the planner already has in the
	// shared DB: clear it now, restore it on cleanup.
	orig, _ := pg.AgentSkillNames(ag.ID)
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetAgentSkillVisibility(ag.ID, orig) })

	// before: skill not visible → no Skill meta-tool
	extra, _, cleanup := agent.ToolAugment(context.Background(), "planner")
	cleanup()
	if hasSkillTool(extra) {
		t.Fatalf("expected no Skill meta-tool before the skill is made visible")
	}

	// make the skill visible to planner
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.ToggleSkillVisibility(ag.ID, skillName, false) })

	// after: the Skill meta-tool is packed in
	extra, _, cleanup = agent.ToolAugment(context.Background(), "planner")
	defer cleanup()
	if !hasSkillTool(extra) {
		t.Fatalf("expected the Skill meta-tool after making the skill visible")
	}

	// AugmentTools appends extra to base without filtering base
	combined, _, c2 := agent.AugmentTools(context.Background(), "planner", nil)
	defer c2()
	if !hasSkillTool(combined) {
		t.Fatalf("AugmentTools should surface the Skill meta-tool")
	}
}

// The research child is launched with the gateway as its --proxy argument, and
// the credential is revoked once the child is gone. Every other server is
// launched exactly as stored, and the stored row is never rewritten.
func TestResearchServerGetsTheGatewayProxy(t *testing.T) {
	prev := researchProxyFor
	t.Cleanup(func() { researchProxyFor = prev })

	revoked := false
	researchProxyFor = func(context.Context) (string, string, func(), error) {
		return "http://cred@127.0.0.1:8788", "", func() { revoked = true }, nil
	}
	row := &db.MCPServer{Name: "obscura", Transport: "stdio", Command: "obscura", Args: json.RawMessage(`["mcp","--stealth"]`)}
	launch, revoke, err := researchServer(context.Background(), row)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mcp", "--stealth", "--proxy", "http://cred@127.0.0.1:8788"}
	if got := jsonStrSlice(launch.Args); !reflect.DeepEqual(got, want) {
		t.Fatalf("launch args = %v, want %v", got, want)
	}
	if got := jsonStrSlice(row.Args); !reflect.DeepEqual(got, []string{"mcp", "--stealth"}) {
		t.Fatalf("the stored row was rewritten: %v", got)
	}
	if revoke == nil {
		t.Fatal("the run has no way to revoke the credential")
	}
	revoke()
	if !revoked {
		t.Fatal("the credential was not revoked")
	}

	// Another server keeps its args and gets no credential.
	other := &db.MCPServer{Name: "rea", Args: json.RawMessage(`["mcp"]`)}
	launch, revoke, err = researchServer(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if launch != other || revoke != nil {
		t.Fatal("a non-research server was rewritten")
	}

	// No gateway runs: no proxy argument, and no credential to revoke.
	researchProxyFor = func(context.Context) (string, string, func(), error) { return "", "", nil, nil }
	launch, revoke, err = researchServer(context.Background(), row)
	if err != nil {
		t.Fatal(err)
	}
	if got := jsonStrSlice(launch.Args); !reflect.DeepEqual(got, []string{"mcp", "--stealth"}) {
		t.Fatalf("launch args without a gateway = %v", got)
	}
	if revoke != nil {
		t.Fatal("a credential was revoked without being issued")
	}
}

// The recorder re-signs every certificate it forwards, so the research child
// must trust its CA: without SSL_CERT_FILE every HTTPS page fails verification
// and the research browser is useless. The CA is set only while a recorder
// runs; with none it is removed rather than left pointing at a deleted file.
func TestResearchServerTrustsTheRecorderCA(t *testing.T) {
	prev := researchProxyFor
	t.Cleanup(func() { researchProxyFor = prev })

	row := &db.MCPServer{
		Name: "obscura", Transport: "stdio", Command: "obscura",
		Args: json.RawMessage(`["mcp","--stealth"]`),
		Env:  json.RawMessage(`{"PAGER":"cat","SSL_CERT_FILE":"/stale/ca.pem"}`),
	}

	researchProxyFor = func(context.Context) (string, string, func(), error) {
		return "http://cred@127.0.0.1:8788", "/state/ca.pem", nil, nil
	}
	launch, _, err := researchServer(context.Background(), row)
	if err != nil {
		t.Fatal(err)
	}
	env := jsonStrMap(launch.Env)
	if env["SSL_CERT_FILE"] != "/state/ca.pem" {
		t.Errorf("SSL_CERT_FILE = %q, want the recorder CA", env["SSL_CERT_FILE"])
	}
	if env["PAGER"] != "cat" {
		t.Errorf("the stored env was dropped: %v", env)
	}
	if got := jsonStrMap(row.Env); got["SSL_CERT_FILE"] != "/stale/ca.pem" {
		t.Errorf("the stored row was rewritten: %v", got)
	}

	// No recorder: the variable goes, so the child does not verify against a CA
	// nothing maintains.
	researchProxyFor = func(context.Context) (string, string, func(), error) { return "", "", nil, nil }
	launch, _, err = researchServer(context.Background(), row)
	if err != nil {
		t.Fatal(err)
	}
	env = jsonStrMap(launch.Env)
	if _, ok := env["SSL_CERT_FILE"]; ok {
		t.Errorf("SSL_CERT_FILE survived with no recorder: %v", env)
	}
	if env["PAGER"] != "cat" {
		t.Errorf("the stored env was dropped: %v", env)
	}
}

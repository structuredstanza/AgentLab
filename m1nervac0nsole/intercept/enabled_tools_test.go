package intercept

import (
	"os"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// The curators' writes (memory_propose and the tool curator's two proposals) belong in the default intercept scope, so an
// instance that never configured intercept_enabled_tools shows it in the scope
// dialog and routes it through the rule/judge path. Membership is not the
// approval itself (see TestMemoryProposeAlwaysAsksBeforeWriting); its read tools
// must stay out, because gating a search protects nothing and makes the curator
// unusable.
func TestMemoryProposeIsInterceptedByDefault(t *testing.T) {
	dsn := os.Getenv("M1NERVAC0NSOLE_PG_DSN")
	if dsn == "" {
		t.Skip("no M1NERVAC0NSOLE_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	ic := New(d)
	prior, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetEnabledTools(prior) })
	// Fall back to the hard-coded defaults, whatever this database was left at.
	if err := d.SetSetting("intercept_enabled_tools", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key='intercept_enabled_tools'`); err != nil {
		t.Fatal(err)
	}
	ic.Invalidate()

	for _, propose := range []string{"memory_propose", "toolbox_propose_template", "toolbox_propose_tool", "toolbox_install"} {
		if !ic.IsToolEnabled(propose) {
			t.Errorf("%s is not intercepted by default: a curator write would be stored unseen", propose)
		}
	}
	for _, read := range []string{"memory_search", "memory_read", "reflection_search", "task_digest", "toolbox_list", "toolbox_read", "toolbox_validate"} {
		if ic.IsToolEnabled(read) {
			t.Errorf("%s is intercepted by default: read-only curator tools must not prompt the operator", read)
		}
	}
}

// The tool curator's two proposals and its install are approval-required and in
// the default scope; its three read tools are neither. This needs no database: it
// pins the sets, and that the approval card names the tool being approved while
// memory_propose keeps its original wording.
func TestToolCuratorApprovalSet(t *testing.T) {
	inDefault := map[string]bool{}
	for _, n := range defaultEnabledTools {
		inDefault[n] = true
	}
	for _, n := range []string{"toolbox_propose_template", "toolbox_propose_tool", "toolbox_install"} {
		if !approvalRequiredTools[n] || !inDefault[n] {
			t.Errorf("%s: approvalRequired=%v inDefaultScope=%v, want both", n, approvalRequiredTools[n], inDefault[n])
		}
		ask := approvalRequiredAsk(n)
		if ask.Action != "ask" || !strings.Contains(ask.Message, n) || !strings.Contains(ask.RuleName, n) {
			t.Errorf("%s approval does not name the tool: %+v", n, ask)
		}
	}
	// An install is not a save: the card must say what is about to run.
	if ask := approvalRequiredAsk("toolbox_install"); !strings.Contains(ask.Message, "install script") {
		t.Errorf("install approval does not say it runs the install script: %+v", ask)
	}
	for _, n := range []string{"toolbox_list", "toolbox_read", "toolbox_validate"} {
		if approvalRequiredTools[n] || inDefault[n] {
			t.Errorf("%s is gated (approvalRequired=%v inDefaultScope=%v): read-only tools must not prompt", n, approvalRequiredTools[n], inDefault[n])
		}
	}
	mem := approvalRequiredAsk("memory_propose")
	if mem.RuleName != "curator memory proposal" || mem.Message != "The curator's memory proposal needs your approval before it is stored." {
		t.Errorf("memory_propose approval wording changed: %+v", mem)
	}
}

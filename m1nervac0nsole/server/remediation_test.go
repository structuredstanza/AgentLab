package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/structuredstanza/norma/llm"
)

type remediationTestProvider struct {
	llm.Provider // Only the tool-free completion method is reachable.
	complete     func(llm.CompletionRequest) string
}

func (p remediationTestProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.complete(req))}}, "stop", llm.Usage{}, nil
}

func TestRemediationCompletionLifecycle(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	ctx := t.Context()
	id := apiTokenTask(t, m, "remediation lifecycle")
	var findingID int64
	err = m.pg.QueryRowContext(ctx, `INSERT INTO findings(task_id,vulnclass,name,severity,status,summary,evidence)
 VALUES ($1,'access','Missing check','high','pending','Review auth.go CheckOwner before access. password=fixture-secret','RAW_EVIDENCE_MARKER') RETURNING id`, id).Scan(&findingID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.ExecContext(ctx, `INSERT INTO findings(task_id,vulnclass,name,severity,status) VALUES ($1,'access','FIXED_MARKER','critical','fixed')`, id); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s := &Server{m: m, engine: &Engine{}, llmOn: true, llmProv: remediationTestProvider{complete: func(req llm.CompletionRequest) string {
		calls++
		if len(req.Tools) != 0 || len(req.Messages) != 1 {
			t.Fatalf("unexpected request surface: %+v", req)
		}
		input := req.Messages[0].Text()
		if !strings.Contains(input, "CheckOwner") || strings.Contains(input, "fixture-secret") ||
			strings.Contains(input, "RAW_EVIDENCE_MARKER") || strings.Contains(input, "FIXED_MARKER") {
			t.Fatalf("wrong finding data sent to provider: %s", input)
		}
		return fmt.Sprintf(`[{"finding_id":%d,"priority":"urgent","exploitability":"unknown","rationale":"The recorded impact warrants review.","remediation":"Check resource ownership before returning data.","regression_check":"Assert a non-owner cannot read the record.","file":"auth.go","function":"CheckOwner"}]`, findingID)
	}}}
	step := func() {
		t.Helper()
		if err := s.remediationStep(ctx); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want string) remediationResult {
		t.Helper()
		text, err := readRemediationReport(ctx, m.pg, id)
		if err != nil {
			t.Fatal(err)
		}
		var report remediationResult
		if err := json.Unmarshal([]byte(text), &report); err != nil || report.State != want {
			t.Fatalf("want report state %s, got %s (%v)", want, text, err)
		}
		return report
	}
	read("not_completed")
	step()
	if calls != 0 {
		t.Fatal("provider called before task completion")
	}
	taskKey := fmt.Sprint(id)
	if !s.engine.beginTaskOperation(taskKey) {
		t.Fatal("could not register fixture operation")
	}
	if _, err := m.pg.ExecContext(ctx, `UPDATE tasks SET status='done', completed_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	read("pending")
	step()
	if calls != 0 {
		t.Fatal("provider called before final task work drained")
	}
	s.engine.decInflight(taskKey)
	step()
	report := read("ready")
	if len(report.Items) != 1 || report.Items[0].FindingID != findingID || report.Items[0].Severity != "high" ||
		report.Items[0].Exploitability != "unknown" || report.Items[0].File != "auth.go" || report.Items[0].Function != "CheckOwner" {
		t.Fatalf("wrong remediation result: %+v", report)
	}
	step()
	if calls != 1 {
		t.Fatalf("provider called %d times for one completion", calls)
	}
	if _, err := m.pg.ExecContext(ctx, `UPDATE tasks SET status='running', completed_at=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	read("not_completed")
	if _, err := m.pg.ExecContext(ctx, `UPDATE tasks SET status='done', completed_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	read("pending")
	step()
	read("ready")
	if calls != 2 {
		t.Fatalf("provider called %d times across two completions", calls)
	}
}

func TestRemediationDoesNotTrustModelFindingReferences(t *testing.T) {
	findings := []remediationFinding{{ID: 1, Summary: "Look at auth.go"}}
	const item = `{"finding_id":%d,"priority":"next","exploitability":"unknown","rationale":"Review impact.","remediation":"Check ownership.","regression_check":"Assert denial.","file":"auth.go","function":"InventedName"}`
	if _, err := parseRemediation("["+fmt.Sprintf(item, 2)+"]", findings); err == nil {
		t.Fatal("accepted a finding outside the batch")
	}
	got, err := parseRemediation("["+fmt.Sprintf(item, 1)+"]", findings)
	if err != nil || len(got) != 1 || got[0].File != "auth.go" || got[0].Function != "" {
		t.Fatalf("source attribution was not constrained: %+v, %v", got, err)
	}
}

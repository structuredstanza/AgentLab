package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// policyTestTask creates a task through the manager, so the policy API sees it as
// live and the cleanup removes it from both PostgreSQL and the in-memory map.
func policyTestTask(t *testing.T, m *Manager) *Task {
	t.Helper()
	task, err := m.CreateTask("policy api", "prove the operator policy surface", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := mustTaskID(t, task.ID)
	t.Cleanup(func() { _ = m.pg.DeleteTask(id) })
	return task
}

// policyRules reads one task's rules through the API, keyed by id.
func policyRules(t *testing.T, s *Server, token, path string) (int64, map[int64]map[string]any) {
	t.Helper()
	code, out := memoryAPI(t, s, token, http.MethodGet, path, "")
	if code != http.StatusOK {
		t.Fatalf("policy list status=%d body=%v", code, out)
	}
	rev, _ := out["revision"].(float64)
	byID := map[int64]map[string]any{}
	list, _ := out["rules"].([]any)
	for _, raw := range list {
		rule, _ := raw.(map[string]any)
		id, _ := rule["id"].(float64)
		byID[int64(id)] = rule
	}
	return int64(rev), byID
}

// A written rule is not a grant: it appears in the list with authorized=false and
// the authorizer still refuses the destination until the operator approves it.
func TestTaskPolicyRuleLifecycle(t *testing.T) {
	m, s, token := memoryTestServer(t)
	task := policyTestTask(t, m)
	taskID := mustTaskID(t, task.ID)
	path := "/api/tasks/" + task.ID + "/policy"
	authorizer := netpolicy.NewAuthorizer(m.pg)
	dest := netpolicy.Destination{Scheme: "https", Host: "api.example.com", Port: 443, Protocol: "http"}
	session := netpolicy.Session{ID: "policy-api-test", TaskID: taskID, Purpose: netpolicy.PurposeTesting}

	if code, _ := memoryAPI(t, s, "", http.MethodGet, path, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status=%d want 401", code)
	}
	rev, rules := policyRules(t, s, token, path)
	if len(rules) != 0 {
		t.Fatalf("a fresh task has %d rules, want none", len(rules))
	}

	code, out := memoryAPI(t, s, token, http.MethodPost, path+"/rules",
		`{"effect":"include","pattern":"api.example.com","protocol":"http","ports":[443],"note":"engagement scope"}`)
	if code != http.StatusCreated {
		t.Fatalf("add rule status=%d body=%v", code, out)
	}
	id, _ := out["id"].(float64)
	ruleID := int64(id)
	if ruleID <= 0 {
		t.Fatalf("add rule returned no id: %v", out)
	}

	afterAdd, rules := policyRules(t, s, token, path)
	rule := rules[ruleID]
	if rule == nil {
		t.Fatalf("the written rule is missing from the list: %v", rules)
	}
	if authorized, _ := rule["authorized"].(bool); authorized {
		t.Fatal("a rule added without approval is authorized")
	}
	if afterAdd <= rev {
		t.Fatalf("writing a rule left the revision at %d (was %d)", afterAdd, rev)
	}
	if dec := authorizer.Authorize(context.Background(), session, dest); dec.Allow {
		t.Fatalf("an unauthorized rule authorized %s: %+v", dest.Host, dec)
	}

	// Approval turns the row into a grant, and the revision moves again.
	code, out = memoryAPI(t, s, token, http.MethodPost, fmt.Sprintf("%s/rules/%d/authorize", path, ruleID), "")
	if code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%v", code, out)
	}
	afterApprove, rules := policyRules(t, s, token, path)
	if authorized, _ := rules[ruleID]["authorized"].(bool); !authorized {
		t.Fatal("the approved rule is still unauthorized")
	}
	if afterApprove <= afterAdd {
		t.Fatalf("approving a rule left the revision at %d (was %d)", afterApprove, afterAdd)
	}
	if dec := authorizer.Authorize(context.Background(), session, dest); !dec.Allow {
		t.Fatalf("the approved rule did not authorize %s: %+v", dest.Host, dec)
	}

	// Revocation is a grant removal, not a delete: the row stays visible.
	code, out = memoryAPI(t, s, token, http.MethodPost, fmt.Sprintf("%s/rules/%d/revoke", path, ruleID), "")
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, out)
	}
	afterRevoke, rules := policyRules(t, s, token, path)
	if authorized, _ := rules[ruleID]["authorized"].(bool); authorized {
		t.Fatal("the revoked rule is still authorized")
	}
	if afterRevoke <= afterApprove {
		t.Fatalf("revoking a rule left the revision at %d (was %d)", afterRevoke, afterApprove)
	}
	if dec := authorizer.Authorize(context.Background(), session, dest); dec.Allow {
		t.Fatalf("a revoked rule still authorized %s: %+v", dest.Host, dec)
	}

	// A rule that is not on this task is a 404, not a silent success.
	if code, _ := memoryAPI(t, s, token, http.MethodPost, fmt.Sprintf("%s/rules/%d/authorize", path, 1<<40), ""); code != http.StatusNotFound {
		t.Fatalf("unknown rule status=%d want 404", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPost, path+"/rules/notanumber/authorize", ""); code != http.StatusBadRequest {
		t.Fatalf("bad rule id status=%d want 400", code)
	}
}

// A rule the destination contract cannot express is refused where it is written,
// so the predicate never has to guess what the operator meant.
func TestTaskPolicyRuleRejectsUnexpressibleRules(t *testing.T) {
	m, s, token := memoryTestServer(t)
	task := policyTestTask(t, m)
	path := "/api/tasks/" + task.ID + "/policy/rules"

	for _, body := range []string{
		// A dns grant is the resolver, which the contract describes on port 53.
		`{"effect":"include","pattern":"api.example.com","protocol":"dns","ports":[443]}`,
		// A scheme is not a protocol: the contract carries http/ws/tcp/udp/dns.
		`{"effect":"include","pattern":"api.example.com","protocol":"https"}`,
		// An effect the predicate does not know.
		`{"effect":"allow","pattern":"api.example.com"}`,
		// A url glob can never match a destination.
		`{"effect":"include","pattern":"https://api.example.com/admin"}`,
		// A port outside the range a destination can carry.
		`{"effect":"include","pattern":"api.example.com","ports":[70000]}`,
	} {
		if code, out := memoryAPI(t, s, token, http.MethodPost, path, body); code != http.StatusBadRequest {
			t.Fatalf("POST %s status=%d body=%v, want 400", body, code, out)
		}
	}
	// A dns rule that names the resolver port is expressible and is stored.
	if code, out := memoryAPI(t, s, token, http.MethodPost, path,
		`{"effect":"include","pattern":"resolver.example","protocol":"dns","ports":[53]}`); code != http.StatusCreated {
		t.Fatalf("dns rule status=%d body=%v", code, out)
	}
}

// Certificate exceptions are task- and authority-bound, and deleting one is a
// real delete: a second delete reports the missing row.
func TestTaskPolicyCertExceptions(t *testing.T) {
	m, s, token := memoryTestServer(t)
	task := policyTestTask(t, m)
	path := "/api/tasks/" + task.ID + "/policy/cert-exceptions"

	code, out := memoryAPI(t, s, token, http.MethodGet, path, "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, out)
	}
	if list, _ := out["exceptions"].([]any); len(list) != 0 {
		t.Fatalf("a fresh task has exceptions: %v", list)
	}

	code, out = memoryAPI(t, s, token, http.MethodPost, path,
		`{"authority":"Self-Signed.Example:443","reason":"lab target","expires_at":"`+futureRFC3339()+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("add status=%d body=%v", code, out)
	}
	code, out = memoryAPI(t, s, token, http.MethodGet, path, "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, out)
	}
	list, _ := out["exceptions"].([]any)
	if len(list) != 1 {
		t.Fatalf("exceptions = %v, want one", list)
	}
	entry, _ := list[0].(map[string]any)
	if entry["authority"] != "self-signed.example:443" {
		t.Fatalf("authority = %v, want the normalized one", entry["authority"])
	}
	id, _ := entry["id"].(float64)

	// A past expiry is refused rather than stored as an exception that never applies.
	if code, _ := memoryAPI(t, s, token, http.MethodPost, path,
		`{"authority":"past.example","expires_at":"2000-01-01T00:00:00Z"}`); code != http.StatusBadRequest {
		t.Fatalf("past expiry status=%d want 400", code)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodPost, path, `{"authority":"  "}`); code != http.StatusBadRequest {
		t.Fatalf("empty authority status=%d want 400", code)
	}

	if code, out := memoryAPI(t, s, token, http.MethodDelete, fmt.Sprintf("%s/%d", path, int64(id)), ""); code != http.StatusOK {
		t.Fatalf("delete status=%d body=%v", code, out)
	}
	if code, _ := memoryAPI(t, s, token, http.MethodDelete, fmt.Sprintf("%s/%d", path, int64(id)), ""); code != http.StatusNotFound {
		t.Fatalf("second delete status=%d want 404", code)
	}
	code, out = memoryAPI(t, s, token, http.MethodGet, path, "")
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, out)
	}
	if list, _ := out["exceptions"].([]any); len(list) != 0 {
		t.Fatalf("exceptions after delete = %v, want none", list)
	}
}

// futureRFC3339 is an expiry the API accepts.
func futureRFC3339() string {
	return "2099-01-01T00:00:00Z"
}

// The gateway resolves a session from the credential alone: an absent or unknown
// credential is refused, and a revoked one stops resolving.
func TestGatewaySessionCredential(t *testing.T) {
	m, _, _ := memoryTestServer(t)
	task := policyTestTask(t, m)
	taskID := mustTaskID(t, task.ID)

	issued, err := m.IssueSession(context.Background(), netpolicy.CallerAgent, taskID, 0, netpolicy.PurposeTesting)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	cred := issued.Credential
	if cred == "" {
		t.Fatal("an issued session carries no credential")
	}
	if issued.TaskID != taskID || issued.Purpose != netpolicy.PurposeTesting {
		t.Fatalf("issued session = %+v, want task %d testing", issued, taskID)
	}

	// A proxy URL of the form http://<credential>@host:port arrives as Basic auth.
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(cred+":"))
	for _, header := range []string{basic, "Bearer " + cred} {
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
		req.Header.Set("Proxy-Authorization", header)
		s, ok := m.gatewaySession(req)
		if !ok {
			t.Fatalf("%q did not resolve a session", header)
		}
		if s.TaskID != taskID || s.Purpose != netpolicy.PurposeTesting {
			t.Fatalf("session = %+v, want task %d testing", s, taskID)
		}
	}

	for _, header := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("unknown:")), "Bearer nope", "Digest abc"} {
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
		if header != "" {
			req.Header.Set("Proxy-Authorization", header)
		}
		if _, ok := m.gatewaySession(req); ok {
			t.Fatalf("%q resolved a session, want a refusal", header)
		}
	}

	m.RevokeSession(cred)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Proxy-Authorization", basic)
	if _, ok := m.gatewaySession(req); ok {
		t.Fatal("a revoked credential still resolves a session")
	}

	// An unbound conversation gets research only, and testing without a task is
	// refused by the issuer rather than downgraded.
	if _, err := m.IssueSession(context.Background(), netpolicy.CallerChat, 0, 0, netpolicy.PurposeResearch); err != nil {
		t.Fatalf("unbound research session: %v", err)
	}
	if _, err := m.IssueSession(context.Background(), netpolicy.CallerChat, 0, 0, netpolicy.PurposeTesting); err == nil {
		t.Fatal("an unbound testing session was issued")
	}
	if _, err := m.IssueSession(context.Background(), netpolicy.CallerCurator, taskID, 0, netpolicy.PurposeTesting); err == nil {
		t.Fatal("the curator caller was allowed a testing purpose")
	}
}

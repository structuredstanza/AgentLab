package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// Evidence above the inline limit is spilled to a content-addressed file and the
// row keeps only a path. The single-finding read and every export must resolve
// it, or the API and each download show a finding with no proof.
func TestFindingReadAndExportResolveSpilledEvidence(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("spilled evidence", "prove the spill resolves", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(tid) })
	s := newFixtureServer(t, m)
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	body := strings.Repeat("proof line\n", 2000) // 22 KiB, above the 8 KiB inline limit
	f, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: tid, ExplorationID: task.ExpID, Worker: "test", VulnClass: "TEST",
		Name: "spilled evidence", Severity: "high", Summary: "large proof", Evidence: body,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	row, err := m.pg.GetFinding(f.FindingID)
	if err != nil || row == nil {
		t.Fatalf("GetFinding: %v %v", row, err)
	}
	if row.EvidencePath == "" || row.Evidence != "" {
		t.Fatalf("fixture did not spill the evidence: path=%q inline=%d bytes", row.EvidencePath, len(row.Evidence))
	}

	id := strconv.FormatInt(f.FindingID, 10)
	w := do(http.MethodGet, "/api/exploration/findings/"+id, "")
	if w.Code != http.StatusOK {
		t.Fatalf("single finding: %d %s", w.Code, w.Body.String())
	}
	var dto FindingDTO
	if err := json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Evidence != body {
		t.Fatalf("single-finding API returned %d bytes of evidence, want %d", len(dto.Evidence), len(body))
	}

	w = do(http.MethodGet, "/api/exploration/findings/export?scope=selected&format=json&ids="+id, "")
	if w.Code != http.StatusOK {
		t.Fatalf("json export: %d %s", w.Code, w.Body.String())
	}
	var exported []FindingDTO
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 {
		t.Fatalf("json export carried %d findings, want 1", len(exported))
	}
	if exported[0].Evidence != body {
		t.Fatalf("json export carried %d bytes of evidence, want %d", len(exported[0].Evidence), len(body))
	}

	w = do(http.MethodGet, "/api/exploration/findings/export?scope=selected&format=md-single&ids="+id, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "proof line") {
		t.Fatalf("markdown export lost the evidence: %d %s", w.Code, w.Body.String())
	}

	// A status edit returns the finding DTO, which must carry the body too.
	w = do(http.MethodPatch, "/api/exploration/findings/"+id, `{"status":"confirmed"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("patch finding: %d %s", w.Code, w.Body.String())
	}
	var patched FindingDTO
	if err := json.Unmarshal(w.Body.Bytes(), &patched); err != nil {
		t.Fatal(err)
	}
	if patched.Evidence != body {
		t.Fatalf("patched finding returned %d bytes of evidence, want %d", len(patched.Evidence), len(body))
	}

	// The deliverable report renders exploration nodes, whose payload carries no
	// body once the standalone row spilled it.
	w = do(http.MethodGet, "/api/report?task="+task.ID, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "proof line") {
		t.Fatalf("report lost the evidence: %d %s", w.Code, w.Body.String())
	}
}

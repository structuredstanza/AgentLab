package agent

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/evidence"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

func pinsToolSet(t *testing.T) (*ToolSet, *db.DB, string) {
	t.Helper()
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return true }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("pins", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	work := t.TempDir()
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID, ts.workDir = d.Exploration(task.ExplorationID), task.ID, work
	ts.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	oldAuth := NetPolicyAuthorizer
	NetPolicyAuthorizer = netpolicy.NewAuthorizer(d)
	t.Cleanup(func() { NetPolicyAuthorizer = oldAuth })
	if _, err := d.AddPolicyRule(t.Context(), task.ID, netpolicy.Rule{
		Effect: "include", Pattern: "10.0.0.0/24", Authorized: true,
	}, "operator"); err != nil {
		t.Fatal(err)
	}
	return ts, d, work
}

func reportPins(t *testing.T, ts *ToolSet, d *db.DB, body string) (string, string) {
	t.Helper()
	res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
	if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
		t.Fatalf("report refused: %v %s", err, res.Flatten())
	}
	var out db.RecordedFinding
	if err := json.Unmarshal([]byte(strings.SplitN(res.Flatten(), "\n", 2)[1]), &out); err != nil {
		t.Fatal(err)
	}
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil {
		t.Fatalf("finding missing: %v", err)
	}
	return f.Evidence, res.Flatten()
}

func TestReportFindingPinsArtifactAndFlow(t *testing.T) {
	ts, d, work := pinsToolSet(t)
	art := filepath.Join(work, "tasks", strconv.FormatInt(ts.taskID, 10), "exec-artifacts", "abc-1234")
	if err := os.MkdirAll(art, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(art, "meta.json"), []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// One ssh packet in a one-segment capture ring.
	base := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	cap := t.TempDir()
	pcap := make([]byte, 24, 24+16+42)
	binary.LittleEndian.PutUint32(pcap, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(pcap[4:], 2)
	binary.LittleEndian.PutUint16(pcap[6:], 4)
	binary.LittleEndian.PutUint32(pcap[16:], 65535)
	binary.LittleEndian.PutUint32(pcap[20:], 1)
	rec := make([]byte, 16+42)
	binary.LittleEndian.PutUint32(rec, uint32(base.Unix()))
	binary.LittleEndian.PutUint32(rec[8:], 42)
	binary.LittleEndian.PutUint32(rec[12:], 42)
	fr := rec[16:]
	binary.BigEndian.PutUint16(fr[12:], 0x0800)
	fr[14], fr[23] = 0x45, 6
	copy(fr[26:], []byte{10, 98, 0, 2, 10, 0, 0, 5})
	binary.BigEndian.PutUint16(fr[34:], 40000)
	binary.BigEndian.PutUint16(fr[36:], 22)
	if err := os.WriteFile(filepath.Join(cap, "capture.pcap"), append(pcap, rec...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(cap, "capture.pcap"), base, base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Setenv(evidence.CaptureDirEnv, cap)

	body, _ := json.Marshal(map[string]any{
		"vulnclass": "SSH", "severity": "low", "summary": "weak ssh", "evidence": "hydra output",
		"artifacts": []string{"exec-artifacts/abc-1234"},
		"flows": []map[string]any{{"host": "10.0.0.5", "port": 22, "proto": "tcp",
			"from": base.Add(-time.Minute).Format(time.RFC3339), "to": base.Add(time.Minute).Format(time.RFC3339)}},
	})
	ev, out := reportPins(t, ts, d, string(body))
	for _, want := range []string{"hydra output", "artifact exec-artifacts/abc-1234 (meta.json sha256 ", "flow 10.0.0.5 tcp port 22", "1 packets"} {
		if !strings.Contains(ev, want) {
			t.Errorf("finding evidence lacks %q:\n%s", want, ev)
		}
	}
	if !strings.Contains(out, "evidence_pinned") || strings.Contains(out, "evidence_pin_failed") {
		t.Errorf("result: %s", out)
	}

	// A flow the capture cannot answer is reported and the finding is still recorded.
	body, _ = json.Marshal(map[string]any{"vulnclass": "SSH", "severity": "low", "summary": "weak ssh 2",
		"flows": []map[string]any{{"host": "10.0.0.6", "from": base.Format(time.RFC3339), "to": base.Add(time.Minute).Format(time.RFC3339)}}})
	if _, out = reportPins(t, ts, d, string(body)); !strings.Contains(out, "evidence_pin_failed") || !strings.Contains(out, "no packets matched") {
		t.Errorf("failed pin not reported: %s", out)
	}
}

func TestReportFindingHTTPWithoutTrafficRecommendsReplay(t *testing.T) {
	ts, d, _ := pinsToolSet(t)
	ev, out := reportPins(t, ts, d, `{"vulnclass":"XSS","severity":"low","summary":"reflected","evidence":"curl output"}`)
	if ev != "curl output" {
		t.Fatalf("evidence rewritten without refs: %q", ev)
	}
	if !strings.Contains(out, "replay it through the recorder") {
		t.Fatalf("no replay recommendation: %s", out)
	}
}

func TestPinArtifactRefusesUnsafeManifest(t *testing.T) {
	for _, tc := range []struct {
		name, want string
	}{
		{"symlink", "not a regular file"},
		{"oversized", "larger than 1 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := &ToolSet{workDir: t.TempDir(), taskID: 1}
			dir := filepath.Join(ts.workDir, "tasks", "1", "exec-artifacts", "fixture")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			meta := filepath.Join(dir, "meta.json")
			if tc.name == "symlink" {
				if err := os.WriteFile(filepath.Join(dir, "target.json"), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target.json", meta); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(meta, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(meta, 1<<20+1); err != nil {
					t.Fatal(err)
				}
			}
			pin, err := ts.pinArtifact("fixture", 0)
			if err == nil || !strings.Contains(err.Error(), tc.want) || pin != "" {
				t.Fatalf("%s manifest pinned or refused for wrong reason: %q (%v)", tc.name, pin, err)
			}
		})
	}
}

type flowPinSpy struct {
	FindingRecorder
	flows []evidence.Flow
}

func (p *flowPinSpy) PinFlow(f evidence.Flow) (evidence.PinnedFlow, error) {
	p.flows = append(p.flows, f)
	return evidence.PinnedFlow{}, nil
}

func TestPinFlowRefusesUnauthorizedHost(t *testing.T) {
	old := NetPolicyAuthorizer
	t.Cleanup(func() { NetPolicyAuthorizer = old })
	NetPolicyAuthorizer = netpolicy.NewAuthorizer(snapshotSource{netpolicy.State{Rules: []netpolicy.Rule{
		{Effect: "include", Pattern: "192.0.2.2", Authorized: true},
	}}})
	spy := &flowPinSpy{}
	ts := &ToolSet{taskID: 1, findingRecorder: spy}
	_, err := ts.pinFlow(t.Context(), findingFlow{Host: "192.0.2.1", Proto: "tcp", Port: 22}, 0)
	if err == nil || !strings.Contains(err.Error(), "not authorized") || len(spy.flows) != 0 {
		t.Fatalf("unauthorized flow reached the pinner or got the wrong rejection: %v (%d calls)", err, len(spy.flows))
	}
}

func TestPinFlowClampsCaptureToIntentOrTaskStart(t *testing.T) {
	ts, d, _ := pinsToolSet(t)
	spy := &flowPinSpy{}
	ts.SetFindingRecorder(spy)
	start := time.Unix(1_000_000, 0).UTC()
	intentStart := start.Add(time.Minute)
	intentID, err := ts.ts.AddIntent(map[string]any{"summary": "pin fixture"}, 1, nil, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE tasks SET created_at=$1, first_run_at=$2 WHERE id=$3`, start.Add(-time.Minute), start, ts.taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE exploration_nodes SET created_at=$1 WHERE id=$2`, intentStart, intentID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		intent int64
		from   string
		want   time.Time
	}{
		{"task floor", 0, start.Add(-time.Minute).Format(time.RFC3339), start},
		{"intent floor", intentID, start.Format(time.RFC3339), intentStart},
		{"intent default", intentID, "", intentStart},
		{"later explicit start", intentID, intentStart.Add(time.Second).Format(time.RFC3339), intentStart.Add(time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.pinFlow(t.Context(), findingFlow{
				Host: "10.0.0.5", Port: 22, Proto: "tcp", From: tc.from,
				To: intentStart.Add(time.Minute).Format(time.RFC3339),
			}, tc.intent)
			if err != nil {
				t.Fatal(err)
			}
			if got := spy.flows[len(spy.flows)-1].From; !got.Equal(tc.want) {
				t.Fatalf("pin started at %s, want %s", got, tc.want)
			}
		})
	}
}

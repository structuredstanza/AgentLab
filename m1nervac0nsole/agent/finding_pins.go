package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/evidence"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
)

// flowPinner is implemented by *evidence.Store; a recorder without it cannot
// pin packets and the flow is reported as not pinned.
type flowPinner interface {
	PinFlow(evidence.Flow) (evidence.PinnedFlow, error)
}

// findingFlow is one packet selection of a report. The window is bounded by
// the originating intent or task because the capture ring is shared.
type findingFlow struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	From  string `json:"from"`
	To    string `json:"to"`
}

const (
	maxFindingArtifacts  = 10
	maxFindingFlows      = 5
	maxArtifactMetaBytes = 1 << 20
)

// artifactName is the directory name execbox gives a capture; anything else
// (separators, "..") is refused so an id can only name a capture directory.
var artifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// pinArtifact anchors one exec artifact by the SHA-256 of its meta.json, which
// itself carries the stdin/stdout/stderr hashes. The capture lives in the run
// workspace (the intent's directory for workers, the task's otherwise), which
// the task's own processes can write, so the hash is the integrity anchor.
func (t *ToolSet) pinArtifact(id string, intentID int64) (string, error) {
	name := strings.TrimPrefix(id, "exec-artifacts/")
	if !artifactName.MatchString(name) {
		return "", fmt.Errorf("artifact %q: expected the id from an [exec artifact: exec-artifacts/<id> ...] line", id)
	}
	if t.workDir == "" || t.taskID <= 0 {
		return "", fmt.Errorf("artifact %q: workspace unavailable", id)
	}
	root, err := os.OpenRoot(t.workDir)
	if err != nil {
		return "", fmt.Errorf("artifact %q: open workspace: %w", id, err)
	}
	defer root.Close()
	task := filepath.Join("tasks", strconv.FormatInt(t.taskID, 10))
	dirs := []string{task}
	if intentID > 0 {
		dirs = []string{filepath.Join(task, "i"+strconv.FormatInt(intentID, 10)), task}
	}
	for _, d := range dirs {
		dir := filepath.Join(d, "exec-artifacts", name)
		if fi, err := root.Lstat(dir); err != nil || !fi.IsDir() {
			continue
		}
		sum, err := hashArtifactMeta(root, filepath.Join(dir, "meta.json"))
		if err != nil {
			return "", fmt.Errorf("artifact %q: %w", id, err)
		}
		return fmt.Sprintf("artifact exec-artifacts/%s (meta.json sha256 %s)", name, hex.EncodeToString(sum[:])), nil
	}
	return "", fmt.Errorf("artifact %q: not found in this task's workspace", id)
}

func hashArtifactMeta(root *os.Root, path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	fi, err := root.Lstat(path)
	if err != nil {
		return sum, fmt.Errorf("stat meta.json: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return sum, fmt.Errorf("meta.json is not a regular file")
	}
	if fi.Size() > maxArtifactMetaBytes {
		return sum, fmt.Errorf("meta.json is larger than 1 MiB")
	}
	// The task can replace the name between stat and open; never follow a
	// symlink or block on a FIFO, and enforce the cap on the bytes read.
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return sum, fmt.Errorf("open meta.json: %w", err)
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(fi, opened) || !opened.Mode().IsRegular() {
		return sum, fmt.Errorf("meta.json changed before reading")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArtifactMetaBytes+1))
	if err != nil {
		return sum, fmt.Errorf("read meta.json: %w", err)
	}
	if n > maxArtifactMetaBytes {
		return sum, fmt.Errorf("meta.json is larger than 1 MiB")
	}
	h.Sum(sum[:0])
	return sum, nil
}

// pinFlow extracts the flow's packets from the guest capture ring.
func (t *ToolSet) pinFlow(ctx context.Context, f findingFlow, intentID int64) (string, error) {
	p, ok := t.findingRecorder.(flowPinner)
	if !ok {
		return "", fmt.Errorf("flow %s: packet pinning is unavailable", f.Host)
	}
	fl := evidence.Flow{Host: f.Host, Port: f.Port, Proto: strings.ToLower(f.Proto), TaskID: t.taskID}
	if dec := authorizeDial(ctx, NetPolicyAuthorizer, t.taskID, netpolicy.Destination{Host: fl.Host, Port: fl.Port, Protocol: fl.Proto}); !dec.Allow {
		return "", fmt.Errorf("flow %s not authorized: %s", fl.Host, dec.Reason)
	}
	var err error
	for _, w := range []struct {
		s   string
		dst *time.Time
	}{{f.From, &fl.From}, {f.To, &fl.To}} {
		if w.s != "" {
			if *w.dst, err = time.Parse(time.RFC3339, w.s); err != nil {
				return "", fmt.Errorf("flow %s: from/to must be RFC3339: %w", f.Host, err)
			}
		}
	}
	if t.ts == nil {
		return "", fmt.Errorf("flow %s: task context is unavailable", fl.Host)
	}
	var start time.Time
	if intentID > 0 {
		n, err := t.ts.GetNode(intentID)
		if err != nil {
			return "", fmt.Errorf("flow %s: read intent: %w", fl.Host, err)
		}
		if n != nil && n.Kind == "intent" {
			start = n.CreatedAt
		}
	}
	if start.IsZero() {
		start, err = t.ts.TaskStartedAt(ctx)
		if err != nil {
			return "", fmt.Errorf("flow %s: %w", fl.Host, err)
		}
	}
	if fl.From.Before(start) {
		fl.From = start
	}
	if fl.To.IsZero() {
		fl.To = time.Now()
	}
	pin, err := p.PinFlow(fl)
	if err != nil {
		return "", fmt.Errorf("flow %s: %w", f.Host, err)
	}
	note := fmt.Sprintf("flow %s %s port %d %s..%s: pcap %s sha256 %s, %d packets, %d bytes",
		fl.Host, fl.Proto, fl.Port, fl.From.Format(time.RFC3339), fl.To.Format(time.RFC3339), pin.Path, pin.SHA256, pin.Packets, pin.Bytes)
	if pin.Truncated {
		note += " (TRUNCATED at the size bound)"
	}
	return note, nil
}

// pinEvidence pins every artifact and flow of one report. A ref that cannot be
// pinned never discards the finding: it is returned as a failure the agent reads.
func (t *ToolSet) pinEvidence(ctx context.Context, artifacts []string, flows []findingFlow, intentID int64) (pinned, failed []string) {
	if len(artifacts) > maxFindingArtifacts || len(flows) > maxFindingFlows {
		return nil, []string{fmt.Sprintf("at most %d artifacts and %d flows per report; none pinned", maxFindingArtifacts, maxFindingFlows)}
	}
	for _, a := range artifacts {
		if s, err := t.pinArtifact(a, intentID); err != nil {
			failed = append(failed, err.Error())
		} else {
			pinned = append(pinned, s)
		}
	}
	for _, f := range flows {
		if s, err := t.pinFlow(ctx, f, intentID); err != nil {
			failed = append(failed, err.Error())
		} else {
			pinned = append(pinned, s)
		}
	}
	return pinned, failed
}

// evidenceAdvice tells the agent which evidence would strengthen a finding that
// has none, without making any kind mandatory.
const evidenceAdvice = "No evidence beyond the text was attached. If this is an HTTP finding and the request is repeatable and non-destructive, replay it through the recorder (curl via the proxy env) and backfill that exchange with bind_finding_traffic. For non-HTTP or destructive findings, cite the exec artifact ids of the commands that proved it and the flows (host/port/proto) that carried it. Do not create the vulnerability again."

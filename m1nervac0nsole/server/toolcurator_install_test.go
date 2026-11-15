package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/manifest"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

// fakeExecbox answers a spawn with canned output and records the session and spec
// it was asked for, so the install path can be tested without a kernel boundary.
type fakeExecbox struct {
	mu         sync.Mutex
	calls      int
	publishes  int
	sess       netpolicy.Session
	spec       execbox.Spec
	result     execbox.Result
	err        error
	published  execbox.Published
	publishErr error
}

func (f *fakeExecbox) RunOnce(_ context.Context, s netpolicy.Session, spec execbox.Spec) (execbox.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.sess, f.spec = s, spec
	return f.result, f.err
}

// Publish records that the install path asked the supervisor to publish, which
// is the only way an artifact reaches the persistent bin directory.
func (f *fakeExecbox) Publish(_ context.Context, s netpolicy.Session, name string) (execbox.Published, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishes++
	f.sess = s
	if f.publishErr != nil {
		return execbox.Published{}, f.publishErr
	}
	if f.published.Name == "" {
		f.published = execbox.Published{Name: name, Path: "/state/m1nervac0nsole/toolbox/bin/" + name, SHA256: "digest", Size: 7}
	}
	return f.published, nil
}

func (f *fakeExecbox) Run(context.Context, netpolicy.Session, execbox.Spec) (io.ReadWriteCloser, error) {
	return nil, execbox.ErrUnavailable
}

func (f *fakeExecbox) Capabilities(context.Context) (execbox.Report, error) {
	return execbox.Report{Isolation: true}, nil
}

// useFakeExecbox installs a fake client for one test and restores the real
// (absent) one afterwards, so no other test inherits it.
func useFakeExecbox(t *testing.T, f *fakeExecbox) {
	t.Helper()
	execbox.Install(f)
	t.Cleanup(func() { execbox.Install(nil) })
}

// installTestServer is a DB-backed server holding one stored template with an
// install script, removed again so a failed assertion cannot leak it.
func installTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, token := manifestStoreServer(t)
	if err := s.m.pg.UpsertToolManifest(context.Background(), "srvtest-custom", storeTestCustomTOML); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadManifests(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, token
}

// installReply is the JSON toolbox_install returns.
type installReply struct {
	Output     string `json:"output"`
	IsError    bool   `json:"is_error"`
	Available  bool   `json:"available"`
	Provenance struct {
		Template       string `json:"template"`
		ScriptSHA256   string `json:"script_sha256"`
		SourceRevision string `json:"source_revision"`
		BinaryVersion  string `json:"binary_version"`
		InstalledAt    string `json:"installed_at"`
		Verified       bool   `json:"verified"`
		Verification   string `json:"verification"`
		Published      *struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		} `json:"published"`
	} `json:"provenance"`
}

// An install runs in an install-purpose session through the boundary, and its
// provenance is recorded with the template.
func TestToolboxInstallRunsInTheInstallSession(t *testing.T) {
	s, _ := installTestServer(t)
	f := &fakeExecbox{result: execbox.Result{Output: []byte("installing-store-test\n[execbox-version] echo 9.9\n")}}
	useFakeExecbox(t, f)

	in, _ := json.Marshal(map[string]string{"id": "srvtest-custom", "source_revision": "deadbeef"})
	text, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_install"), string(in))
	if isErr {
		t.Fatalf("install errored: %s", text)
	}
	var reply installReply
	if err := json.Unmarshal([]byte(text), &reply); err != nil {
		t.Fatalf("install reply is not JSON: %v: %s", err, text)
	}

	if f.calls != 1 {
		t.Fatalf("install ran %d times, want once", f.calls)
	}
	// The session is issued by netpolicy, not minted at the call site: a 32-hex
	// id, an install purpose, and no task, so no engagement grant is inherited.
	if f.sess.Purpose != netpolicy.PurposeInstall || len(f.sess.ID) != 32 {
		t.Errorf("session = %+v, want an issued install-purpose session", f.sess)
	}
	if f.sess.TaskID != 0 {
		t.Errorf("install session carries task %d, want no task", f.sess.TaskID)
	}
	if f.publishes != 1 {
		t.Errorf("publish calls = %d, want the staged artifact published once", f.publishes)
	}
	if len(f.spec.Argv) != 5 || f.spec.Argv[0] != "bash" || f.spec.Argv[1] != "-c" {
		t.Fatalf("argv = %v, want bash -c <script> install <program>", f.spec.Argv)
	}
	if !strings.Contains(f.spec.Argv[2], "echo installing-store-test") {
		t.Errorf("the template's install script was not the program run: %q", f.spec.Argv[2])
	}
	if f.spec.Argv[3] != "install" || f.spec.Argv[4] != "echo" {
		t.Errorf("the version probe does not name the program: %v", f.spec.Argv)
	}
	if !f.spec.MergeStderr {
		t.Error("install output must keep stderr: an install's failure is usually printed there")
	}

	wantDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("echo installing-store-test")))
	if reply.Provenance.ScriptSHA256 != wantDigest {
		t.Errorf("script digest = %q, want %q", reply.Provenance.ScriptSHA256, wantDigest)
	}
	if reply.Provenance.SourceRevision != "deadbeef" || reply.Provenance.InstalledAt == "" {
		t.Errorf("provenance = %+v, want the source revision and a timestamp", reply.Provenance)
	}
	if reply.Provenance.BinaryVersion != "echo 9.9" {
		t.Errorf("binary version = %q, want the probe's line", reply.Provenance.BinaryVersion)
	}
	if strings.Contains(reply.Output, "execbox-version") {
		t.Errorf("the version probe leaked into the operator's log: %q", reply.Output)
	}
	if reply.IsError || !reply.Available || !reply.Provenance.Verified {
		t.Errorf("a successful install reported as %+v", reply)
	}
	pub := reply.Provenance.Published
	if pub == nil || pub.Name != "echo" || pub.Path != "/state/m1nervac0nsole/toolbox/bin/echo" || pub.SHA256 == "" || pub.Size == 0 {
		t.Errorf("published provenance = %+v, want the path, digest and size", pub)
	}
	if !strings.Contains(reply.Provenance.Verification, "/state survives sandbox recreation") {
		t.Errorf("verification = %q, want the persistence statement", reply.Provenance.Verification)
	}

	// Recorded, not just returned: the Toolbox can show it later.
	stored, ok, err := s.m.pg.GetSetting(toolInstallSettingPrefix + "srvtest-custom")
	if err != nil || !ok {
		t.Fatalf("install provenance not stored: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(stored, wantDigest) || !strings.Contains(stored, "deadbeef") {
		t.Errorf("stored provenance = %s", stored)
	}
}

// A failed install records the failure and publishes nothing: the template is
// not reported as verified and no tool becomes available.
func TestToolboxInstallFailureIsRecordedAndNotPublished(t *testing.T) {
	s, _ := installTestServer(t)
	f := &fakeExecbox{result: execbox.Result{ExitCode: 2, Output: []byte("no such package\n")}}
	useFakeExecbox(t, f)

	text, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_install"), `{"id":"srvtest-custom"}`)
	if isErr {
		t.Fatalf("a failed install must be reported in the reply, not as a tool error: %s", text)
	}
	var reply installReply
	if err := json.Unmarshal([]byte(text), &reply); err != nil {
		t.Fatalf("install reply is not JSON: %v: %s", err, text)
	}
	if !reply.IsError || reply.Provenance.Verified {
		t.Fatalf("a failed install reported as %+v", reply)
	}
	if !strings.Contains(reply.Provenance.Verification, "exited 2") {
		t.Errorf("verification = %q, want the exit status", reply.Provenance.Verification)
	}
	if f.publishes != 0 || reply.Provenance.Published != nil {
		t.Errorf("a failed install published %d artifact(s): %+v", f.publishes, reply.Provenance.Published)
	}
	stored, ok, err := s.m.pg.GetSetting(toolInstallSettingPrefix + "srvtest-custom")
	if err != nil || !ok || !strings.Contains(stored, `"verified":false`) {
		t.Fatalf("failure not recorded: ok=%v err=%v stored=%s", ok, err, stored)
	}
}

// A publish the supervisor refuses is a failed install: the boundary is the only
// path into the persistent bin directory, so nothing is reported as verified.
func TestToolboxInstallPublishRefusalIsReported(t *testing.T) {
	s, _ := installTestServer(t)
	f := &fakeExecbox{publishErr: fmt.Errorf("execbox: publish refused: not a regular file")}
	useFakeExecbox(t, f)

	text, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_install"), `{"id":"srvtest-custom"}`)
	if isErr {
		t.Fatalf("a refused publish must be reported in the reply, not as a tool error: %s", text)
	}
	var reply installReply
	if err := json.Unmarshal([]byte(text), &reply); err != nil {
		t.Fatalf("install reply is not JSON: %v: %s", err, text)
	}
	if !reply.IsError || reply.Provenance.Verified || reply.Provenance.Published != nil {
		t.Fatalf("a refused publish reported as %+v", reply)
	}
	if !strings.Contains(reply.Provenance.Verification, "publish was refused") {
		t.Errorf("verification = %q, want the publish refusal", reply.Provenance.Verification)
	}
}

// An install that stages nothing is not a failure of the boundary, but it is not
// verified either: the tool is usable only if it was already on PATH.
func TestToolboxInstallWithNothingStagedIsNotVerified(t *testing.T) {
	s, _ := installTestServer(t)
	f := &fakeExecbox{publishErr: execbox.ErrNotStaged}
	useFakeExecbox(t, f)

	text, isErr := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_install"), `{"id":"srvtest-custom"}`)
	if isErr {
		t.Fatalf("install errored: %s", text)
	}
	var reply installReply
	if err := json.Unmarshal([]byte(text), &reply); err != nil {
		t.Fatalf("install reply is not JSON: %v: %s", err, text)
	}
	if f.publishes != 1 {
		t.Errorf("publish calls = %d, want the publish attempted once", f.publishes)
	}
	if reply.Provenance.Published != nil {
		t.Errorf("nothing was staged but the reply claims a publication: %+v", reply.Provenance.Published)
	}
	// echo is on the backend's PATH, so the tool is usable even though this
	// install staged nothing.
	if reply.IsError || !reply.Available || !reply.Provenance.Verified {
		t.Errorf("an install of an already-available tool reported as %+v", reply)
	}
}

// Without the boundary the install is refused rather than run unisolated.
func TestToolboxInstallRefusesWithoutTheBoundary(t *testing.T) {
	s, _ := installTestServer(t)
	execbox.Install(nil)

	text, _ := callCuratorTool(t, toolCuratorTool(t, s, "toolbox_install"), `{"id":"srvtest-custom"}`)
	var reply installReply
	if err := json.Unmarshal([]byte(text), &reply); err != nil {
		t.Fatalf("install reply is not JSON: %v: %s", err, text)
	}
	if !reply.IsError || !strings.Contains(reply.Provenance.Verification, "isolated execution is unavailable") {
		t.Fatalf("install without a boundary reported as %+v", reply)
	}
}

// The curator has no way to approve its own work: its tool set is exactly the
// read tools, the two proposals and the install, and the decide endpoint needs an
// operator session.
func TestCuratorCannotSelfApprove(t *testing.T) {
	s, _ := installTestServer(t)
	want := []string{"toolbox_list", "toolbox_read", "toolbox_validate", "toolbox_propose_template", "toolbox_propose_tool", "toolbox_install"}
	got := make([]string, 0, len(s.toolCuratorTools()))
	for _, tool := range s.toolCuratorTools() {
		name := tool.Name()
		got = append(got, name)
		if strings.Contains(name, "approve") || strings.Contains(name, "decide") || strings.Contains(name, "intercept") {
			t.Errorf("%s looks like an approval tool: the curator must not resolve its own cards", name)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") || strings.Join(toolCuratorToolKeys, ",") != strings.Join(want, ",") {
		t.Errorf("curator tool set = %v (keys %v), want %v", got, toolCuratorToolKeys, want)
	}

	// The decision itself is an operator action on an authenticated route.
	if code, _ := memoryAPI(t, s, "", http.MethodPost, "/api/intercept/pending/1/decide", `{"decision":"allowed"}`); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated decide status %d, want 401", code)
	}
}

// A template that hides its HTTP nature behind a non-web category is refused, and
// so is a web template with no rate declaration.
func TestCuratorRefusesCategoryEvasion(t *testing.T) {
	s := newCustomToolServer()
	validate := toolCuratorTool(t, s, "toolbox_validate")
	base := `id = "evade"
name = "Evade"
description = "HTTP client labelled as recon"
category = "%s"
accepts = ["url"]
requires = ["curl"]

[params]
threads = { type = "number", label = "Threads", default = "4" }

[command]
program = "curl"
args = ["-A", "{{ useragent }}", "{{ target.value }}"]
timeout_seconds = 30

[emit]
parser = "lines"
fields = ["value"]
`
	withLimits := `
[limits]
param = "threads"
unit = "threads"
`
	cases := []struct {
		name    string
		toml    string
		refused bool
	}{
		{"recon claiming HTTP flags", fmt.Sprintf(base, "recon"), true},
		{"web without limits", strings.Replace(fmt.Sprintf(base, "web"), `"-A", "{{ useragent }}", `, "", 1), true},
		{"recon with limits", fmt.Sprintf(base, "recon") + withLimits, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := json.Marshal(map[string]string{"toml": tc.toml})
			text, isErr := callCuratorTool(t, validate, string(in))
			if isErr {
				t.Fatalf("validate errored: %s", text)
			}
			var reply struct {
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(text), &reply); err != nil {
				t.Fatalf("validate reply is not JSON: %v: %s", err, text)
			}
			if reply.OK == tc.refused {
				t.Fatalf("ok=%v for %s: %s", reply.OK, tc.name, reply.Error)
			}
			if tc.refused && !strings.Contains(reply.Error, "limits") {
				t.Errorf("refusal does not name the missing [limits]: %q", reply.Error)
			}
		})
	}

	// The same gate runs where the template is saved, so validate cannot be
	// skipped to store the evasion.
	propose := toolCuratorTool(t, s, "toolbox_propose_template")
	in, _ := json.Marshal(map[string]string{"toml": fmt.Sprintf(base, "recon"), "provenance": "verified: nothing"})
	text, isErr := callCuratorTool(t, propose, string(in))
	if !isErr || !strings.Contains(text, "limits") {
		t.Fatalf("propose of an evading template = %q (isErr=%v), want a refusal naming [limits]", text, isErr)
	}
}

// The provenance block is required on a proposal and is stored with the template,
// where the approval card and the template page read it.
func TestToolboxProposeTemplateStoresProvenance(t *testing.T) {
	s, _ := manifestStoreServer(t)
	propose := toolCuratorTool(t, s, "toolbox_propose_template")

	if text, isErr := callCuratorTool(t, propose, `{"toml":`+quoteJSON(t, storeTestCustomTOML)+`}`); !isErr ||
		!strings.Contains(text, "provenance is required") {
		t.Fatalf("a proposal with no provenance = %q (isErr=%v), want a refusal", text, isErr)
	}

	provenance := "verified: flags from echo -h\ninferred: default rate"
	in, _ := json.Marshal(map[string]string{"toml": storeTestCustomTOML, "provenance": provenance})
	text, isErr := callCuratorTool(t, propose, string(in))
	if isErr {
		t.Fatalf("propose errored: %s", text)
	}
	stored, _, ok := s.manifestSource("srvtest-custom")
	if !ok {
		t.Fatal("the template was not stored")
	}
	for _, line := range strings.Split(provenance, "\n") {
		if !strings.Contains(stored, provenancePrefix+line) {
			t.Errorf("stored template lost %q:\n%s", line, stored)
		}
	}
	// The block is a comment, so the manifest still parses and runs.
	if _, err := manifest.Check(stored); err != nil {
		t.Fatalf("a stored template with provenance no longer parses: %v", err)
	}

	// Re-proposing replaces the block instead of stacking it.
	in, _ = json.Marshal(map[string]string{"toml": storeTestCustomTOML, "provenance": "verified: second pass"})
	if _, isErr := callCuratorTool(t, propose, string(in)); isErr {
		t.Fatal("re-propose failed")
	}
	stored, _, _ = s.manifestSource("srvtest-custom")
	if !strings.Contains(stored, "second pass") || strings.Contains(stored, "flags from echo -h") {
		t.Fatalf("provenance blocks stacked:\n%s", stored)
	}
}

// A curator-triggered install must carry the tool call that caused it, so the
// artifact can be traced back to that call. An operator-started install has no
// call, and must not invent one.
func TestInstallArtifactsAttributeTheCall(t *testing.T) {
	dir := t.TempDir()
	operator := installArtifacts(dir, context.Background())
	if operator.Origin != execbox.OriginOperator || operator.ToolUseID != "" || operator.Dir != dir {
		t.Fatalf("operator install capture = %+v, want an operator action with no tool id", operator)
	}

	ctx := actool.WithExecIdentity(context.Background(), actool.ExecIdentity{RunDir: dir, ToolUseID: "call-install"})
	curator := installArtifacts(dir, ctx)
	if curator.Origin != execbox.OriginTool || curator.ToolUseID != "call-install" || curator.Dir != dir {
		t.Fatalf("curator install capture = %+v, want the calling tool id", curator)
	}
}

// quoteJSON renders s as a JSON string literal, for embedding TOML in a test
// argument.
func quoteJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

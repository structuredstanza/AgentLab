package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/execbox"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/netpolicy"
	actool "github.com/structuredstanza/norma/tool"
)

func TestRenderTemplateCommand(t *testing.T) {
	// command: string params shell-quoted; array → JSON (also quoted).
	got := renderTemplate("nmap -p {ports} {target}", map[string]any{
		"target": "10.0.0.1; rm -rf /", // injection attempt → must be single-quoted
		"ports":  []any{80.0, 443.0},
	}, shellQuote)
	if !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("target not shell-quoted: %q", got)
	}
	if strings.Contains(got, "rm -rf /'") && !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("possible injection leak: %q", got)
	}
	if strings.Contains(got, "{target}") || strings.Contains(got, "{ports}") {
		t.Fatalf("placeholders not replaced: %q", got)
	}
}

func TestRenderTemplateHTTP(t *testing.T) {
	// http: identity (no shell quoting) — raw substitution into url/body.
	got := renderTemplate("https://x/submit?flag={flag}", map[string]any{"flag": "CTF{abc}"}, identity)
	if got != "https://x/submit?flag=CTF{abc}" {
		t.Fatalf("http render: %q", got)
	}
}

func TestScalarStr(t *testing.T) {
	cases := []struct {
		v    any
		want string
		ok   bool
	}{
		{"hi", "hi", true},
		{true, "true", true},
		{float64(80), "80", true},   // integer-valued float → no decimal
		{float64(1.5), "1.5", true}, // real float
		{[]any{1, 2}, "", false},    // array → not scalar
		{map[string]any{}, "", false},
	}
	for _, c := range cases {
		got, ok := scalarStr(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("scalarStr(%v) = (%q,%v), want (%q,%v)", c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestEnsureSchema(t *testing.T) {
	// empty → thin {args:string}
	m := ensureSchema(nil)
	props, _ := m["properties"].(map[string]any)
	if _, ok := props["args"]; !ok {
		t.Fatalf("empty schema should default to args: %v", m)
	}
	// non-empty → passthrough
	raw := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`)
	m2 := ensureSchema(raw)
	p2, _ := m2["properties"].(map[string]any)
	if _, ok := p2["target"]; !ok {
		t.Fatalf("non-empty schema should pass through: %v", m2)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Fatalf("shellQuote(a'b) = %q", got)
	}
}

// testPython returns an interpreter that actually runs: LookPath alone is not
// enough on Windows, where the Store "python3" App Execution Alias is found but
// dies with exit status 9009.
func testPython(t *testing.T) string {
	t.Helper()
	for _, c := range []string{"python3", "python"} {
		if p, err := exec.LookPath(c); err == nil && exec.Command(p, "-c", "").Run() == nil {
			return p
		}
	}
	t.Skip("python unavailable")
	return ""
}

// TestScriptBootstrapDeliversBodyAndParamsOnStdin runs the argv a script tool
// builds with a real shell and interpreter: the body lands in the script file
// byte for byte, the params still arrive as stdin JSON and as TOOL_<NAME>, a
// body past the kernel's argument limit still runs, and a script that reads
// stdin to EOF finishes instead of hanging.
func TestScriptBootstrapDeliversBodyAndParamsOnStdin(t *testing.T) {
	interp := testPython(t)
	run := func(t *testing.T, code string, params map[string]any) (string, string) {
		t.Helper()
		file := scriptPath(t.TempDir(), "test", code)
		argv := scriptArgv(interp, "test", file, len(code))
		c := exec.Command(argv[0], argv[1:]...)
		env, err := scriptEnv(nil, params)
		if err != nil {
			t.Fatal(err)
		}
		// The supervisor adds PATH; the bootstrap needs it for dirname/head.
		c.Env = append(env, "PATH="+os.Getenv("PATH"))
		pj, _ := json.Marshal(params)
		c.Stdin = bytes.NewReader(append([]byte(code), pj...))
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("script bootstrap: %v\n%s", err, out)
		}
		return string(out), file
	}

	t.Run("params on stdin and in the environment", func(t *testing.T) {
		code := `import json,sys,os
a = json.load(sys.stdin)
print("stdin_target=" + a["target"])
print("env_target=" + os.environ.get("TOOL_TARGET",""))
print("port=" + str(a["port"]))
print("body=" + open(__file__).read())
`
		params := map[string]any{"target": "example.com", "port": float64(8080)}
		out, _ := run(t, code, params)
		for _, want := range []string{"stdin_target=example.com", "env_target=example.com", "port=8080", "body=" + code} {
			if !strings.Contains(out, want) {
				t.Fatalf("output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("body past the argument limit", func(t *testing.T) {
		code := strings.Repeat("# pad\n", 30000) + "print('big-ok')\n"
		if len(code) <= maxToolEnvBytes {
			t.Fatalf("the fixture body is %d bytes, which is not past the argument limit", len(code))
		}
		out, file := run(t, code, map[string]any{})
		if !strings.Contains(out, "big-ok") {
			t.Fatalf("the oversized script did not run:\n%s", out)
		}
		written, err := os.ReadFile(file)
		if err != nil || string(written) != code {
			t.Fatalf("the script file does not hold the body (%d bytes, err=%v)", len(written), err)
		}
	})

	t.Run("script that reads stdin to EOF", func(t *testing.T) {
		out, _ := run(t, `import sys; print("rest=" + sys.stdin.read().strip())`, map[string]any{"target": "example.com"})
		if !strings.Contains(out, `rest={"target":"example.com"}`) {
			t.Fatalf("the params did not follow the body on stdin:\n%s", out)
		}
	})
}

// scriptClient wraps the shared fake so a test can see the stdin a script tool
// delivers: the body and the params must arrive there, and the EOF must follow,
// or a script that reads stdin hangs.
type scriptClient struct {
	*fakeExecClient
	mu    sync.Mutex
	input bytes.Buffer
	eof   bool
}

func (c *scriptClient) Run(ctx context.Context, s netpolicy.Session, spec execbox.Spec) (io.ReadWriteCloser, error) {
	rwc, err := c.fakeExecClient.Run(ctx, s, spec)
	if err != nil {
		return nil, err
	}
	proc, ok := execbox.ProcessOf(rwc)
	if !ok {
		return rwc, nil
	}
	return &scriptProc{Process: proc, c: c}, nil
}

type scriptProc struct {
	execbox.Process
	c *scriptClient
}

func (p *scriptProc) Write(b []byte) (int, error) {
	p.c.mu.Lock()
	p.c.input.Write(b)
	p.c.mu.Unlock()
	return p.Process.Write(b)
}

func (p *scriptProc) CloseStdin() error {
	p.c.mu.Lock()
	p.c.eof = true
	p.c.mu.Unlock()
	return p.Process.CloseStdin()
}

// ArtifactPointer forwards the capture pointer of the wrapped process, so the
// script tool's pointer plumbing is exercised through the wrapper.
func (p *scriptProc) ArtifactPointer() string { return execbox.ArtifactPointer(p.Process) }

func (c *scriptClient) received() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.input.String(), c.eof
}

// TestScriptToolRunsInTheSessionWithoutTheBackendEnvironment proves a custom
// script tool goes through the run's isolated session with a minimal
// environment: a backend-only variable (the DSN among them) never reaches it,
// while the run's proxy env, the TOOL_* params and the stdin JSON still do. The
// body and the params travel on stdin, never in argv, and the EOF follows so a
// script that reads stdin finishes.
func TestScriptToolRunsInTheSessionWithoutTheBackendEnvironment(t *testing.T) {
	f := &scriptClient{fakeExecClient: &fakeExecClient{}}
	execbox.Install(f)
	t.Cleanup(func() { execbox.Install(nil) })
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	// The fake client never starts the interpreter, so any absolute path works.
	if err := m.pg.SetSetting(settingPythonInterp, "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M1NERVAC0NSOLE_TEST_BACKEND_ONLY", "dsn-or-controller-secret")
	s := &Server{m: m}
	code := "import sys; print(sys.stdin.read())"
	execRaw, _ := json.Marshal(map[string]any{"code": code})
	ctx := execbox.WithSession(context.Background(), testSession())
	tc := &actool.ToolContext{WorkingDir: t.TempDir(), ToolUseID: "call-script", Env: []string{"HTTPS_PROXY=http://127.0.0.1:8788"}}
	f.artifactRef = "[exec artifact: exec-artifacts/abc-1234 (stdin sha256: aa, stdout sha256: bb, stderr: merged into stdout)]"
	res, err := s.runScriptTool(ctx, "fixture", execRaw, map[string]any{"target": "example.com"}, tc)
	if err != nil {
		t.Fatalf("runScriptTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("script tool refused: %s", res.Flatten())
	}
	spec, sess, ok := f.last()
	if !ok {
		t.Fatal("the script tool never reached the execution boundary")
	}
	if sess.ID != testSession().ID {
		t.Fatalf("the script ran under session %q, want the run's", sess.ID)
	}
	if spec.Dir != tc.WorkingDir {
		t.Fatalf("script dir = %q, want the run's working directory %q", spec.Dir, tc.WorkingDir)
	}
	if !spec.MergeStderr {
		t.Fatal("the script's stderr must fold into the stream the tool reports")
	}
	hasEnv := func(want string) bool {
		for _, kv := range spec.Env {
			if kv == want {
				return true
			}
		}
		return false
	}
	for _, kv := range spec.Env {
		if strings.HasPrefix(kv, "M1NERVAC0NSOLE_TEST_BACKEND_ONLY=") {
			t.Fatalf("the script process inherits the backend environment: %q", kv)
		}
	}
	if !hasEnv("HTTPS_PROXY=http://127.0.0.1:8788") {
		t.Fatalf("the run's proxy env did not reach the script: %v", spec.Env)
	}
	if !hasEnv("TOOL_TARGET=example.com") {
		t.Fatalf("the scalar param was not mirrored to TOOL_TARGET: %v", spec.Env)
	}
	// The body and the params are no longer visible in the process list.
	argv := strings.Join(spec.Argv, "\x00")
	if strings.Contains(argv, code) || strings.Contains(argv, `{"target":"example.com"}`) {
		t.Fatalf("the body or the params travel in argv: %v", spec.Argv)
	}
	if !strings.Contains(argv, tc.WorkingDir+"/.tool-scripts/fixture-") {
		t.Fatalf("argv does not name the script file the bootstrap writes: %v", spec.Argv)
	}
	input, eof := f.received()
	if want := code + `{"target":"example.com"}`; input != want {
		t.Fatalf("stdin carried %q, want the body then the params %q", input, want)
	}
	if !eof {
		t.Fatal("the script tool never signalled stdin EOF, so a script that reads stdin would hang")
	}
	// The turn's result names the file, so the export's record points at the
	// exact bytes that ran.
	if body := res.Flatten(); !strings.Contains(body, "[script: "+tc.WorkingDir+"/.tool-scripts/fixture-") {
		t.Fatalf("the tool result does not name the executed script: %q", body)
	}
	// The spawn carried the call's identity, and the result names the capture
	// that holds the stdin and the merged output.
	if !f.hasArtifact {
		t.Fatal("the script run carried no capture identity")
	}
	if f.artifact.ToolUseID != "call-script" || f.artifact.Dir != tc.WorkingDir || f.artifact.Origin != execbox.OriginTool {
		t.Fatalf("capture identity = %+v, want the call's id and the run workspace", f.artifact)
	}
	if body := res.Flatten(); !strings.Contains(body, f.artifactRef) {
		t.Fatalf("the tool result does not name the capture: %q", body)
	}
}

// TestScriptToolRejectsOversizedInput proves an oversized body or parameter is
// refused with a message the model can act on, instead of reaching the boundary
// and failing to spawn.
func TestScriptToolRejectsOversizedInput(t *testing.T) {
	f := installFakeClient(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.pg.SetSetting(settingPythonInterp, "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	many := map[string]any{}
	for i := range 9 {
		// Each value fits the per-string limit; the set together does not fit
		// the total, which is the other way a spawn would fail with E2BIG.
		many[fmt.Sprintf("p%d", i)] = strings.Repeat("x", maxToolEnvBytes-8000)
	}
	s := &Server{m: m}
	ctx := execbox.WithSession(context.Background(), testSession())
	tc := &actool.ToolContext{WorkingDir: t.TempDir()}
	for _, c := range []struct {
		name   string
		code   string
		params map[string]any
		want   string
	}{
		{"body", strings.Repeat("#", maxScriptBytes+1), nil, "script code is"},
		{"parameter", "print(1)", map[string]any{"blob": strings.Repeat("x", maxToolEnvBytes)}, "too large for the script environment"},
		{"parameters", "print(1)", many, "the script parameters are too large"},
	} {
		t.Run(c.name, func(t *testing.T) {
			execRaw, _ := json.Marshal(map[string]any{"code": c.code})
			res, err := s.runScriptTool(ctx, "fixture", execRaw, c.params, tc)
			if err != nil {
				t.Fatalf("runScriptTool: %v", err)
			}
			if !res.IsError || !strings.Contains(res.Flatten(), c.want) {
				t.Fatalf("oversized %s = %q (isError=%v), want %q", c.name, res.Flatten(), res.IsError, c.want)
			}
		})
	}
	if runOnce, run, runFiles := f.counts(); runOnce+run+runFiles != 0 {
		t.Fatalf("a refused script still reached the supervisor: runOnce=%d run=%d runFiles=%d", runOnce, run, runFiles)
	}
}

// TestScriptToolRefusesWithoutASession proves there is no direct-execution
// fallback: with no backend-issued session the script tool refuses instead of
// running as root in the backend's own namespace.
func TestScriptToolRefusesWithoutASession(t *testing.T) {
	f := installFakeClient(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.pg.SetSetting(settingPythonInterp, "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	execRaw, _ := json.Marshal(map[string]any{"code": "print('ran')"})
	res, err := (&Server{m: m}).runScriptTool(context.Background(), "fixture", execRaw,
		map[string]any{}, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil {
		t.Fatalf("runScriptTool: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), execboxRefusal) {
		t.Fatalf("script without a session = %q (isError=%v), want the capability error", res.Flatten(), res.IsError)
	}
	if runOnce, run, runFiles := f.counts(); runOnce+run+runFiles != 0 {
		t.Fatalf("a refused script still reached the supervisor: runOnce=%d run=%d runFiles=%d", runOnce, run, runFiles)
	}
}

// TestRunHTTPTool functionally exercises the http executor against a local server:
// method/url/header/body templates are rendered from params, the request is sent,
// and the response status+body are returned. No recording proxy → s.m untouched.
func TestRunHTTPTool(t *testing.T) {
	var gotMethod, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{
		"method":  "POST",
		"url":     srv.URL + "/submit?flag={flag}",
		"headers": map[string]string{"Authorization": "Bearer {token}"},
		"body":    `{"flag":"{flag}"}`,
	})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw,
		map[string]any{"flag": "CTF{x}", "token": "sekret"}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	var out struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)

	if gotMethod != "POST" {
		t.Fatalf("method: %q", gotMethod)
	}
	if gotAuth != "Bearer sekret" {
		t.Fatalf("header template not rendered: %q", gotAuth)
	}
	if gotBody != `{"flag":"CTF{x}"}` {
		t.Fatalf("body template not rendered: %q", gotBody)
	}
	if out.Status != 201 || !strings.Contains(out.Body, `"ok":true`) {
		t.Fatalf("response not captured: %+v", out)
	}
}

// The http tool's proxy transport must use Manager.ProxyAddr as-is (it is already a
// complete URL, so no second scheme) and must never fall back to a direct request.
func TestHTTPToolProxyRouting(t *testing.T) {
	var mu sync.Mutex
	var hits int
	var gotURI string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		gotURI = r.RequestURI
		mu.Unlock()
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()

	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()

	for _, tc := range []struct {
		name string
		spec map[string]any
		m    *Manager
	}{
		{"explicit proxy", map[string]any{"proxy": proxy.URL}, &Manager{}},
		{"recording proxy", map[string]any{"use_recording_proxy": true}, &Manager{globalProxy: proxy.URL}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			hits, gotURI = 0, ""
			mu.Unlock()
			tc.spec["method"] = "GET"
			tc.spec["url"] = target.URL + "/x"
			execRaw, _ := json.Marshal(tc.spec)
			// The recording proxy is the gateway, so the run carries the session
			// its proxy URL is built from.
			ctx := execbox.WithSession(context.Background(), credentialSession())
			res, err := (&Server{m: tc.m}).runHTTPTool(ctx, execRaw, map[string]any{}, nil)
			if err != nil {
				t.Fatalf("runHTTPTool: %v", err)
			}
			if res.IsError {
				t.Fatalf("http tool failed: %s", res.Flatten())
			}
			mu.Lock()
			gotHits, uri := hits, gotURI
			mu.Unlock()
			if gotHits != 1 {
				t.Fatalf("proxy hits = %d, want 1", gotHits)
			}
			// A double-schemed proxy URL ("http://http://host:port") parses to host
			// "http:" and never reaches the proxy with this absolute request URI.
			if uri != target.URL+"/x" {
				t.Fatalf("proxy received %q, want %q", uri, target.URL+"/x")
			}
			if n := targetHits.Load(); n != 0 {
				t.Fatalf("target reached directly %d time(s) despite a configured proxy", n)
			}
		})
	}
}

// use_recording_proxy with no recording proxy running must fail the tool, not
// quietly send the request directly.
func TestHTTPToolRecordingProxyMissingFailsClosed(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": target.URL, "use_recording_proxy": true})
	res, err := (&Server{m: &Manager{}}).runHTTPTool(context.Background(), execRaw, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("missing recording proxy did not fail the tool: %q", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "use_recording_proxy") {
		t.Fatalf("error is not actionable: %q", res.Flatten())
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("request was sent directly %d time(s)", n)
	}
}

func TestDetectPython(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	if p := detectPython(); p == "" {
		t.Fatal("detectPython returned empty despite python3 on PATH")
	}
}

// The http tool must truncate an oversized response through norma's Capture, the
// same valve every other tool uses — a session with no OutputDir falls back to a
// head+tail cut, so a body far past the default cap comes back shortened.
func TestHTTPToolTruncatesLargeBody(t *testing.T) {
	big := strings.Repeat("x", 40000) // past Capture's 30000 default
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	out := res.Flatten()
	if len(out) >= 40000 {
		t.Fatalf("oversized http body was not truncated: len=%d", len(out))
	}
}

// ---------- editor test action: a session of its own ----------

// postTestTool drives the editor's test endpoint and returns the status and body.
func postTestTool(t *testing.T, s *Server, body map[string]any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.pgTestCustomTool(rec, httptest.NewRequest(http.MethodPost, "/api/tools/custom/test", bytes.NewReader(raw)))
	return rec.Code, rec.Body.String()
}

// testToolResult decodes the endpoint's response shape.
func testToolResult(t *testing.T, body string) (output string, isError bool) {
	t.Helper()
	var out struct {
		Output  string `json:"output"`
		IsError bool   `json:"is_error"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("response %q: %v", body, err)
	}
	return out.Output, out.IsError
}

// TestTestCustomToolRunsUnderASession proves the editor's test action is not an
// unconfined one: a script and a command reach the execution boundary under a
// session minted for the test, in the session's private /tmp, carrying the run's
// proxy env with that session's credential, and the credential is revoked when
// the request ends.
func TestTestCustomToolRunsUnderASession(t *testing.T) {
	f := installFakeClient(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.pg.SetSetting(settingPythonInterp, "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	m.globalProxy = "http://127.0.0.1:8788"
	s := &Server{m: m}
	for _, kind := range []string{"script", "command"} {
		t.Run(kind, func(t *testing.T) {
			code, body := postTestTool(t, s, map[string]any{
				"kind":   kind,
				"exec":   map[string]any{"code": "print(1)", "command": "id"},
				"params": map[string]any{"target": "example.com"},
			})
			if code != 200 {
				t.Fatalf("status %d: %s", code, body)
			}
			if out, isErr := testToolResult(t, body); isErr {
				t.Fatalf("the test run failed: %s", out)
			}
			spec, sess, ok := f.last()
			if !ok {
				t.Fatal("the test run never reached the execution boundary")
			}
			if sess.ID == "" || sess.Credential == "" || sess.Purpose != netpolicy.PurposeResearch || sess.TaskID != 0 {
				t.Fatalf("the test ran under %+v, want a research session with no task", sess)
			}
			if spec.Dir != "/tmp" {
				t.Fatalf("the test ran in %q, want the session's private /tmp", spec.Dir)
			}
			proxy := ""
			for _, kv := range spec.Env {
				if v, ok := strings.CutPrefix(kv, "HTTPS_PROXY="); ok {
					proxy = v
				}
			}
			if !strings.Contains(proxy, sess.Credential) {
				t.Fatalf("the test's proxy env does not carry the session credential: %q", proxy)
			}
			if !drained(m, 5*time.Second) {
				t.Fatal("the credential outlived the request")
			}
		})
	}
}

// TestTestCustomToolBindsToATask proves the editor's test run tests under the
// task it names, and that a task the store cannot answer for refuses the run
// instead of falling back to an unbound session.
func TestTestCustomToolBindsToATask(t *testing.T) {
	f := installFakeClient(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("custom tool test", "prove the editor test run binds to a task", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })
	s := &Server{m: m}
	body := func(taskID int64) map[string]any {
		return map[string]any{"kind": "command", "exec": map[string]any{"command": "id"}, "task_id": taskID}
	}

	if code, resp := postTestTool(t, s, body(taskID)); code != 200 {
		t.Fatalf("task-bound test run: status %d: %s", code, resp)
	}
	_, sess, ok := f.last()
	if !ok || sess.Purpose != netpolicy.PurposeTesting || sess.TaskID != taskID {
		t.Fatalf("the task-bound test ran under %+v (reached=%v), want a testing session for task %d", sess, ok, taskID)
	}
	if !drained(m, 5*time.Second) {
		t.Fatal("the credential outlived the request")
	}

	before, _, _ := f.counts()
	code, resp := postTestTool(t, s, body(1<<60))
	if code != 409 || !strings.Contains(resp, "session") {
		t.Fatalf("an unknown task gave status %d: %s", code, resp)
	}
	if after, _, _ := f.counts(); after != before {
		t.Fatal("a refused test run still reached the supervisor")
	}
}

// holdClient keeps a spawn open until the run's context ends, so a test can end
// the request while the tool is still running.
type holdClient struct {
	*fakeExecClient
	started chan struct{}
}

func (c *holdClient) Run(ctx context.Context, s netpolicy.Session, spec execbox.Spec) (io.ReadWriteCloser, error) {
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestTestCustomToolRevokesOnDisconnectAndTimeout proves the test run's
// credential does not outlive the request: a client that goes away mid-run and a
// request that hits its deadline both leave nothing behind for the gateway's cap.
func TestTestCustomToolRevokesOnDisconnectAndTimeout(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.pg.SetSetting(settingPythonInterp, "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"disconnect", func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}},
		{"timeout", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 100*time.Millisecond)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &holdClient{fakeExecClient: &fakeExecClient{}, started: make(chan struct{})}
			execbox.Install(f)
			t.Cleanup(func() { execbox.Install(nil) })
			ctx, cancel := c.ctx()
			defer cancel()
			raw, _ := json.Marshal(map[string]any{"kind": "script", "exec": map[string]any{"code": "print(1)"}})
			req := httptest.NewRequest(http.MethodPost, "/api/tools/custom/test", bytes.NewReader(raw)).WithContext(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.pgTestCustomTool(httptest.NewRecorder(), req)
			}()
			select {
			case <-f.started:
			case <-time.After(5 * time.Second):
				t.Fatal("the test run never reached the execution boundary")
			}
			if c.name == "disconnect" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the test run outlived its context")
			}
			if !drained(m, 5*time.Second) {
				t.Fatal("the credential outlived the request")
			}
		})
	}
}

// TestTestCustomToolHTTPGoesThroughTheRecordingProxy proves the editor's http
// test has no direct path to an origin: the request is recorded through the
// session's proxy, and refused with a clear message when none is reachable.
func TestTestCustomToolHTTPGoesThroughTheRecordingProxy(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()
	var mu sync.Mutex
	var proxyHits int
	var proxyURI string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxyHits++
		proxyURI = r.RequestURI
		mu.Unlock()
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m}
	post := func() (int, string) {
		return postTestTool(t, s, map[string]any{
			"kind": "http",
			"exec": map[string]any{"method": "GET", "url": target.URL + "/x"},
		})
	}

	m.globalProxy = proxy.URL
	code, body := post()
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if out, isErr := testToolResult(t, body); isErr || !strings.Contains(out, "via-proxy") {
		t.Fatalf("the http test did not go through the recording proxy: %q (isError=%v)", out, isErr)
	}
	mu.Lock()
	hits, uri := proxyHits, proxyURI
	mu.Unlock()
	if hits != 1 || uri != target.URL+"/x" {
		t.Fatalf("proxy saw %d request(s), last %q; want 1 for %q", hits, uri, target.URL+"/x")
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("the target was reached directly %d time(s)", n)
	}
	if !drained(m, 5*time.Second) {
		t.Fatal("the credential outlived the request")
	}

	// No proxy at all: the request is refused, never sent directly.
	m.globalProxy = ""
	code, body = post()
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	out, isErr := testToolResult(t, body)
	if !isErr || !strings.Contains(out, "use_recording_proxy") {
		t.Fatalf("a test with no reachable proxy = %q (isError=%v), want the refusal", out, isErr)
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("the target was reached directly %d time(s)", n)
	}
}
